import hashlib
import socket
import threading
import time
from src.srft_packet import TYPE_DATA, TYPE_FIN, TYPE_REQ, TYPE_ACK, pack_packet, unpack_packet
from src.ip_header import build_ipv4_header
from src.udp_header import build_udp_header
from src.raw_socket import create_raw_socket
from src.security import (
    derive_session_key,
    encrypt_payload,
    build_aad,
    generate_nonce,
    compute_sha256
)
from src.handshake import (
    build_client_hello,
    parse_server_hello,
    HELLO_CLIENT,
    HELLO_SERVER
)

# Handshake timeout
HANDSHAKE_TIMEOUT = 5


class SRFTClient:

    def __init__(self, cfg, filename):
        self.cfg = cfg
        self.filename = filename
        self.client_ip = cfg.network.client_ip
        self.client_port = cfg.network.client_port
        self.server_ip = cfg.network.server_ip
        self.server_port = cfg.network.server_port
        self.chunk_size = cfg.transfer.chunk_size
        self.window_size = cfg.transfer.send_window_packets
        self.rto = cfg.timers.rto_ms / 1000

        # security config
        self.security_enabled = getattr(cfg.security, "enabled", False)
        psk_str = getattr(cfg.security, "psk", "")
        self.psk = psk_str.encode() if psk_str else b""

        # session state — set after handshake
        self.session_id = None
        self.enc_key = None

        # raw sockets
        self.send_socket = create_raw_socket()
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.recv_socket.bind(("0.0.0.0", self.client_port))

        # sliding window state
        self.base = 1
        self.next_seq = 1
        self.unacked = {}
        self.lock = threading.Lock()
        self.all_sent = False

        # stats
        self.packets_sent = 0
        self.packets_retransmitted = 0

    def send_udp_packet(self, dst_ip, src_port, dst_port, payload):
        """Build and send a raw IP+UDP packet."""
        udp_header = build_udp_header(src_port, dst_port, payload, self.client_ip, dst_ip)
        udp_packet = udp_header + payload
        ip_header = build_ipv4_header(self.client_ip, dst_ip, len(udp_packet))
        full_packet = ip_header + udp_packet
        self.send_socket.sendto(full_packet, (dst_ip, 0))

    def extract_srft_data(self, raw_packet):
        """Extract SRFT payload from raw packet."""
        ip_header_length = (raw_packet[0] & 0x0F) * 4
        dst_port = (raw_packet[ip_header_length + 2] << 8) + raw_packet[ip_header_length + 3]
        if dst_port != self.client_port:
            return None
        return raw_packet[ip_header_length + 8:]

    # -------------------------------------------------
    # Handshake
    # -------------------------------------------------

    def do_handshake(self) -> bool:
        """
        Perform security handshake with server.
        1. Send ClientHello with nonce + HMAC
        2. Receive ServerHello with nonce + session_id + HMAC
        3. Derive session encryption key from PSK + both nonces
        Returns True if handshake succeeded, False if failed.
        """
        print("[CLIENT] Starting security handshake...")

        # build and send ClientHello
        client_hello, client_nonce = build_client_hello(self.psk)
        self.send_udp_packet(
            self.server_ip,
            self.client_port,
            self.server_port,
            client_hello
        )
        print("[CLIENT] Sent ClientHello")

        # wait for ServerHello
        self.recv_socket.settimeout(HANDSHAKE_TIMEOUT)
        try:
            while True:
                raw_packet, _ = self.recv_socket.recvfrom(65535)
                srft_data = self.extract_srft_data(raw_packet)
                if srft_data is None:
                    continue

                # check if this is a handshake packet
                if len(srft_data) > 0 and srft_data[0] == HELLO_SERVER:
                    try:
                        server_nonce, session_id = parse_server_hello(
                            srft_data, self.psk, client_nonce
                        )
                        # derive session encryption key
                        self.enc_key = derive_session_key(
                            self.psk, client_nonce, server_nonce
                        )
                        self.session_id = session_id
                        print(f"[CLIENT] Handshake SUCCESS — session: {session_id.hex()}")
                        return True
                    except ValueError as e:
                        print(f"[CLIENT] Handshake FAILED: {e}")
                        return False

        except (socket.timeout, TimeoutError):
            print("[CLIENT] Handshake FAILED — timeout waiting for ServerHello")
            return False

    # -------------------------------------------------
    # File Request
    # -------------------------------------------------

    def send_request(self):
        """Send filename request to server before transfer."""
        req_bytes = pack_packet(
            msg_type=TYPE_REQ,
            seq=0,
            ack=0,
            payload=self.filename.encode(),
            window=0
        )
        self.send_udp_packet(
            self.server_ip,
            self.client_port,
            self.server_port,
            req_bytes
        )
        print(f"[CLIENT] Requested file: {self.filename}")
        time.sleep(0.1)

    # -------------------------------------------------
    # ACK Receiver Thread
    # -------------------------------------------------

    def ack_receiver(self):
        """
        Thread: receives cumulative ACKs from server.
        Slides the window forward on each ACK received.
        """
        self.recv_socket.settimeout(self.rto)
        while True:
            try:
                raw_packet, _ = self.recv_socket.recvfrom(65535)
                srft_data = self.extract_srft_data(raw_packet)
                if srft_data is None:
                    continue

                info, _ = unpack_packet(srft_data)

                if info["type"] == TYPE_ACK:
                    ack_num = info["ack"]
                    print(f"[CLIENT] Cumulative ACK received: {ack_num}")

                    with self.lock:
                        for seq in list(self.unacked.keys()):
                            if seq <= ack_num:
                                del self.unacked[seq]
                        self.base = ack_num + 1

                    if self.all_sent and not self.unacked:
                        return

            except ValueError:
                continue
            except (socket.timeout, TimeoutError):
                self._retransmit_unacked()
                if self.all_sent and not self.unacked:
                    return

    def _retransmit_unacked(self):
        """Retransmit all unACKed packets that have timed out."""
        now = time.time()
        with self.lock:
            for seq, (packet_bytes, send_time) in list(self.unacked.items()):
                if now - send_time >= self.rto:
                    print(f"[CLIENT] Timeout — retransmitting seq: {seq}")
                    self.send_udp_packet(
                        self.server_ip,
                        self.client_port,
                        self.server_port,
                        packet_bytes
                    )
                    self.unacked[seq] = (packet_bytes, now)
                    self.packets_retransmitted += 1

    # -------------------------------------------------
    # File Transfer
    # -------------------------------------------------

    def compute_md5(self, filepath):
        """Compute MD5 hash of file."""
        h = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()

    def send_file(self):
        """Send file using sliding window. Encrypts if security enabled."""
        md5 = self.compute_md5(self.filename)
        print(f"[CLIENT] MD5 of file to send: {md5}")

        # start ACK receiver thread
        ack_thread = threading.Thread(target=self.ack_receiver, daemon=True)
        ack_thread.start()

        with open(self.filename, "rb") as f:
            while True:
                # wait if window is full
                while True:
                    with self.lock:
                        window_available = self.next_seq - self.base < self.window_size
                    if window_available:
                        break
                    time.sleep(0.001)

                chunk = f.read(self.chunk_size)
                if not chunk:
                    break

                # encrypt chunk if security enabled
                if self.security_enabled and self.enc_key:
                    nonce = generate_nonce()
                    aad = build_aad(self.session_id, self.next_seq, 0, TYPE_DATA)
                    encrypted_chunk = encrypt_payload(self.enc_key, nonce, chunk, aad)
                    # prepend nonce so server can decrypt
                    payload = nonce + encrypted_chunk
                else:
                    payload = chunk

                srft_bytes = pack_packet(
                    msg_type=TYPE_DATA,
                    seq=self.next_seq,
                    ack=0,
                    payload=payload,
                    window=self.window_size
                )

                with self.lock:
                    self.unacked[self.next_seq] = (srft_bytes, time.time())

                print(f"[CLIENT] Sending packet seq: {self.next_seq}")
                self.send_udp_packet(
                    self.server_ip,
                    self.client_port,
                    self.server_port,
                    srft_bytes
                )
                self.packets_sent += 1
                self.next_seq += 1

        # all chunks sent — wait for all ACKs
        self.all_sent = True
        ack_thread.join(timeout=30)

        # send SHA-256 digest for end-to-end verification
        if self.security_enabled and self.enc_key:
            sha256_digest = compute_sha256(self.filename)
            nonce = generate_nonce()
            aad = build_aad(self.session_id, self.next_seq, 0, TYPE_FIN)
            encrypted_digest = encrypt_payload(self.enc_key, nonce, sha256_digest, aad)
            fin_payload = nonce + encrypted_digest
        else:
            fin_payload = b""

        # send FIN
        fin_bytes = pack_packet(
            msg_type=TYPE_FIN,
            seq=self.next_seq,
            ack=0,
            payload=fin_payload,
            window=0
        )
        self.send_udp_packet(
            self.server_ip,
            self.client_port,
            self.server_port,
            fin_bytes
        )
        print("[CLIENT] FIN packet sent — transfer complete")

        print("\n--- Client Transfer Stats ---")
        print(f"File: {self.filename}")
        print(f"Packets sent: {self.packets_sent}")
        print(f"Packets retransmitted: {self.packets_retransmitted}")
        print(f"MD5: {md5}")
        if self.security_enabled:
            print(f"Security: enabled (PSK + AES-GCM)")

    # -------------------------------------------------
    # Start
    # -------------------------------------------------

    def start(self):
        """Start client — handshake if security enabled, then transfer."""
        print(f"[CLIENT] Running on {self.client_ip}:{self.client_port}")
        print(f"[CLIENT] Talking to server {self.server_ip}:{self.server_port}")

        if self.security_enabled:
            if not self.do_handshake():
                print("[CLIENT] Aborting — handshake failed")
                return

        self.send_request()
        self.send_file()


def run_client(cfg, filename):
    client = SRFTClient(cfg, filename)
    client.start()