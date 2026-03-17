import hashlib
import os
import socket
import threading
import time
from src.srft_packet import TYPE_DATA, TYPE_ACK, TYPE_FIN, TYPE_REQ, pack_packet, unpack_packet
from src.ip_header import build_ipv4_header
from src.udp_header import build_udp_header
from src.attacker import Attacker
from src.security import (
    derive_session_key,
    decrypt_payload,
    build_aad,
    compute_sha256
)
from src.handshake import (
    parse_client_hello,
    build_server_hello,
    HELLO_CLIENT,
    HELLO_SERVER
)

OUTPUT_FILE = "received_file.txt"
STATS_FILE = "transfer_stats.txt"


class SRFTServer:

    def __init__(self, cfg, attack=None):
        self.cfg = cfg
        self.server_ip = cfg.network.server_ip
        self.server_port = cfg.network.server_port
        self.chunk_size = cfg.transfer.chunk_size
        self.rto = cfg.timers.rto_ms / 1000
        self.ack_interval = cfg.timers.ack_interval_ms / 1000

        # attack mode
        self.attacker = None
        if attack:
            self.attacker = Attacker(
                server_ip=self.server_ip,
                server_port=self.server_port,
                client_port=5000,
                attack_mode=attack
            )

        # security config
        self.security_enabled = getattr(cfg.security, "enabled", False)
        psk_str = getattr(cfg.security, "psk", "")
        self.psk = psk_str.encode() if psk_str else b""

        # session state
        self.session_id = None
        self.enc_key = None
        self.handshake_done = False
        self.handshake_status = "Not started"

        # raw sockets
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.recv_socket.bind(("0.0.0.0", self.server_port))

        # transfer state
        self.received_seqs = set()
        self.receive_buffer = {}
        self.expected_seq = 1
        self.packets_received = 0
        self.start_time = None
        self.transferred_filename = None
        self.client_ip = None
        self.client_port = None
        self.running = True
        self.fin_received = False  # separate flag for FIN
        self.lock = threading.Lock()

        # cumulative ACK state
        self.last_ack_sent = 0
        self.ack_pending = False

        # security stats
        self.aead_failures = 0
        self.replay_drops = 0
        self.sha256_match = None

    def send_udp_packet(self, dst_ip, src_port, dst_port, payload):
        """Build and send a raw IP+UDP packet."""
        udp_header = build_udp_header(src_port, dst_port, payload, self.server_ip, dst_ip)
        udp_packet = udp_header + payload
        ip_header = build_ipv4_header(self.server_ip, dst_ip, len(udp_packet))
        full_packet = ip_header + udp_packet
        self.send_socket.sendto(full_packet, (dst_ip, 0))

    # -------------------------------------------------
    # Handshake
    # -------------------------------------------------

    def handle_client_hello(self, packet, sender_ip, src_port):
        """
        Process ClientHello and send ServerHello back.
        Derives session key if handshake succeeds.
        """
        try:
            client_nonce = parse_client_hello(packet, self.psk)
            print("[SERVER] ClientHello verified")

            server_hello, server_nonce, session_id = build_server_hello(
                self.psk, client_nonce
            )

            self.send_udp_packet(
                sender_ip,
                self.server_port,
                src_port,
                server_hello
            )

            self.enc_key = derive_session_key(
                self.psk, client_nonce, server_nonce
            )
            self.session_id = session_id
            self.handshake_done = True
            self.handshake_status = "Success"
            print(f"[SERVER] Handshake SUCCESS — session: {session_id.hex()}")

        except ValueError as e:
            self.handshake_status = "Fail"
            print(f"[SERVER] Handshake FAILED: {e}")

    # -------------------------------------------------
    # Cumulative ACK
    # -------------------------------------------------

    def send_cumulative_ack(self):
        """Send ONE cumulative ACK for highest in-order seq received."""
        if self.client_ip is None:
            return

        ack_num = self.expected_seq - 1
        if ack_num <= 0:
            return

        ack_bytes = pack_packet(
            msg_type=TYPE_ACK,
            seq=0,
            ack=ack_num,
            payload=b"",
            window=5
        )
        self.send_udp_packet(
            self.client_ip,
            self.server_port,
            self.client_port,
            ack_bytes
        )
        self.last_ack_sent = ack_num
        self.ack_pending = False
        print(f"[SERVER] Sent cumulative ACK: {ack_num}")

    def ack_sender_loop(self):
        """Thread: sends cumulative ACKs at intervals."""
        while self.running:
            time.sleep(self.ack_interval)
            with self.lock:
                if self.ack_pending:
                    self.send_cumulative_ack()

    # -------------------------------------------------
    # Shutdown Thread
    # -------------------------------------------------

    def shutdown_after_wait(self, duration_so_far):
        """
        Thread: waits for attack packets to arrive after FIN,
        then writes stats and shuts down.
        receive_loop keeps running during the wait so replayed
        packets are still processed and counted.
        """
        if self.attacker:
            print("[SERVER] Waiting for attack packets...")
            time.sleep(2)

        self.write_stats(duration_so_far + (time.time() - self.start_time if self.start_time else 0))
        self.running = False

    # -------------------------------------------------
    # Packet Processing
    # -------------------------------------------------

    def process_packet(self, packet):
        ip_header_length = (packet[0] & 0x0F) * 4
        udp_header_size = 8

        dst_port = (packet[ip_header_length + 2] << 8) + packet[ip_header_length + 3]
        if dst_port != self.server_port:
            return

        src_port = (packet[ip_header_length] << 8) + packet[ip_header_length + 1]
        sender_ip = socket.inet_ntoa(packet[12:16])
        srft_data = packet[ip_header_length + udp_header_size:]

        if len(srft_data) == 0:
            return

        # check if this is a handshake packet
        if self.security_enabled and srft_data[0] == HELLO_CLIENT:
            self.handle_client_hello(srft_data, sender_ip, src_port)
            return

        # if security enabled but handshake not done yet, ignore
        if self.security_enabled and not self.handshake_done:
            return

        # --- ATTACK INTERCEPT — before parsing so tamper affects decrypt ---
        if self.attacker:
            try:
                pre_info, _ = unpack_packet(srft_data)
                pre_seq = pre_info["seq"]
            except ValueError:
                pre_seq = 0
            srft_data = self.attacker.intercept(srft_data, pre_seq)

        try:
            info, payload = unpack_packet(srft_data)
        except ValueError:
            with self.lock:
                self.aead_failures += 1
            print(f"[SERVER] Packet integrity check failed — dropping")
            return

        if info["type"] == TYPE_REQ:
            self.client_ip = sender_ip
            self.client_port = src_port
            self.transferred_filename = payload.decode()
            print(f"[SERVER] File request received: {self.transferred_filename}")
            open(OUTPUT_FILE, "wb").close()

        elif info["type"] == TYPE_DATA:
            # ignore DATA packets after FIN received
            if self.fin_received and info["seq"] in self.received_seqs:
                print(f"[SERVER] Duplicate/replay seq {info['seq']} — dropping")
                with self.lock:
                    self.replay_drops += 1
                return

            if self.start_time is None:
                self.start_time = time.time()

            seq = info["seq"]

            with self.lock:
                self.packets_received += 1
                self.client_ip = sender_ip
                self.client_port = src_port

                # replay protection — drop duplicates
                if seq in self.received_seqs:
                    print(f"[SERVER] Duplicate/replay seq {seq} — dropping")
                    self.replay_drops += 1
                    self.ack_pending = True
                    return

                # decrypt if security enabled
                if self.security_enabled and self.enc_key:
                    try:
                        nonce = payload[:12]
                        ciphertext = payload[12:]
                        aad = build_aad(self.session_id, seq, 0, TYPE_DATA)
                        payload = decrypt_payload(self.enc_key, nonce, ciphertext, aad)
                    except Exception:
                        print(f"[SERVER] AEAD auth failure on seq {seq} — dropping")
                        self.aead_failures += 1
                        return

                self.received_seqs.add(seq)

                # in-order — write immediately
                if seq == self.expected_seq:
                    with open(OUTPUT_FILE, "ab") as f:
                        f.write(payload)
                    print(f"[SERVER] Written seq {seq} to file")
                    self.expected_seq += 1

                    # flush buffer
                    while self.expected_seq in self.receive_buffer:
                        buffered = self.receive_buffer.pop(self.expected_seq)
                        with open(OUTPUT_FILE, "ab") as f:
                            f.write(buffered)
                        print(f"[SERVER] Written buffered seq {self.expected_seq}")
                        self.expected_seq += 1
                else:
                    print(f"[SERVER] Out-of-order seq {seq} buffered")
                    self.receive_buffer[seq] = payload

                self.ack_pending = True

        elif info["type"] == TYPE_FIN:
            if self.fin_received:
                return  # ignore duplicate FIN
            self.fin_received = True
            print("[SERVER] FIN received — transfer complete")

            # verify SHA-256 if security enabled
            if self.security_enabled and self.enc_key and len(payload) > 0:
                try:
                    nonce = payload[:12]
                    ciphertext = payload[12:]
                    aad = build_aad(self.session_id, info["seq"], 0, TYPE_FIN)
                    sha256_received = decrypt_payload(
                        self.enc_key, nonce, ciphertext, aad
                    )
                    sha256_local = compute_sha256(OUTPUT_FILE)
                    self.sha256_match = (sha256_received == sha256_local)
                    print(f"[SERVER] SHA-256 match: {self.sha256_match}")
                except Exception:
                    print("[SERVER] SHA-256 verification failed")
                    self.sha256_match = False

            with self.lock:
                self.send_cumulative_ack()

            # calculate duration so far
            duration = time.time() - self.start_time if self.start_time else 0

            # start shutdown in separate thread so receive_loop keeps running
            # this allows replayed/injected packets to still be processed
            shutdown_thread = threading.Thread(
                target=self.shutdown_after_wait,
                args=(duration,),
                daemon=True
            )
            shutdown_thread.start()

    # -------------------------------------------------
    # Stats
    # -------------------------------------------------

    def compute_md5(self, filepath):
        h = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()

    def write_stats(self, duration):
        file_size = 0
        try:
            file_size = os.path.getsize(OUTPUT_FILE)
        except:
            pass

        md5 = self.compute_md5(OUTPUT_FILE)
        hours = int(duration // 3600)
        mins = int((duration % 3600) // 60)
        secs = int(duration % 60)

        with open(STATS_FILE, "w") as f:
            f.write(f"Name of the transferred file: {self.transferred_filename}\n")
            f.write(f"Size of the transferred file: {file_size} bytes\n")
            f.write(f"The number of packets received from the client: {self.packets_received}\n")
            f.write(f"The time duration of the file transfer (hh:min:ss): {hours:02d}:{mins:02d}:{secs:02d}\n")
            if self.security_enabled:
                f.write(f"Security enabled (PSK + AEAD): Yes\n")
                f.write(f"Handshake status: {self.handshake_status}\n")
                f.write(f"AEAD authentication failures: {self.aead_failures}\n")
                f.write(f"Replay drops: {self.replay_drops}\n")
                f.write(f"SHA-256 match: {'Yes' if self.sha256_match else 'No'}\n")
            f.write(f"MD5 hash of received file: {md5}\n")

        print("\n--- Transfer Stats ---")
        print(f"File: {self.transferred_filename}")
        print(f"Size: {file_size} bytes")
        print(f"Packets received: {self.packets_received}")
        print(f"Duration: {hours:02d}:{mins:02d}:{secs:02d}")
        if self.security_enabled:
            print(f"Security: enabled (PSK + AES-GCM)")
            print(f"Handshake: {self.handshake_status}")
            print(f"AEAD failures: {self.aead_failures}")
            print(f"Replay drops: {self.replay_drops}")
            print(f"SHA-256 match: {'Yes' if self.sha256_match else 'No'}")
        print(f"MD5: {md5}")

    # -------------------------------------------------
    # Main Loop
    # -------------------------------------------------

    def receive_loop(self):
        """Thread: receives all packets."""
        open(OUTPUT_FILE, "wb").close()
        while self.running:
            try:
                packet, _ = self.recv_socket.recvfrom(65535)
                self.process_packet(packet)
            except Exception as e:
                if self.running:
                    print(f"[SERVER] Error: {e}")

    def start(self):
        print(f"[SERVER] Listening on {self.server_ip}:{self.server_port}")
        if self.security_enabled:
            print(f"[SERVER] Security enabled — waiting for handshake")

        recv_thread = threading.Thread(target=self.receive_loop, daemon=True)
        ack_thread = threading.Thread(target=self.ack_sender_loop, daemon=True)

        recv_thread.start()
        ack_thread.start()
        recv_thread.join()


def run_server(cfg, attack=None):
    server = SRFTServer(cfg, attack=attack)
    server.start()