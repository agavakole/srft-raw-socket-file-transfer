import hashlib
import socket
import threading
import time
from src.srft_packet import TYPE_DATA, TYPE_FIN, TYPE_REQ, TYPE_ACK, pack_packet, unpack_packet
from src.ip_header import build_ipv4_header
from src.udp_header import build_udp_header
from src.raw_socket import create_raw_socket


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

        # raw sockets
        self.send_socket = create_raw_socket()
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.recv_socket.bind(("0.0.0.0", self.client_port))

        # sliding window state
        self.base = 1           # oldest unACKed seq
        self.next_seq = 1       # next seq to send
        self.unacked = {}       # seq -> (packet_bytes, send_time)
        self.lock = threading.Lock()
        self.all_sent = False   # true when all chunks queued

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

    def compute_md5(self, filepath):
        """Compute MD5 hash of file."""
        h = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()

    def ack_receiver(self):
        """
        Thread: receives cumulative ACKs from server.
        A cumulative ACK of N means all packets up to N were received.
        Slides the window forward.
        """
        self.recv_socket.settimeout(self.rto)
        while True:
            try:
                raw_packet, _ = self.recv_socket.recvfrom(65535)

                ip_header_length = (raw_packet[0] & 0x0F) * 4
                dst_port = (raw_packet[ip_header_length + 2] << 8) + raw_packet[ip_header_length + 3]
                if dst_port != self.client_port:
                    continue

                srft_data = raw_packet[ip_header_length + 8:]
                info, _ = unpack_packet(srft_data)

                if info["type"] == TYPE_ACK:
                    ack_num = info["ack"]
                    print(f"[CLIENT] Cumulative ACK received: {ack_num}")

                    with self.lock:
                        # slide window — remove all ACKed packets
                        for seq in list(self.unacked.keys()):
                            if seq <= ack_num:
                                del self.unacked[seq]
                        self.base = ack_num + 1

                    # if all sent and all ACKed we are done
                    if self.all_sent and not self.unacked:
                        return

            except ValueError:
                continue
            except (socket.timeout, TimeoutError):
                # check for retransmissions on timeout
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

    def send_file(self):
        """Send file using sliding window with cumulative ACKs."""
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

                srft_bytes = pack_packet(
                    msg_type=TYPE_DATA,
                    seq=self.next_seq,
                    ack=0,
                    payload=chunk,
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

        # send FIN
        fin_bytes = pack_packet(
            msg_type=TYPE_FIN,
            seq=self.next_seq,
            ack=0,
            payload=b"",
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

    def start(self):
        """Start the client — send request then transfer file."""
        print(f"[CLIENT] Running on {self.client_ip}:{self.client_port}")
        print(f"[CLIENT] Talking to server {self.server_ip}:{self.server_port}")
        self.send_request()
        self.send_file()


def run_client(cfg, filename):
    client = SRFTClient(cfg, filename)
    client.start()