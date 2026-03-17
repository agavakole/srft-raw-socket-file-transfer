import hashlib
import os
import socket
import threading
import time
from src.srft_packet import TYPE_DATA, TYPE_ACK, TYPE_FIN, TYPE_REQ, pack_packet, unpack_packet
from src.ip_header import build_ipv4_header
from src.udp_header import build_udp_header

OUTPUT_FILE = "received_file.txt"
STATS_FILE = "transfer_stats.txt"


class SRFTServer:

    def __init__(self, cfg):
        self.cfg = cfg
        self.server_ip = cfg.network.server_ip
        self.server_port = cfg.network.server_port
        self.chunk_size = cfg.transfer.chunk_size
        self.rto = cfg.timers.rto_ms / 1000
        self.ack_interval = cfg.timers.ack_interval_ms / 1000

        # raw sockets
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.recv_socket.bind(("0.0.0.0", self.server_port))

        # transfer state
        self.received_seqs = set()
        self.receive_buffer = {}    # out-of-order buffer: seq -> payload
        self.expected_seq = 1       # next expected in-order seq
        self.packets_received = 0
        self.start_time = None
        self.transferred_filename = None
        self.client_ip = None
        self.client_port = None
        self.running = True
        self.lock = threading.Lock()

        # cumulative ACK state
        self.last_ack_sent = 0      # last cumulative ACK value sent
        self.ack_pending = False    # true if we need to send an ACK

    def send_udp_packet(self, dst_ip, src_port, dst_port, payload):
        """Build and send a raw IP+UDP packet."""
        udp_header = build_udp_header(src_port, dst_port, payload, self.server_ip, dst_ip)
        udp_packet = udp_header + payload
        ip_header = build_ipv4_header(self.server_ip, dst_ip, len(udp_packet))
        full_packet = ip_header + udp_packet
        self.send_socket.sendto(full_packet, (dst_ip, 0))

    def send_cumulative_ack(self):
        """
        Send ONE cumulative ACK for the highest in-order seq received.
        This avoids sending an ACK per packet as required by the spec.
        """
        if self.client_ip is None:
            return

        ack_num = self.expected_seq - 1  # highest in-order seq received

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
        """
        Thread: sends cumulative ACKs at intervals instead of per packet.
        This implements the spec requirement of avoiding ACK per packet.
        """
        while self.running:
            time.sleep(self.ack_interval)
            with self.lock:
                if self.ack_pending:
                    self.send_cumulative_ack()

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
            f.write(f"MD5 hash of received file: {md5}\n")

        print("\n--- Transfer Stats ---")
        print(f"File: {self.transferred_filename}")
        print(f"Size: {file_size} bytes")
        print(f"Packets received: {self.packets_received}")
        print(f"Duration: {hours:02d}:{mins:02d}:{secs:02d}")
        print(f"MD5: {md5}")

    def extract_src_ip(self, packet):
        return socket.inet_ntoa(packet[12:16])

    def process_packet(self, packet):
        ip_header_length = (packet[0] & 0x0F) * 4
        udp_header_size = 8

        dst_port = (packet[ip_header_length + 2] << 8) + packet[ip_header_length + 3]
        if dst_port != self.server_port:
            return

        src_port = (packet[ip_header_length] << 8) + packet[ip_header_length + 1]
        sender_ip = self.extract_src_ip(packet)

        try:
            srft_data = packet[ip_header_length + udp_header_size:]
            info, payload = unpack_packet(srft_data)
        except ValueError:
            return

        if info["type"] == TYPE_REQ:
            self.client_ip = sender_ip
            self.client_port = src_port
            self.transferred_filename = payload.decode()
            print(f"[SERVER] File request received: {self.transferred_filename}")
            open(OUTPUT_FILE, "wb").close()

        elif info["type"] == TYPE_DATA:
            if self.start_time is None:
                self.start_time = time.time()

            seq = info["seq"]

            with self.lock:
                self.packets_received += 1
                self.client_ip = sender_ip
                self.client_port = src_port

                # duplicate detection
                if seq in self.received_seqs:
                    print(f"[SERVER] Duplicate seq {seq} — dropping")
                    self.ack_pending = True
                    return

                self.received_seqs.add(seq)

                # buffer out-of-order packets
                if seq == self.expected_seq:
                    # in order — write immediately
                    with open(OUTPUT_FILE, "ab") as f:
                        f.write(payload)
                    print(f"[SERVER] Written seq {seq} to file")
                    self.expected_seq += 1

                    # check if buffered packets can now be written
                    while self.expected_seq in self.receive_buffer:
                        buffered_payload = self.receive_buffer.pop(self.expected_seq)
                        with open(OUTPUT_FILE, "ab") as f:
                            f.write(buffered_payload)
                        print(f"[SERVER] Written buffered seq {self.expected_seq} to file")
                        self.expected_seq += 1

                else:
                    # out of order — buffer it
                    print(f"[SERVER] Out-of-order seq {seq} buffered (expected {self.expected_seq})")
                    self.receive_buffer[seq] = payload

                self.ack_pending = True

        elif info["type"] == TYPE_FIN:
            print("[SERVER] FIN received — transfer complete")
            # send final ACK
            with self.lock:
                self.send_cumulative_ack()
            duration = time.time() - self.start_time if self.start_time else 0
            self.write_stats(duration)
            self.running = False

    def receive_loop(self):
        """Thread: receives packets from client."""
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

        recv_thread = threading.Thread(target=self.receive_loop, daemon=True)
        ack_thread = threading.Thread(target=self.ack_sender_loop, daemon=True)

        recv_thread.start()
        ack_thread.start()

        recv_thread.join()


def run_server(cfg):
    server = SRFTServer(cfg)
    server.start()