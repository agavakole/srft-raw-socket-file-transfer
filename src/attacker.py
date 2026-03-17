import os
import socket
import threading
import time
from src.ip_header import build_ipv4_header
from src.udp_header import build_udp_header
from src.srft_packet import TYPE_DATA, unpack_packet, HEADER_SIZE


class Attacker:
    """
    Built-in attack module for security testing.
    Intercepts packets between client and server and performs attacks.

    Supports three attack modes:
    - tamper: flips bits inside the encrypted payload to trigger AEAD failure
    - replay: captures a packet and resends it later to test replay protection
    - inject: injects a forged packet with random bytes to test rejection
    """

    def __init__(self, server_ip, server_port, client_port, attack_mode):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_port = client_port
        self.attack_mode = attack_mode

        # store one captured packet for replay attack
        self.captured_packet = None
        self.captured_srft = None
        self.attack_done = False

        # raw socket for sending forged packets
        self.send_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_RAW
        )

        print(f"[ATTACKER] Attack mode: {attack_mode}")

    def send_raw_packet(self, dst_ip, src_port, dst_port, payload, src_ip="127.0.0.1"):
        """Send a raw forged packet."""
        udp_header = build_udp_header(src_port, dst_port, payload, src_ip, dst_ip)
        udp_packet = udp_header + payload
        ip_header = build_ipv4_header(src_ip, dst_ip, len(udp_packet))
        full_packet = ip_header + udp_packet
        self.send_socket.sendto(full_packet, (dst_ip, 0))

    def tamper_packet(self, srft_bytes: bytes) -> bytes:
        """
        Tamper the ciphertext bytes then recompute the SRFT checksum
        so the packet passes SRFT parsing but fails AES-GCM auth tag check.
        """
        from src.srft_packet import checksum16

        if len(srft_bytes) < HEADER_SIZE + 30:
            return srft_bytes

        data = bytearray(srft_bytes)

        # flip bytes inside ciphertext (past nonce which is 12 bytes)
        tamper_pos = HEADER_SIZE + 20
        data[tamper_pos] ^= 0xFF
        data[tamper_pos + 1] ^= 0xFF

        # recompute SRFT checksum so packet passes unpack_packet
        data[20] = 0  # zero checksum field
        data[21] = 0
        new_checksum = checksum16(bytes(data))
        # pack checksum big-endian into bytes 20-21
        data[20] = (new_checksum >> 8) & 0xFF
        data[21] = new_checksum & 0xFF

        print(f"[ATTACKER] Tampered ciphertext at pos {tamper_pos}, recomputed checksum")
        return bytes(data)

    def inject_forged_packet(self):
        """
        Inject a completely random forged DATA packet.
        Should be rejected by AES-GCM authentication.
        """
        forged_payload = os.urandom(64)  # random garbage bytes
        self.send_raw_packet(
            self.server_ip,
            self.client_port,
            self.server_port,
            forged_payload
        )
        print("[ATTACKER] Injected forged packet with random bytes")

    def replay_captured_packet(self):
        """
        Resend a previously captured valid DATA packet.
        Should be rejected by replay protection (duplicate seq detection).
        """
        if self.captured_srft is None:
            print("[ATTACKER] No packet captured yet for replay")
            return

        time.sleep(0.2)  # reduced from 1 second to 0.2 seconds
        self.send_raw_packet(
            self.server_ip,
            self.client_port,
            self.server_port,
            self.captured_srft
        )
        print("[ATTACKER] Replayed captured packet")
    def intercept(self, srft_bytes: bytes, seq: int) -> bytes:
        """
        Called by server for each incoming packet.
        Only attacks DATA packets (seq > 0).
        """
        # skip non-data packets
        if seq == 0:
            return srft_bytes

        if self.attack_done:
            return srft_bytes

        if self.attack_mode == "tamper":
            self.attack_done = True
            return self.tamper_packet(srft_bytes)

        elif self.attack_mode == "replay":
            if self.captured_srft is None:
                self.captured_srft = srft_bytes
                print(f"[ATTACKER] Captured packet seq {seq} for replay")
                t = threading.Thread(
                    target=self.replay_captured_packet,
                    daemon=True
                )
                t.start()
            return srft_bytes

        elif self.attack_mode == "inject":
            self.attack_done = True
            self.inject_forged_packet()
            return srft_bytes

        return srft_bytes