import socket
from src.raw_socket import create_raw_socket
from src.reliable import reliable_send
from src.srft_packet import SRFTPacket, DATA
from src.ip_header import build_ipv4_header
from src.udp_header import build_udp_header


def send_file(src_ip, dst_ip, src_port, dst_port, file_path):

    sock = create_raw_socket()

    seq_num = 1
    chunk_size = 1024

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(chunk_size)

            if not chunk:
                break

            # Create SRFT packet
            srft_packet = SRFTPacket(
                seq_num=seq_num,
                ack_num=0,
                flags=DATA,
                window=5,
                payload=chunk
            )

            srft_bytes = srft_packet.to_bytes()

            # Build UDP header
            udp_header = build_udp_header(
                src_port,
                dst_port,
                srft_bytes,
                src_ip,
                dst_ip
            )

            udp_packet = udp_header + srft_bytes

            # Build IP header
            ip_header = build_ipv4_header(
                src_ip,
                dst_ip,
                len(udp_packet)
            )

            # Full packet
            full_packet = ip_header + udp_packet

            # Send reliably
            reliable_send(sock, full_packet, seq_num, dst_ip)

            seq_num += 1


if __name__ == "__main__":

    src_ip = "192.168.1.10"
    dst_ip = "192.168.1.20"

    src_port = 5000
    dst_port = 6000

    file_path = "file.txt"

    send_file(src_ip, dst_ip, src_port, dst_port, file_path)