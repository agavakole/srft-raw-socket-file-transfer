import socket
from src.raw_socket import create_raw_socket
from src.reliable import reliable_send, create_receive_socket  # ADD THIS
from src.srft_packet import SRFTPacket, DATA, FIN
from src.ip_header import build_ipv4_header
from src.udp_header import build_udp_header


def send_file(src_ip, dst_ip, src_port, dst_port, file_path):

    send_sock = create_raw_socket()         # for sending (IPPROTO_RAW)
    recv_sock = create_receive_socket(src_port)  # for receiving ACKs (IPPROTO_UDP)

    seq_num = 1
    chunk_size = 1024

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break

            srft_packet = SRFTPacket(seq_num=seq_num, ack_num=0, flags=DATA, window=5, payload=chunk)
            srft_bytes = srft_packet.to_bytes()
            udp_header = build_udp_header(src_port, dst_port, srft_bytes, src_ip, dst_ip)
            udp_packet = udp_header + srft_bytes
            ip_header = build_ipv4_header(src_ip, dst_ip, len(udp_packet))
            full_packet = ip_header + udp_packet
            
            reliable_send(send_sock, recv_sock, full_packet, seq_num, dst_ip, our_port=src_port) # pass both sockets
            seq_num += 1

    # FIN packet (same as before, no change needed)
    fin_packet = SRFTPacket(seq_num=seq_num, ack_num=0, flags=FIN, window=5, payload=b"")
    fin_bytes = fin_packet.to_bytes()
    udp_header = build_udp_header(src_port, dst_port, fin_bytes, src_ip, dst_ip)
    udp_packet = udp_header + fin_bytes
    ip_header = build_ipv4_header(src_ip, dst_ip, len(udp_packet))
    full_packet = ip_header + udp_packet
    send_sock.sendto(full_packet, (dst_ip, 0))
    print("FIN packet sent — transfer complete")


if __name__ == "__main__":
    src_ip = "127.0.0.1"
    dst_ip = "127.0.0.1"
    src_port = 5000
    dst_port = 6000
    file_path = "file.txt"
    send_file(src_ip, dst_ip, src_port, dst_port, file_path)