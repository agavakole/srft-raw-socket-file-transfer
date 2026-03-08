import socket
import struct
from src.srft_packet import FIN, SRFTPacket, DATA, ACK
from src.ip_header import build_ipv4_header
from src.udp_header import build_udp_header

OUTPUT_FILE = "received_file.txt"
SERVER_PORT = 6000
CLIENT_PORT = 5000


def create_receive_socket(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.bind(("0.0.0.0", port))  # bind to all interfaces on the specified port
    return sock


def create_send_socket():
    # IPPROTO_RAW is needed to send hand-crafted IP+UDP packets
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    return sock


def extract_src_ip(packet):
    """
    Extract the source IP from the IPv4 header.
    Bytes 12-15 of the IP header are the source IP.
    """
    return socket.inet_ntoa(packet[12:16])


def send_ack(send_sock, src_ip_of_sender, seq_num):
    src_ip =  "127.0.0.1"   # server IP
    dst_ip = src_ip_of_sender  # send ACK back to whoever sent the data

    ack_packet = SRFTPacket(
        seq_num=0,
        ack_num=seq_num,
        flags=ACK,
        window=5,
        payload=b""
    )

    srft_bytes = ack_packet.to_bytes()

    udp_header = build_udp_header(SERVER_PORT, CLIENT_PORT, srft_bytes, src_ip, dst_ip)
    udp_packet = udp_header + srft_bytes
    ip_header = build_ipv4_header(src_ip, dst_ip, len(udp_packet))
    full_packet = ip_header + udp_packet

    send_sock.sendto(full_packet, (dst_ip, 0))
    print("Sent ACK for:", seq_num)


def process_packet(packet, send_sock):
    ip_header_length = (packet[0] & 0x0F) * 4
    udp_header_size = 8

    # Filter: only handle packets destined for our port
    dst_port = (packet[ip_header_length + 2] << 8) + packet[ip_header_length + 3]
    if dst_port != SERVER_PORT:
        return

    # Extract real sender IP from IP header (don't trust addr from recvfrom)
    sender_ip = extract_src_ip(packet)

    try:
        srft_data = packet[ip_header_length + udp_header_size:]
        srft_packet = SRFTPacket.from_bytes(srft_data)
    except ValueError:
        return  # not an SRFT packet, ignore

    if srft_packet.flags == DATA:
        print("Received DATA packet, seq:", srft_packet.seq_num)

        with open(OUTPUT_FILE, "ab") as f:
            f.write(srft_packet.payload)

        print("Data written to file")
        send_ack(send_sock, sender_ip, srft_packet.seq_num)

    elif srft_packet.flags == FIN:
        print("FIN received — transfer complete")


def receive_packets(recv_sock, send_sock):
    while True:
        packet, _ = recv_sock.recvfrom(65535)  # addr is unreliable on raw sockets
        process_packet(packet, send_sock)


if __name__ == "__main__":
    recv_sock = create_receive_socket(SERVER_PORT)
    send_sock = create_send_socket()

    print("Server listening...")
    receive_packets(recv_sock, send_sock)