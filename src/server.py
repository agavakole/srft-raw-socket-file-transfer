import socket
from src.srft_packet import SRFTPacket, DATA, ACK

def create_receive_socket(port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_UDP
    )

    sock.bind(("0.0.0.0", port))

    return sock

def send_ack(sock, addr, seq_num):

    ack_packet = SRFTPacket(
        seq_num=0,
        ack_num=seq_num,
        flags=ACK,
        window=5,
        payload=b""
    )

    raw_packet = ack_packet.to_bytes()

    sock.sendto(raw_packet, addr)

    print("Sent ACK for sequence:", seq_num)

def process_packet(packet, sock, addr):

    ip_header_size = 20
    udp_header_size = 8

    srft_data = packet[ip_header_size + udp_header_size:]

    srft_packet = SRFTPacket.from_bytes(srft_data)

    if srft_packet.flags == DATA:

        print("Received DATA packet")
        print("Sequence:", srft_packet.seq_num)
        print("Payload:", srft_packet.payload)

        send_ack(sock, addr, srft_packet.seq_num)

def receive_packets(sock):

    while True:

        packet, addr = sock.recvfrom(65535)

        print("Packet received from:", addr)

        process_packet(packet, sock, addr)

if __name__ == "__main__":

    port = 6000

    sock = create_receive_socket(port)

    print("Server listening...")

    receive_packets(sock)