import socket
from src.srft_packet import SRFTPacket, DATA


def create_receive_socket(port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_UDP
    )

    sock.bind(("0.0.0.0", port))

    return sock


def process_packet(packet):

    ip_header_size = 20
    udp_header_size = 8

    srft_data = packet[ip_header_size + udp_header_size:]

    srft_packet = SRFTPacket.from_bytes(srft_data)

    if srft_packet.flags == DATA:

        print("Received DATA packet")
        print("Sequence:", srft_packet.seq_num)
        print("Payload:", srft_packet.payload)


def receive_packets(sock):

    while True:

        packet, addr = sock.recvfrom(65535)

        print("Packet received from:", addr)

        process_packet(packet)


if __name__ == "__main__":

    port = 6000

    sock = create_receive_socket(port)

    print("Server listening...")

    receive_packets(sock)