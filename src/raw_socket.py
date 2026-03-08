import socket


def create_raw_socket():
    """
    Create a raw socket for sending packets.
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_RAW
    )

    return sock


def send_packet(sock, packet, dst_ip):
    """
    Send a raw packet to the destination.
    """

    sock.sendto(packet, (dst_ip, 0))