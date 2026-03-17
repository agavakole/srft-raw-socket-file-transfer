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


