import socket
from src.srft_packet import SRFTPacket, DATA, ACK

# Network header sizes
IP_HEADER_SIZE = 20
UDP_HEADER_SIZE = 8


def extract_srft_packet(raw_packet):
    """
    Extract the SRFT packet from a received raw packet.
    Removes the IPv4 and UDP headers.
    """

    srft_data = raw_packet[IP_HEADER_SIZE + UDP_HEADER_SIZE:]

    return SRFTPacket.from_bytes(srft_data)


def wait_for_ack(sock, expected_ack, timeout=2):
    """
    Wait for an ACK packet.

    Parameters:
    sock           -> socket used to receive packets
    expected_ack   -> sequence number we expect acknowledgement for
    timeout        -> seconds to wait before retransmitting

    Returns:
    True  -> correct ACK received
    False -> timeout occurred
    """

    sock.settimeout(timeout)

    try:
        raw_packet, addr = sock.recvfrom(65535)

        srft_packet = extract_srft_packet(raw_packet)

        if srft_packet.flags == ACK and srft_packet.ack_num == expected_ack:
            print("ACK received for packet:", expected_ack)
            return True

    except socket.timeout:
        print("Timeout waiting for ACK")

    return False


def reliable_send(sock, packet_bytes, seq_num, dst_ip):
    """
    Send a packet reliably using Stop-and-Wait protocol.

    The sender keeps retransmitting until the correct ACK is received.
    """

    while True:

        print("Sending packet seq:", seq_num)

        sock.sendto(packet_bytes, (dst_ip, 0))

        ack_received = wait_for_ack(sock, seq_num)

        if ack_received:
            print("Packet delivered successfully\n")
            break

        print("Retransmitting packet...\n")


def send_file(sock, dst_ip, file_path, chunk_size=1024):
    """
    Send a file reliably using Stop-and-Wait.
    """

    seq_num = 1

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(chunk_size)

            if not chunk:
                break

            packet = SRFTPacket(
                seq_num=seq_num,
                ack_num=0,
                flags=DATA,
                window=5,
                payload=chunk
            )

            packet_bytes = packet.to_bytes()

            reliable_send(sock, packet_bytes, seq_num, dst_ip)

            seq_num += 1