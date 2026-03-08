import socket
from src.srft_packet import SRFTPacket, ACK


def create_receive_socket(port):
    """Raw UDP socket that CAN receive — used by client to receive ACKs."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.bind(("0.0.0.0", port))  # bind to all interfaces on the specified port
    return sock


def extract_srft_packet(raw_packet):
    ip_header_length = (raw_packet[0] & 0x0F) * 4
    udp_header_size = 8
    srft_data = raw_packet[ip_header_length + udp_header_size:]
    return SRFTPacket.from_bytes(srft_data)


def extract_dst_port(raw_packet):
    """Read the destination port from the UDP header."""
    ip_header_length = (raw_packet[0] & 0x0F) * 4
    # UDP header: src_port (2), dst_port (2), length (2), checksum (2)
    dst_port = (raw_packet[ip_header_length + 2] << 8) + raw_packet[ip_header_length + 3]
    return dst_port


def wait_for_ack(recv_sock, expected_ack, our_port, timeout=2):
    recv_sock.settimeout(timeout)

    while True:
        try:
            raw_packet, addr = recv_sock.recvfrom(65535)

            dst_port = extract_dst_port(raw_packet)
            if dst_port != our_port:
                continue

            srft_packet = extract_srft_packet(raw_packet)

            if srft_packet.flags == ACK and srft_packet.ack_num == expected_ack:
                print("ACK received for packet:", expected_ack)
                return True

        except ValueError:
            continue

        except (socket.timeout, TimeoutError):  # <-- THIS LINE CHANGED
            print("Timeout waiting for ACK")
            return False


def reliable_send(send_sock, recv_sock, packet_bytes, seq_num, dst_ip, our_port=5000):
    """Stop-and-Wait reliable transmission."""
    while True:
        print("Sending packet seq:", seq_num)
        send_sock.sendto(packet_bytes, (dst_ip, 0))

        if wait_for_ack(recv_sock, seq_num, our_port):
            print("Packet delivered successfully\n")
            break

        print("Retransmitting packet...\n")