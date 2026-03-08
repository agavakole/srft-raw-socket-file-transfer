import struct
from src.checksum import udp_checksum_ipv4


def build_udp_header(src_port, dst_port, payload, src_ip, dst_ip):

    # UDP header length is always 8 bytes
    udp_length = 8 + len(payload)

    # checksum initially zero
    checksum = 0

    # build header with checksum = 0
    header = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        udp_length,
        checksum
    )

    # compute UDP checksum using pseudo header
    checksum = udp_checksum_ipv4(
        src_ip,
        dst_ip,
        header,
        payload
    )

    # rebuild header with correct checksum
    header = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        udp_length,
        checksum
    )

    return header