import struct
from src.checksum import ipv4_header_checksum, ipv4_string_to_bytes


def build_ipv4_header(src_ip, dst_ip, payload_length):

    # IPv4 version (4) and header length (5 words = 20 bytes)
    version = 4
    ihl = 5
    version_ihl = (version << 4) + ihl

    # Type of Service
    tos = 0

    # Total packet length = header + payload
    total_length = 20 + payload_length

    # Identification (can be random or constant)
    identification = 54321

    # Flags and fragment offset
    flags_fragment = 0

    # Time To Live
    ttl = 64

    # Protocol number for UDP
    protocol = 17

    # Checksum initially zero
    checksum = 0

    # Convert IP strings to bytes
    src_ip_bytes = ipv4_string_to_bytes(src_ip)
    dst_ip_bytes = ipv4_string_to_bytes(dst_ip)

    # Build header with checksum = 0
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        checksum,
        src_ip_bytes,
        dst_ip_bytes
    )

    # Compute checksum
    checksum = ipv4_header_checksum(header)

    # Rebuild header with correct checksum
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        checksum,
        src_ip_bytes,
        dst_ip_bytes
    )

    return header