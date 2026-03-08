# Internet checksum helpers (IPv4 + UDP)
# Key idea: add 16-bit words with wrap-around carry, then flip bits.

import struct


def pad_if_odd_length(data):
    """
    If the number of bytes is odd, add one 0 byte at the end.
    Why? Because checksum adds 16-bit words (2 bytes at a time).
    """
    if len(data) % 2 == 1:
        return data + b"\x00" # we pad a zero so we can still form the last 16-bit word.
    return data


def add_16bit_words(data):
    """
    Add the data as 16-bit words (2 bytes each) using one's-complement addition.
    This returns the SUM (not flipped yet).
    """
    data = pad_if_odd_length(data) #calls function to pad if odd length

    total = 0 #keep track of the running sum.
    index = 0

    while index < len(data):
        high_byte = data[index]
        low_byte = data[index + 1]

        # Combine two bytes into one 16-bit word (big-endian):
        # Example: 0x45 and 0x00 => (0x45 << 8) + 0x00 = 0x4500
        word = (high_byte << 8) + low_byte

        total = total + word 

        # Wrap-around carry:
        total = (total & 0xFFFF) + (total >> 16) #the & 0xFFFF keeps only the lower 16 bits of the total, while the >> 16 shifts the total right by 16 bits to get any carry that may have occurred from adding two 16-bit words together. This ensures that if the sum exceeds 16 bits, the carry is added back into the total, which is a key aspect of one's-complement addition.

        index = index + 2 #move to the next pair of bytes (next 16-bit word)

    return total


def internet_checksum(data):
    """
    Full Internet checksum:
    1) Add all 16-bit words with wrap-around carry.
    2) Flip all bits (one's complement).
    Result is a 16-bit value that can be used as the checksum.
    """
    sum_16 = add_16bit_words(data)

    checksum = (~sum_16) & 0xFFFF # the ~ operator flips all bits in the sum, and the & 0xFFFF ensures that we only keep the lower 16 bits of the result, which is important because the checksum must be a 16-bit value.
    return checksum


def ipv4_header_checksum(ip_header_bytes):
    """
    IPv4 header checksum is computed ONLY over the IPv4 header.
    IMPORTANT RULE:
    - The checksum field inside the header must be 0 when computing.
    """
    return internet_checksum(ip_header_bytes) #calls the internet_checksum function to compute the checksum for the given IPv4 header bytes, which should have the checksum field set to 0 before calling this function.


def ipv4_string_to_bytes(ip_str):
    """
    Convert '192.168.1.10' to 4 bytes.
    We do this because UDP checksum uses source/destination IP in pseudo-header.
    """
    parts = ip_str.split(".") #split the IP string into its four parts eg ["192", "168", "1", "10"] based on the dot separator, resulting in a list of strings representing each octet of the IP address.
    return bytes([int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])]) #convert each part of the IP address to an integer and then to a byte, resulting in a 4-byte representation of the IP address.


def udp_checksum_ipv4(src_ip_str, dst_ip_str, udp_header_bytes, udp_payload_bytes):
    """
    UDP checksum for IPv4 is computed over:
    (pseudo-header) + (UDP header) + (UDP payload)

    The pseudo-header is NOT actually sent as part of UDP,
    but it is included in checksum calculation to protect:
    - source IP
    - destination IP
    - protocol number
    - UDP length

    IMPORTANT RULE:
    - The UDP checksum field must be 0 when computing.
    """

    src_ip = ipv4_string_to_bytes(src_ip_str) #convert IP string to bytes
    dst_ip = ipv4_string_to_bytes(dst_ip_str)

    udp_length = len(udp_header_bytes) + len(udp_payload_bytes) #UDP length is header + payload length in bytes

    # Pseudo-header format (12 bytes):
    # src IP (4), dst IP (4), zero (1), protocol (1), UDP length (2)
    pseudo_header = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, 17, udp_length) #struct.pack formats the pseudo-header according to the specified format string:
    # !: network byte order (big-endian)

    data_to_check = pseudo_header + udp_header_bytes + udp_payload_bytes #combine pseudo-header, UDP header, and UDP payload for checksum calculation
    return internet_checksum(data_to_check) #calls the internet_checksum function to compute the checksum for the combined data, which includes the pseudo-header, UDP header, and UDP payload.