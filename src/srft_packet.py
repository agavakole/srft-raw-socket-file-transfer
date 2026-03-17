import struct

# Magic identifier for our protocol
MAGIC = b"SRFT"
VERSION = 1

# Packet types
TYPE_REQ  = 1  # client requests a file from server
TYPE_DATA = 2  # data packet carrying file chunk
TYPE_ACK  = 3  # acknowledgement
TYPE_FIN  = 4  # end of transfer
TYPE_ERR  = 5  # error

# Aliases so existing code doesn't break
DATA = TYPE_DATA
ACK  = TYPE_ACK
FIN  = TYPE_FIN

# Header structure
# magic(4s), version(B), msg_type(B), flags(H), seq(I), ack(I),
# payload_len(H), window(H), checksum(H), reserved(H)
HEADER_FORMAT = "!4sBBHIIHHHH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def checksum16(data: bytes) -> int:
    """
    Compute 16-bit internet checksum over SRFT header + payload.
    Detects corruption at the application layer.
    """
    if len(data) % 2 == 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        s += word
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def pack_packet(msg_type: int, seq: int, ack: int,
                payload: bytes, window: int = 0, flags: int = 0) -> bytes:
    """
    Build a complete SRFT packet with checksum.
    Returns raw bytes ready to be sent.
    """
    payload_len = len(payload)
    reserved = 0
    checksum = 0

    # Build header with checksum = 0 first
    header_wo_checksum = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        VERSION,
        msg_type,
        flags,
        seq,
        ack,
        payload_len,
        window,
        checksum,
        reserved
    )

    # Compute checksum over header + payload
    checksum = checksum16(header_wo_checksum + payload)

    # Rebuild header with real checksum
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        VERSION,
        msg_type,
        flags,
        seq,
        ack,
        payload_len,
        window,
        checksum,
        reserved
    )

    return header + payload


def unpack_packet(data: bytes) -> tuple:
    """
    Parse raw bytes into packet fields.
    Returns (info_dict, payload) or raises ValueError if invalid.
    """
    if len(data) < HEADER_SIZE:
        raise ValueError("Packet too short")

    fields = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    magic, version, msg_type, flags, seq, ack, payload_len, window, checksum, _ = fields

    if magic != MAGIC:
        raise ValueError("Invalid SRFT magic")

    payload = data[HEADER_SIZE:HEADER_SIZE + payload_len]

    # Verify checksum
    header_wo_checksum = struct.pack(
        HEADER_FORMAT,
        magic,
        version,
        msg_type,
        flags,
        seq,
        ack,
        payload_len,
        window,
        0,
        0
    )

    expected = checksum16(header_wo_checksum + payload)
    if expected != checksum:
        raise ValueError("SRFT checksum mismatch — packet corrupted")

    info = {
        "type":        msg_type,
        "seq":         seq,
        "ack":         ack,
        "payload_len": payload_len,
        "window":      window,
        "flags":       flags,
    }

    return info, payload