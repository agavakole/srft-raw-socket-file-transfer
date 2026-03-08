import struct

# Packet types
DATA = 1
ACK = 2
FIN = 3

# Header structure
HEADER_FORMAT = "!IIBHH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


class SRFTPacket:

    def __init__(self, seq_num, ack_num, flags, window, payload=b""):
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.window = window
        self.payload = payload

    def to_bytes(self):

        payload_length = len(self.payload)

        header = struct.pack(
            HEADER_FORMAT,
            self.seq_num,
            self.ack_num,
            self.flags,
            self.window,
            payload_length
        )

        packet = header + self.payload
        return packet

    @classmethod
    def from_bytes(cls, data):

        header = data[:HEADER_SIZE]

        seq_num, ack_num, flags, window, payload_length = struct.unpack(
            HEADER_FORMAT,
            header
        )

        payload_start = HEADER_SIZE
        payload_end = HEADER_SIZE + payload_length

        payload = data[payload_start:payload_end]

        return cls(seq_num, ack_num, flags, window, payload)