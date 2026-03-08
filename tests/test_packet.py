import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.srft_packet import SRFTPacket, DATA

packet = SRFTPacket(1, 0, DATA, 5, b"hello")

raw = packet.to_bytes()

parsed = SRFTPacket.from_bytes(raw)

print("Sequence:", parsed.seq_num)
print("Payload:", parsed.payload)