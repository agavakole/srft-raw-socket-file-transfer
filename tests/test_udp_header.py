import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.udp_header import build_udp_header

payload = b"hello"

header = build_udp_header(
    5000,
    6000,
    payload,
    "192.168.1.1",
    "192.168.1.2"
)

print("UDP header length:", len(header))
print(header)