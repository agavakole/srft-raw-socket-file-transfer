import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.ip_header import build_ipv4_header

header = build_ipv4_header("192.168.1.1", "192.168.1.2", 100)

print("Header length:", len(header))
print(header)