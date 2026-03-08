# SRFT Raw Socket File Transfer

A portfolio project implementing a custom Secure Reliable File Transfer (SRFT) protocol using raw sockets in Python.

## Project Goal
This project builds a mini transport protocol from scratch on top of IPv4 and UDP. It includes:

- manual IPv4 header construction
- manual UDP header construction
- Internet checksum computation
- custom SRFT packet format
- raw socket packet transmission
- reliable delivery using ACKs and retransmissions
- full file transfer between client and server

## Why This Project Matters
This project demonstrates low-level networking knowledge, transport protocol design, packet serialization, checksum handling, and reliable data transfer.

## Modules
- `checksum.py` — Internet checksum helpers
- `srft_packet.py` — SRFT header + packet serialization
- `ip_header.py` — IPv4 header builder
- `udp_header.py` — UDP header builder
- `raw_socket.py` — raw socket send/receive
- `reliable.py` — ACK and retransmission logic
- `client.py` — sender
- `server.py` — receiver