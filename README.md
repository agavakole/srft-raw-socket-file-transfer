# SRFT — Secure Reliable File Transfer Protocol

A custom secure and reliable file transfer protocol built from scratch over raw UDP sockets in Python. This project implements the full Internet protocol stack manually — including IPv4 headers, UDP headers, checksums, and a custom application-layer security protocol — without relying on any OS networking abstractions.

Built as part of CS 5700 (Computer Networks) at Northeastern University.

---

## What This Project Does

Standard UDP provides no reliability or security. This project builds both from scratch:

- **Phase 1** — Reliable file transfer over raw UDP with checksums, sequence numbers, cumulative ACKs, retransmission, and MD5 verification
- **Phase 2** — Secure file transfer with PSK handshake, AES-GCM encryption, replay protection, and SHA-256 end-to-end verification

---

## Architecture

```
┌─────────────────────────────────────────┐
│           Application Layer             │
│     SRFT Protocol (custom packets)      │
│   AES-GCM encryption, HMAC handshake   │
├─────────────────────────────────────────┤
│         Transport Layer (manual)        │
│      UDP header built from scratch      │
│     Checksum computed via RFC 768       │
├─────────────────────────────────────────┤
│          Network Layer (manual)         │
│      IPv4 header built from scratch     │
│     Checksum computed via RFC 791       │
├─────────────────────────────────────────┤
│              SOCK_RAW                   │
│     Raw socket — OS bypassed entirely   │
└─────────────────────────────────────────┘
```

---

## Key Features

### Phase 1 — Reliable Transfer

- **SOCK_RAW sockets** — manually constructs every IP and UDP header byte
- **Internet checksum** — RFC-compliant one's complement checksum for both IP and UDP headers, plus application-layer SRFT packet checksum
- **Sliding window** — configurable window size for efficient transfer of large files
- **Cumulative ACKs** — server batches ACKs at configurable intervals instead of ACKing every packet
- **Retransmission** — automatic retransmission on timeout with configurable RTO
- **Duplicate detection** — sequence number tracking prevents duplicate writes
- **Out-of-order buffering** — packets arriving out of order are buffered and flushed in order
- **MD5 verification** — both sides compute and compare MD5 hash of the file
- **Transfer stats** — server produces a stats report file after every transfer
- **Multithreading** — separate threads for sending, receiving, and ACK batching

### Phase 2 — Secure Transfer

- **Pre-shared key (PSK)** — stored in config file, used as root secret
- **Security handshake** — ClientHello/ServerHello with HMAC-SHA256 authentication
- **HKDF key derivation** — per-session encryption key derived from PSK + client nonce + server nonce
- **AES-GCM AEAD encryption** — authenticated encryption with associated data on every DATA packet
- **Replay protection** — sequence number tracking rejects replayed packets
- **SHA-256 file verification** — sender encrypts and sends SHA-256 digest, receiver verifies
- **Attack test modes** — built-in `--attack` flag for tamper/replay/inject testing

---

## Tech Stack

- **Language** — Python 3.12
- **Sockets** — `SOCK_RAW` with `IPPROTO_RAW` (send) and `IPPROTO_UDP` (receive)
- **Cryptography** — `cryptography` library (AES-GCM, HKDF-SHA256, HMAC-SHA256)
- **Threading** — `threading` module for concurrent send/receive/ACK loops
- **Platform** — Linux / WSL2 (raw sockets require Linux kernel)

---

## Project Structure

```
srft-raw-socket-file-transfer/
├── main.py              # Entry point — run as client or server
├── config.py            # Config loader with validation
├── config.json          # Network, transfer, and security settings
├── file.txt             # Sample test file
└── src/
    ├── client.py        # SRFTClient class — sliding window sender
    ├── server.py        # SRFTServer class — receiver with ACK batching
    ├── srft_packet.py   # SRFT packet format — pack/unpack with checksum
    ├── ip_header.py     # IPv4 header builder and parser
    ├── udp_header.py    # UDP header builder and parser
    ├── checksum.py      # Internet checksum utilities (IP + UDP)
    ├── security.py      # AES-GCM, HKDF, HMAC, SHA-256
    ├── handshake.py     # ClientHello / ServerHello
    ├── attacker.py      # Built-in attack modes for security testing
    └── raw_socket.py    # Raw socket factory
```

---

## How to Run

### Requirements

```bash
# Linux or WSL2 required (raw sockets need Linux kernel)
pip3 install cryptography
```

### Configuration

Edit `config.json` to set IPs, ports, and security settings:

```json
{
  "network": {
    "client_ip": "127.0.0.1",
    "server_ip": "127.0.0.1",
    "client_port": 5000,
    "server_port": 6000
  },
  "transfer": {
    "chunk_size": 1024,
    "send_window_packets": 8
  },
  "timers": {
    "rto_ms": 2000,
    "ack_interval_ms": 50
  },
  "security": {
    "enabled": true,
    "psk": "your-32-byte-secret-key-here!!!!"
  }
}
```

### Running

**Terminal 1 — Start server:**

```bash
sudo python3 main.py --mode server --config config.json
```

**Terminal 2 — Start client:**

```bash
sudo python3 main.py --mode client --config config.json --file file.txt
```

> `sudo` is required because raw sockets need root privileges on Linux.

---

## Security Test Plan

### Test 1 — Baseline Secure Transfer

```bash
sudo python3 main.py --mode server --config config.json
sudo python3 main.py --mode client --config config.json --file file.txt
```

**Expected:** Handshake = Success, AEAD failures = 0, SHA-256 = Yes

### Test 2 — Wrong PSK

```bash
sudo python3 main.py --mode server --config config.json
sudo python3 main.py --mode client --config config_wrong_psk.json --file file.txt
```

**Expected:** Handshake = Fail, connection rejected, no file output

### Test 3 — Tamper Detection

```bash
sudo python3 main.py --mode server --config config.json --attack tamper
sudo python3 main.py --mode client --config config.json --file file.txt
```

**Expected:** AEAD failures = 1, retransmission recovers, SHA-256 = Yes

### Test 4 — Replay Protection

```bash
sudo python3 main.py --mode server --config config.json --attack replay
sudo python3 main.py --mode client --config config.json --file file.txt
```

**Expected:** Replay drops = 1, SHA-256 = Yes

### Test 5 — Forged Injection

```bash
sudo python3 main.py --mode server --config config.json --attack inject
sudo python3 main.py --mode client --config config.json --file file.txt
```

**Expected:** AEAD failures = 1, SHA-256 = Yes

---

## Sample Output

### Successful Secure Transfer

```
[SERVER] Security enabled — waiting for handshake
[SERVER] ClientHello verified
[SERVER] Handshake SUCCESS — session: 270d1b15260ae30a
[SERVER] File request received: file.txt
[SERVER] Written seq 1 to file
[SERVER] Sent cumulative ACK: 1
[SERVER] FIN received — transfer complete
[SERVER] SHA-256 match: True

--- Transfer Stats ---
File: file.txt
Size: 81 bytes
Packets received: 1
Duration: 00:00:00
Security: enabled (PSK + AES-GCM)
Handshake: Success
AEAD failures: 0
Replay drops: 0
SHA-256 match: Yes
MD5: 5054dcab3afbf4651ce9326a9a3322b9
```

---

## What I Learned

- How IPv4 and UDP headers are structured at the byte level
- How the Internet checksum algorithm works using one's complement addition
- How raw sockets bypass the OS networking stack
- Why Linux blocks raw sockets on loopback and how Windows handles them differently
- How AES-GCM provides both encryption and authentication in a single operation
- Why HKDF is used instead of using a PSK directly as an encryption key
- How cumulative ACKs reduce network overhead compared to per-packet ACKs
- How sliding window protocols improve throughput over stop-and-wait
- The practical challenges of building reliable protocols — duplicate detection, out-of-order buffering, retransmission timers

---

## Limitations

- Requires Linux/WSL2 — Windows raw socket restrictions prevent loopback testing
- Security handshake uses a pre-shared key — no public key infrastructure
- No congestion control — window size is fixed, not adaptive
- Single file transfer per session — no persistent connection

---

## Author

Kole Agava — CS Master's student at Northeastern University  
GitHub: [agavakole](https://github.com/agavakole)
