import os
import struct
from src.security import (
    compute_hmac,
    verify_hmac,
    derive_session_key,
    generate_nonce,
    generate_session_id
)

# Handshake packet types
HELLO_CLIENT = 0xA1
HELLO_SERVER = 0xA2

# Handshake packet sizes
CLIENT_NONCE_LEN = 16
SERVER_NONCE_LEN = 16
SESSION_ID_LEN = 8
HMAC_LEN = 32


def build_client_hello(psk: bytes) -> tuple:
    """
    Build ClientHello packet.
    Returns (packet_bytes, client_nonce)

    Format:
    - type (1 byte) = HELLO_CLIENT
    - version (1 byte) = 1
    - client_nonce (16 bytes)
    - hmac (32 bytes) over (type + version + client_nonce)
    """
    msg_type = HELLO_CLIENT
    version = 1
    client_nonce = generate_nonce(CLIENT_NONCE_LEN)

    # data to authenticate
    data = struct.pack("!BB", msg_type, version) + client_nonce

    # compute HMAC over handshake fields
    mac = compute_hmac(psk, data)

    packet = data + mac
    return packet, client_nonce


def parse_client_hello(packet: bytes, psk: bytes) -> bytes:
    """
    Parse and verify ClientHello.
    Returns client_nonce if valid.
    Raises ValueError if HMAC verification fails.
    """
    expected_len = 1 + 1 + CLIENT_NONCE_LEN + HMAC_LEN
    if len(packet) < expected_len:
        raise ValueError("ClientHello too short")

    msg_type = packet[0]
    version = packet[1]
    client_nonce = packet[2:2 + CLIENT_NONCE_LEN]
    received_hmac = packet[2 + CLIENT_NONCE_LEN:2 + CLIENT_NONCE_LEN + HMAC_LEN]

    if msg_type != HELLO_CLIENT:
        raise ValueError(f"Expected HELLO_CLIENT, got {msg_type}")

    # verify HMAC
    data = struct.pack("!BB", msg_type, version) + client_nonce
    if not verify_hmac(psk, data, received_hmac):
        raise ValueError("ClientHello HMAC verification failed — rejected")

    return client_nonce


def build_server_hello(psk: bytes, client_nonce: bytes) -> tuple:
    """
    Build ServerHello packet.
    Returns (packet_bytes, server_nonce, session_id)

    Format:
    - type (1 byte) = HELLO_SERVER
    - version (1 byte) = 1
    - session_id (8 bytes)
    - server_nonce (16 bytes)
    - hmac (32 bytes) over all fields above
    """
    msg_type = HELLO_SERVER
    version = 1
    session_id = generate_session_id()
    server_nonce = generate_nonce(SERVER_NONCE_LEN)

    # data to authenticate — include client_nonce to bind to this session
    data = (
        struct.pack("!BB", msg_type, version)
        + session_id
        + server_nonce
        + client_nonce
    )

    mac = compute_hmac(psk, data)
    packet = struct.pack("!BB", msg_type, version) + session_id + server_nonce + mac

    return packet, server_nonce, session_id


def parse_server_hello(packet: bytes, psk: bytes, client_nonce: bytes) -> tuple:
    """
    Parse and verify ServerHello.
    Returns (server_nonce, session_id) if valid.
    Raises ValueError if HMAC verification fails.
    """
    expected_len = 1 + 1 + SESSION_ID_LEN + SERVER_NONCE_LEN + HMAC_LEN
    if len(packet) < expected_len:
        raise ValueError("ServerHello too short")

    msg_type = packet[0]
    version = packet[1]
    session_id = packet[2:2 + SESSION_ID_LEN]
    server_nonce = packet[2 + SESSION_ID_LEN:2 + SESSION_ID_LEN + SERVER_NONCE_LEN]
    received_hmac = packet[2 + SESSION_ID_LEN + SERVER_NONCE_LEN:]

    if msg_type != HELLO_SERVER:
        raise ValueError(f"Expected HELLO_SERVER, got {msg_type}")

    # verify HMAC — must include client_nonce to prevent replay
    data = (
        struct.pack("!BB", msg_type, version)
        + session_id
        + server_nonce
        + client_nonce
    )

    if not verify_hmac(psk, data, received_hmac):
        raise ValueError("ServerHello HMAC verification failed — rejected")

    return server_nonce, session_id