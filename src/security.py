import hashlib
import hmac
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# -------------------------------------------------
# HMAC
# -------------------------------------------------

def compute_hmac(psk: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 over data using the PSK.
    Used during handshake to authenticate ClientHello and ServerHello.
    """
    return hmac.new(psk, data, hashlib.sha256).digest()


def verify_hmac(psk: bytes, data: bytes, received_hmac: bytes) -> bool:
    """
    Verify HMAC-SHA256. Uses constant-time comparison to prevent timing attacks.
    Returns True if valid, False if tampered.
    """
    expected = compute_hmac(psk, data)
    return hmac.compare_digest(expected, received_hmac)


# -------------------------------------------------
# Key Derivation
# -------------------------------------------------

def derive_session_key(psk: bytes, client_nonce: bytes, server_nonce: bytes) -> bytes:
    """
    Derive a 32-byte session encryption key from the PSK and both nonces.
    Uses HKDF-SHA256 as the Key Derivation Function (KDF).

    Why HKDF?
    - PSK alone is not safe to use directly as an encryption key
    - HKDF mixes in the nonces so every session gets a unique key
    - Even if PSK is reused across sessions, enc_key is always fresh
    """
    salt = client_nonce + server_nonce  # combine nonces as salt
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,          # 32 bytes = 256-bit AES key
        salt=salt,
        info=b"srft-enc-key"   # context label
    )
    return hkdf.derive(psk)


# -------------------------------------------------
# AES-GCM AEAD Encryption
# -------------------------------------------------

def encrypt_payload(enc_key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """
    Encrypt plaintext using AES-GCM (AEAD).

    Parameters:
    - enc_key: 32-byte session key derived from HKDF
    - nonce: 12-byte unique nonce per packet (never reuse!)
    - plaintext: the file chunk to encrypt
    - aad: Additional Authenticated Data — fields that are
           authenticated but NOT encrypted (session_id, seq, flags)

    Returns ciphertext + 16-byte GCM authentication tag (appended by library)

    Why AES-GCM?
    - Provides both confidentiality (encryption) and integrity (auth tag)
    - AAD lets us authenticate packet headers without encrypting them
    - If any bit is tampered, decryption raises an exception
    """
    aesgcm = AESGCM(enc_key)
    return aesgcm.encrypt(nonce, plaintext, aad)


def decrypt_payload(enc_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-GCM.
    Raises InvalidTag exception if authentication fails (tampered packet).
    Caller must catch this and discard the packet.
    """
    aesgcm = AESGCM(enc_key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# -------------------------------------------------
# AAD Builder
# -------------------------------------------------

def build_aad(session_id: bytes, seq: int, ack: int, msg_type: int) -> bytes:
    """
    Build Additional Authenticated Data (AAD) for AES-GCM.
    These fields are authenticated but not encrypted.

    Per spec requirements:
    - session_id (8 bytes)
    - sequence_number (4 bytes)
    - ack_number (4 bytes)
    - flags/type (1 byte)
    """
    return session_id + struct.pack("!IIB", seq, ack, msg_type)


# -------------------------------------------------
# Nonce Generation
# -------------------------------------------------

def generate_nonce(length: int = 12) -> bytes:
    """
    Generate a cryptographically random nonce.
    12 bytes is the recommended size for AES-GCM.
    Never reuse a nonce with the same key.
    """
    return os.urandom(length)


def generate_session_id() -> bytes:
    """Generate a random 8-byte session ID."""
    return os.urandom(8)


# -------------------------------------------------
# SHA-256 File Digest
# -------------------------------------------------

def compute_sha256(filepath: str) -> bytes:
    """
    Compute SHA-256 hash of a file.
    Used for end-to-end file verification after transfer.
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.digest()