"""Ed25519 + did:key primitives — the cryptographic floor the SDK signs on.

W3C did:key (multibase base58btc over multicodec 0xed01 ‖ pubkey32) and Ed25519
over a canonical string. Pure functions: bytes and strings in, bytes and strings
out — no time, no I/O, no framework. Keys cross the API as standard base64 to
match how a client stores them; raw-bytes helpers back the conformance adapter.
"""

from __future__ import annotations

import base64

import base58
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ED25519_MULTICODEC_PREFIX = b"\xed\x01"


def generate_keypair() -> tuple[bytes, bytes]:
    """Return a fresh ``(private_seed32, public_key32)`` Ed25519 pair."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return priv.private_bytes_raw(), pub


def public_key_from_seed(private_key32: bytes) -> bytes:
    """The 32-byte Ed25519 public key a 32-byte seed determines."""
    if len(private_key32) != 32:
        raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(private_key32)}")
    return Ed25519PrivateKey.from_private_bytes(private_key32).public_key().public_bytes_raw()


def derive_did_key(pubkey32: bytes) -> str:
    """32-byte Ed25519 public key → ``did:key:z<base58btc(0xed01 ‖ pubkey)>``."""
    if len(pubkey32) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(pubkey32)}")
    return "did:key:z" + base58.b58encode(ED25519_MULTICODEC_PREFIX + pubkey32).decode()


def build_did_key(pubkey_b64: str) -> str:
    """did:key from a standard-base64 public key (the SDK's storage form)."""
    return derive_did_key(base64.b64decode(pubkey_b64))


def parse_did_key(did_key: str) -> bytes:
    """Inverse of :func:`derive_did_key`: ``did:key`` string → 32-byte public key."""
    if not did_key.startswith("did:key:z"):
        raise ValueError(f"not a did:key: {did_key!r}")
    decoded = base58.b58decode(did_key[len("did:key:z") :])
    if not decoded.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError("did:key does not encode an Ed25519 key")
    pub = decoded[len(ED25519_MULTICODEC_PREFIX) :]
    if len(pub) != 32:
        raise ValueError(f"decoded key has wrong length: {len(pub)}")
    return pub


def ed25519_sign_message(message: str, private_key_b64: str) -> str:
    """Standard-base64 Ed25519 signature over ``message`` (UTF-8) by a b64 seed."""
    seed = base64.b64decode(private_key_b64)
    return base64.b64encode(_sign_raw(seed, message.encode())).decode()


def _sign_raw(private_key32: bytes, message: bytes) -> bytes:
    if len(private_key32) != 32:
        raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(private_key32)}")
    return Ed25519PrivateKey.from_private_bytes(private_key32).sign(message)


def verify(pubkey32: bytes, signature: bytes, message: bytes) -> bool:
    """True iff ``signature`` is a valid Ed25519 signature over ``message``."""
    try:
        Ed25519PublicKey.from_public_bytes(pubkey32).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
