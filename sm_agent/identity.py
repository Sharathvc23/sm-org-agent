"""Agent identity — a keypair plus the did:key derived from it.

The ergonomic surface a user actually touches: ``Identity.generate("alice")``
gives a ready-to-sign agent. Everything else in the SDK takes an ``Identity``.
The private seed never leaves the object except as the base64 a signer needs.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from sm_agent import crypto


@dataclass(frozen=True)
class Identity:
    agent_id: str
    private_key: bytes  # 32-byte Ed25519 seed
    public_key: bytes  # 32-byte Ed25519 public key
    did_key: str

    def __post_init__(self) -> None:
        if len(self.private_key) != 32:
            raise ValueError(f"private key must be 32 bytes, got {len(self.private_key)}")
        if len(self.public_key) != 32:
            raise ValueError(f"public key must be 32 bytes, got {len(self.public_key)}")

    @classmethod
    def generate(cls, agent_id: str) -> Identity:
        """Mint a fresh identity for ``agent_id``."""
        priv, pub = crypto.generate_keypair()
        return cls(agent_id, priv, pub, crypto.derive_did_key(pub))

    @classmethod
    def from_seed(cls, agent_id: str, private_key: bytes) -> Identity:
        """Reconstruct an identity from a stored 32-byte seed."""
        if len(private_key) != 32:
            raise ValueError(f"private key must be 32 bytes, got {len(private_key)}")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        pub = Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()
        return cls(agent_id, private_key, pub, crypto.derive_did_key(pub))

    @property
    def private_key_b64(self) -> str:
        return base64.b64encode(self.private_key).decode()

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key).decode()
