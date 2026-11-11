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
        # The seed determines the public key, and the public key determines the
        # did:key. Refuse an Identity whose parts disagree: a mismatched pair
        # would sign with one key while advertising another, and every request
        # would fail verification at the server with no hint of why.
        if len(self.private_key) != 32:
            raise ValueError(f"private key must be 32 bytes, got {len(self.private_key)}")
        expected_pub = crypto.public_key_from_seed(self.private_key)
        if self.public_key != expected_pub:
            raise ValueError("public key does not match the one derived from the private seed")
        expected_did = crypto.derive_did_key(expected_pub)
        if self.did_key != expected_did:
            raise ValueError(f"did_key {self.did_key!r} does not match the public key ({expected_did!r})")

    @classmethod
    def generate(cls, agent_id: str) -> Identity:
        """Mint a fresh identity for ``agent_id``."""
        priv, pub = crypto.generate_keypair()
        return cls(agent_id, priv, pub, crypto.derive_did_key(pub))

    @classmethod
    def from_seed(cls, agent_id: str, private_key: bytes) -> Identity:
        """Reconstruct an identity from a stored 32-byte seed."""
        pub = crypto.public_key_from_seed(private_key)
        return cls(agent_id, private_key, pub, crypto.derive_did_key(pub))

    @property
    def private_key_b64(self) -> str:
        return base64.b64encode(self.private_key).decode()

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key).decode()
