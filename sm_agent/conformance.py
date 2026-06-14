"""Conformance adapter — plugs this SDK into the chapter-protocol client suite.

The suite calls these six pure operations and asserts each against the spec's
test vectors. A runtime that does its signing in one internal call still must
expose the operations independently so each can be verified in isolation. Select
it with ``--adapter=sm_agent.conformance:ConformanceAdapter``.
"""

from __future__ import annotations

import base64

from sm_agent import crypto, signing


class ConformanceAdapter:
    """Wraps :mod:`sm_agent.crypto` + :mod:`sm_agent.signing`."""

    name = "sm-agent"
    runtime_path = __file__

    def derive_did_key(self, pubkey32: bytes) -> str:
        return crypto.derive_did_key(pubkey32)

    def canonical_string(self, body: str, agent_id: str, timestamp: str) -> str:
        return signing.canonical_string(body, agent_id, timestamp)

    def sign(self, private_key32: bytes, canonical: str) -> str:
        if len(private_key32) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(private_key32)}")
        return crypto.ed25519_sign_message(canonical, base64.b64encode(private_key32).decode())

    def compose_headers(
        self, agent_id: str, did_key: str, timestamp: str, signature_b64: str
    ) -> dict[str, str]:
        return signing.compose_headers(agent_id, did_key, timestamp, signature_b64)

    def canonical_string_v03(
        self, method: str, url_path: str, body: str, agent_id: str, timestamp: str, nonce: str
    ) -> str:
        return signing.canonical_string_v03(method, url_path, body, agent_id, timestamp, nonce)

    def compose_headers_v03(
        self, agent_id: str, did_key: str, timestamp: str, nonce: str, signature_b64: str
    ) -> dict[str, str]:
        return signing.compose_headers_v03(agent_id, did_key, timestamp, nonce, signature_b64)
