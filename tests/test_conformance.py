"""The conformance adapter — the six operations the client suite calls.

These pin the adapter against the spec formats directly; the umbrella client
suite is the cross-implementation check, run separately via ``--adapter``.
"""

from __future__ import annotations

import base64

import pytest

from sm_member_sdk import crypto
from sm_member_sdk.conformance import ConformanceAdapter

ADAPTER = ConformanceAdapter()


def test_derive_did_key_matches_crypto() -> None:
    _, pub = crypto.generate_keypair()
    assert ADAPTER.derive_did_key(pub) == crypto.derive_did_key(pub)


def test_derive_did_key_boundary_raises() -> None:
    with pytest.raises(ValueError):
        ADAPTER.derive_did_key(b"\x00" * 31)


def test_canonical_strings() -> None:
    assert ADAPTER.canonical_string("B", "a", "1") == "B:a:1"
    assert ADAPTER.canonical_string_v03("get", "/x", "B", "a", "1", "n") == "GET:/x:B:a:1:n"


def test_sign_boundary_raises_and_signature_verifies() -> None:
    priv, pub = crypto.generate_keypair()
    with pytest.raises(ValueError):
        ADAPTER.sign(b"\x00" * 31, "B:a:1")
    sig = ADAPTER.sign(priv, "B:a:1")
    assert crypto.verify(pub, base64.b64decode(sig), b"B:a:1")


def test_header_sets() -> None:
    h2 = ADAPTER.compose_headers("a", "did:key:zX", "1", "S")
    assert h2["X-Agent-Sig-Scheme"] == "ed25519" and "X-Agent-Nonce" not in h2
    h3 = ADAPTER.compose_headers_v03("a", "did:key:zX", "1", "n", "S")
    assert h3["X-Agent-Sig-Scheme"] == "ed25519+nonce" and h3["X-Agent-Nonce"] == "n"
