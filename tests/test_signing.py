"""Canonical strings, header sets, and the one-call signer."""

from __future__ import annotations

import pytest

from sm_member_sdk import crypto, signing
from sm_member_sdk.identity import Identity


def test_canonical_v02_format() -> None:
    assert signing.canonical_string("BODY", "alice", "1700000000") == "BODY:alice:1700000000"


def test_canonical_v03_format_uppercases_method() -> None:
    out = signing.canonical_string_v03("post", "/api/feedback", "BODY", "alice", "1700000000", "n1")
    assert out == "POST:/api/feedback:BODY:alice:1700000000:n1"


def test_compose_headers_v02_exact_set() -> None:
    h = signing.compose_headers("alice", "did:key:zABC", "1700000000", "SIG")
    assert h == {
        "X-Agent-ID": "alice",
        "X-Agent-DID-Key": "did:key:zABC",
        "X-Agent-Sig-Scheme": "ed25519",
        "X-Agent-Timestamp": "1700000000",
        "X-Agent-Signature": "SIG",
    }


def test_compose_headers_v03_adds_nonce_and_scheme() -> None:
    h = signing.compose_headers_v03("alice", "did:key:zABC", "1700000000", "n1", "SIG")
    assert h["X-Agent-Sig-Scheme"] == "ed25519+nonce"
    assert h["X-Agent-Nonce"] == "n1"


def test_sign_request_v02_signature_verifies() -> None:
    ident = Identity.generate("alice")
    h = signing.sign_request(ident, "BODY", "1700000000")
    canonical = signing.canonical_string("BODY", "alice", "1700000000").encode()
    assert crypto.verify(ident.public_key, _sig(h), canonical)
    assert h["X-Agent-Sig-Scheme"] == "ed25519"


def test_sign_request_v03_signature_verifies() -> None:
    ident = Identity.generate("alice")
    h = signing.sign_request(
        ident, "BODY", "1700000000", method="POST", url_path="/api/feedback", nonce="n1"
    )
    canonical = signing.canonical_string_v03(
        "POST", "/api/feedback", "BODY", "alice", "1700000000", "n1"
    ).encode()
    assert crypto.verify(ident.public_key, _sig(h), canonical)
    assert h["X-Agent-Sig-Scheme"] == "ed25519+nonce"


def test_sign_request_partial_v03_args_rejected() -> None:
    ident = Identity.generate("alice")
    with pytest.raises(ValueError):
        signing.sign_request(ident, "BODY", "1700000000", method="POST")


def _sig(headers: dict[str, str]) -> bytes:
    import base64

    return base64.b64decode(headers["X-Agent-Signature"])
