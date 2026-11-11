"""Canonical strings, header sets, and the one-call signer."""

from __future__ import annotations

import pytest

from sm_agent import crypto, signing
from sm_agent.identity import Identity


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
    nonce = signing.make_nonce()
    h = signing.sign_request(
        ident, "BODY", "1700000000", method="POST", url_path="/api/feedback", nonce=nonce
    )
    canonical = signing.canonical_string_v03(
        "POST", "/api/feedback", "BODY", "alice", "1700000000", nonce
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


# ── nonce / timestamp helpers and the composer's defaults + validation ─────────


def test_make_nonce_is_32_random_bytes_standard_base64() -> None:
    import base64

    a, b = signing.make_nonce(), signing.make_nonce()
    assert a != b
    assert len(a) == 44 and a.endswith("=")
    assert len(base64.b64decode(a, validate=True)) == 32
    assert signing.validate_nonce(a) == a


def test_now_ts_is_integer_seconds_string() -> None:
    import time

    before = int(time.time())
    ts = signing.now_ts()
    assert ts.isdigit() and before <= int(ts) <= before + 1
    assert signing.validate_timestamp(ts) == ts


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "test-nonce",  # not base64 alphabet
        "AAAA",  # 3 bytes
        "A" * 44,  # 44 chars but no padding → 33 bytes
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # 43 chars, missing the '=' padding
        "-_" + "A" * 41 + "=",  # urlsafe alphabet
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=",  # 32 bytes but non-canonical trailing bits
    ],
)
def test_validate_nonce_rejects_non_spec_values(bad: str) -> None:
    with pytest.raises(ValueError):
        signing.validate_nonce(bad)


@pytest.mark.parametrize(
    "bad", ["", "17e9", "1700000000.5", "-1", "+1700000000", " 1700000000", "1700000000Z", "١٢٣"]
)
def test_validate_timestamp_rejects_non_integer_strings(bad: str) -> None:
    with pytest.raises(ValueError):
        signing.validate_timestamp(bad)


def test_sign_request_v03_defaults_nonce_and_timestamp() -> None:
    ident = Identity.generate("alice")
    h = signing.sign_request(ident, "BODY", method="POST", url_path="/api/feedback")
    assert h["X-Agent-Sig-Scheme"] == "ed25519+nonce"
    assert signing.validate_nonce(h["X-Agent-Nonce"]) == h["X-Agent-Nonce"]
    assert signing.validate_timestamp(h["X-Agent-Timestamp"]) == h["X-Agent-Timestamp"]
    canonical = signing.canonical_string_v03(
        "POST", "/api/feedback", "BODY", "alice", h["X-Agent-Timestamp"], h["X-Agent-Nonce"]
    ).encode()
    assert crypto.verify(ident.public_key, _sig(h), canonical)
    # Two calls never reuse a nonce.
    again = signing.sign_request(ident, "BODY", method="POST", url_path="/api/feedback")
    assert again["X-Agent-Nonce"] != h["X-Agent-Nonce"]


def test_sign_request_v02_defaults_timestamp() -> None:
    ident = Identity.generate("alice")
    h = signing.sign_request(ident, "BODY")
    assert h["X-Agent-Sig-Scheme"] == "ed25519"
    assert signing.validate_timestamp(h["X-Agent-Timestamp"]) == h["X-Agent-Timestamp"]


def test_sign_request_accepts_spec_shaped_supplied_values() -> None:
    ident = Identity.generate("alice")
    nonce = signing.make_nonce()
    h = signing.sign_request(ident, "BODY", "1700000000", method="POST", url_path="/x", nonce=nonce)
    assert h["X-Agent-Nonce"] == nonce and h["X-Agent-Timestamp"] == "1700000000"


def test_sign_request_rejects_malformed_supplied_values() -> None:
    ident = Identity.generate("alice")
    with pytest.raises(ValueError, match="nonce"):
        signing.sign_request(ident, "BODY", "1700000000", method="POST", url_path="/x", nonce="n1")
    with pytest.raises(ValueError, match="timestamp"):
        signing.sign_request(ident, "BODY", "1700000000.0", method="POST", url_path="/x")
    with pytest.raises(ValueError, match="timestamp"):
        signing.sign_request(ident, "BODY", "soon")


def test_sign_request_nonce_without_v03_fields_rejected() -> None:
    ident = Identity.generate("alice")
    with pytest.raises(ValueError):
        signing.sign_request(ident, "BODY", "1700000000", nonce=signing.make_nonce())


def test_compose_headers_v03_stays_a_pure_formatter() -> None:
    """The conformance suite pins the header set with placeholder values; the
    formatter must not validate them — that is sign_request's job."""
    h = signing.compose_headers_v03("a", "did:key:zX", "1", "test-nonce", "S")
    assert h["X-Agent-Nonce"] == "test-nonce"
