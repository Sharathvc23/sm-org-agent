"""Ed25519 + did:key primitives."""

from __future__ import annotations

import base64

import pytest

from sm_agent import crypto


def test_keypair_and_did_round_trip() -> None:
    priv, pub = crypto.generate_keypair()
    assert len(priv) == 32 and len(pub) == 32
    did = crypto.derive_did_key(pub)
    assert did.startswith("did:key:z")
    assert crypto.parse_did_key(did) == pub


def test_build_did_key_matches_raw() -> None:
    _, pub = crypto.generate_keypair()
    assert crypto.build_did_key(base64.b64encode(pub).decode()) == crypto.derive_did_key(pub)


def test_derive_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        crypto.derive_did_key(b"\x00" * 31)


@pytest.mark.parametrize("bad", ["", "did:web:example.com", "did:key:zStillWrong"])
def test_parse_rejects_non_did_key(bad: str) -> None:
    with pytest.raises(ValueError):
        crypto.parse_did_key(bad)


def test_sign_and_verify() -> None:
    priv, pub = crypto.generate_keypair()
    sig_b64 = crypto.ed25519_sign_message("hello:alice:123", base64.b64encode(priv).decode())
    assert crypto.verify(pub, base64.b64decode(sig_b64), b"hello:alice:123") is True
    assert crypto.verify(pub, base64.b64decode(sig_b64), b"tampered") is False


def test_sign_rejects_wrong_seed_length() -> None:
    with pytest.raises(ValueError):
        crypto.ed25519_sign_message("x", base64.b64encode(b"\x00" * 31).decode())
