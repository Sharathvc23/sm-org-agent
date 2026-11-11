"""Identity — keypair + did:key ergonomics."""

from __future__ import annotations

import base64

import pytest

from sm_agent import crypto
from sm_agent.identity import Identity


def test_generate_is_internally_consistent() -> None:
    ident = Identity.generate("alice")
    assert ident.agent_id == "alice"
    assert crypto.derive_did_key(ident.public_key) == ident.did_key
    assert crypto.parse_did_key(ident.did_key) == ident.public_key


def test_from_seed_round_trips() -> None:
    ident = Identity.generate("alice")
    restored = Identity.from_seed("alice", ident.private_key)
    assert restored.public_key == ident.public_key
    assert restored.did_key == ident.did_key


def test_b64_properties() -> None:
    ident = Identity.generate("alice")
    assert base64.b64decode(ident.private_key_b64) == ident.private_key
    assert base64.b64decode(ident.public_key_b64) == ident.public_key


@pytest.mark.parametrize("bad_len", [16, 31, 33])
def test_wrong_key_length_rejected(bad_len: int) -> None:
    with pytest.raises(ValueError):
        Identity.from_seed("alice", b"\x00" * bad_len)


def test_mismatched_public_key_rejected() -> None:
    alice, bob = Identity.generate("alice"), Identity.generate("bob")
    with pytest.raises(ValueError, match="public key does not match"):
        Identity("alice", alice.private_key, bob.public_key, bob.did_key)
    with pytest.raises(ValueError, match="public key does not match"):
        Identity("alice", alice.private_key, bob.public_key, alice.did_key)


def test_mismatched_did_key_rejected() -> None:
    alice, bob = Identity.generate("alice"), Identity.generate("bob")
    with pytest.raises(ValueError, match="did_key"):
        Identity("alice", alice.private_key, alice.public_key, bob.did_key)


def test_consistent_parts_accepted() -> None:
    alice = Identity.generate("alice")
    rebuilt = Identity("alice", alice.private_key, alice.public_key, alice.did_key)
    assert rebuilt == alice


def test_wrong_public_key_length_rejected() -> None:
    alice = Identity.generate("alice")
    with pytest.raises(ValueError):
        Identity("alice", alice.private_key, alice.public_key[:31], alice.did_key)
