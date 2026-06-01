"""Identity — keypair + did:key ergonomics."""

from __future__ import annotations

import base64

import pytest

from sm_member_sdk import crypto
from sm_member_sdk.identity import Identity


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
