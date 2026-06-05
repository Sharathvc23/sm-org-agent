"""ARP receipt emission — the member's default Agency Log behaviour.

A member issues a signed receipt for each action, hash-chained to the previous
one, persisted to its Agency Log. The receipt envelope is `sm_arp`'s; these
tests prove the SDK binds it correctly to the member's identity and chains it.

Prosecution-grade: identity binding, chain continuity + the hostile break,
resume-from-log, principal delegation, and tamper rejection.
"""

from __future__ import annotations

import pytest
from sm_arp import chain_link, verify_receipt

from sm_member_sdk import AgencyLog, Identity, MemberAgent, build_action, issue


@pytest.fixture
def alice() -> Identity:
    return Identity.generate("alice")


def _agent(identity: Identity, tmp_path) -> MemberAgent:
    return MemberAgent(identity, AgencyLog(tmp_path / f"{identity.agent_id}.sqlite"))


# ── identity binding ───────────────────────────────────────────────


def test_issued_receipt_is_attributed_to_member(alice: Identity) -> None:
    r = issue(alice, action=build_action(category="data_shared", human_summary="hi"))
    assert r["issuer_did"] == alice.did_key
    assert r["principal_did"] == alice.did_key  # acting for itself by default
    assert verify_receipt(r).ok


def test_principal_can_be_delegated(alice: Identity) -> None:
    principal = "did:key:z6MkOwnerOfTheAction000000000000000000000000000"
    r = issue(
        alice,
        action=build_action(category="purchase", human_summary="bought on behalf"),
        principal_did=principal,
    )
    assert r["issuer_did"] == alice.did_key and r["principal_did"] == principal
    assert verify_receipt(r).ok


# ── default emission + chain ───────────────────────────────────────


def test_record_emits_logs_and_verifies(alice: Identity, tmp_path) -> None:
    agent = _agent(alice, tmp_path)
    r = agent.record(category="message_sent", human_summary="said hello")
    assert verify_receipt(r).ok
    assert agent.log.count() == 1
    assert agent.log.list_for_issuer(alice.did_key)[0]["receipt_id"] == r["receipt_id"]


def test_records_form_a_verifiable_chain(alice: Identity, tmp_path) -> None:
    agent = _agent(alice, tmp_path)
    first = agent.record(category="message_sent", human_summary="one")
    second = agent.record(category="message_sent", human_summary="two")
    assert "previous_receipt_hash" not in first  # genesis
    assert second["previous_receipt_hash"] == chain_link(first)
    assert verify_receipt(second, prior=first, check_chain=True).ok
    assert agent.log.count() == 2


def test_chain_resumes_from_existing_log(alice: Identity, tmp_path) -> None:
    log = AgencyLog(tmp_path / "alice.sqlite")
    first = MemberAgent(alice, log).record(category="vote_cast", human_summary="r1")
    # A fresh agent over the same log must continue the chain, not fork a genesis.
    second = MemberAgent(alice, log).record(category="vote_cast", human_summary="r2")
    assert second["previous_receipt_hash"] == chain_link(first)
    assert verify_receipt(second, prior=first, check_chain=True).ok


# ── adversarial ────────────────────────────────────────────────────


def test_a_forged_predecessor_breaks_the_chain(alice: Identity, tmp_path) -> None:
    agent = _agent(alice, tmp_path)
    genesis = agent.record(category="message_sent", human_summary="one")
    second = agent.record(category="message_sent", human_summary="two")
    # Verified against the WRONG prior (genesis re-read but claiming a bad link).
    impostor = dict(genesis)
    impostor["receipt_id"] = "00000000-0000-4000-8000-000000000000"
    assert verify_receipt(second, prior=impostor, check_chain=True).stage == "hash_chain"


def test_tampered_logged_receipt_fails_verification(alice: Identity, tmp_path) -> None:
    agent = _agent(alice, tmp_path)
    r = agent.record(category="data_shared", human_summary="original")
    r["action"]["human_summary"] = "rewritten"
    assert not verify_receipt(r).ok
