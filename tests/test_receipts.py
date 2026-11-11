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

from sm_agent import AgencyLog, Identity, MemberAgent, build_action, issue


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


def test_chain_resumes_from_true_head_when_issued_at_ties(
    alice: Identity, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Three receipts in one second share an ``issued_at``; the log's ordering has
    no tiebreaker, so a restart must find the head by the chain, not by storage
    order. Storage order is made to disagree with chain order here the way it
    does in production: the genesis is re-appended (the log's idempotent
    re-append, e.g. after a re-sync), which gives it the newest rowid."""
    import sm_arp.receipts

    monkeypatch.setattr(sm_arp.receipts, "now_iso", lambda: "2026-11-11T12:00:00Z")
    log = AgencyLog(tmp_path / "alice.sqlite")
    agent = MemberAgent(alice, log)
    chain = [agent.record(category="vote_cast", human_summary=f"r{i}") for i in range(3)]
    assert len({r["issued_at"] for r in chain}) == 1
    log.append(chain[0])
    assert log.count() == 3
    monkeypatch.undo()

    resumed = MemberAgent(alice, log)
    fourth = resumed.record(category="vote_cast", human_summary="r4")
    assert fourth["previous_receipt_hash"] == chain_link(chain[-1])
    assert verify_receipt(fourth, prior=chain[-1], check_chain=True).ok
    # The whole log is one unbroken chain: every link but the genesis has exactly one predecessor.
    receipts = {chain_link(r): r for r in (*chain, fourth)}
    for r in receipts.values():
        prev = r.get("previous_receipt_hash")
        assert prev is None or prev in receipts


def test_chain_head_widens_its_window_past_one_second_of_receipts(
    alice: Identity, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sm_arp.receipts

    from sm_agent.receipts import chain_head

    monkeypatch.setattr(sm_arp.receipts, "now_iso", lambda: "2026-11-11T12:00:00Z")
    log = AgencyLog(tmp_path / "alice.sqlite")
    agent = MemberAgent(alice, log)
    last = [agent.record(category="vote_cast", human_summary=f"r{i}") for i in range(40)][-1]
    assert chain_head(log, alice.did_key) == last
    assert chain_head(log, "did:key:z6MkNobody") is None


def test_forked_log_is_refused_on_resume(alice: Identity, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two receipts both claiming the same predecessor is a fork — picking one
    silently would extend it, so resume refuses."""
    import sm_arp.receipts

    monkeypatch.setattr(sm_arp.receipts, "now_iso", lambda: "2026-11-11T12:00:00Z")
    log = AgencyLog(tmp_path / "alice.sqlite")
    genesis = MemberAgent(alice, log).record(category="vote_cast", human_summary="g")
    for i in range(2):
        log.append(
            issue(
                alice,
                action=build_action(category="vote_cast", human_summary=f"fork{i}"),
                previous_receipt_hash=chain_link(genesis),
            )
        )
    with pytest.raises(ValueError, match="forked"):
        MemberAgent(alice, log)


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


def test_sdk_verifies_a_counterpartys_receipt(alice: Identity) -> None:
    """The SDK is also a consumer: it verifies receipts presented by others
    before trusting them, via its own verify_receipt surface."""
    from sm_agent import verify_receipt as sdk_verify

    bob = Identity.generate("bob")
    r = issue(bob, action=build_action(category="message_sent", human_summary="from bob"))
    assert sdk_verify(r).ok
    r["signature"] = "AAAAAAAA"
    assert not sdk_verify(r).ok
