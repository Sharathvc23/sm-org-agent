"""ARP receipts — a member emits a signed receipt for the actions it takes.

Emitting receipts is a default capability of the SDK, not an add-on: the same
Ed25519 identity that signs requests signs receipts, each is hash-chained to the
member's previous one (ARP §6.4), and appended to its **Agency Log** (§10.1).
The receipt envelope itself — build / sign / verify / canonical-bytes / chain —
is owned by `sm_arp`, the one canonical implementation shared across every
runtime; this module binds it to the SDK's :class:`Identity`.

No transport here (true to the SDK's charter): :meth:`MemberAgent.record`
returns a ready-to-POST receipt dict; *sending* it to a server's
``/api/receipts`` is the caller's concern.
"""

from __future__ import annotations

from typing import Any

from sm_arp import AgencyLog, build_action, chain_link, issue_receipt, verify_receipt
from sm_arp import Identity as _ArpIdentity

from sm_agent.identity import Identity

# A member is both a producer (issue / MemberAgent) and a consumer: it verifies
# the receipts its counterparties present before trusting them. `verify_receipt`
# is that consumer surface — the same canonical verifier every runtime shares.
__all__ = ["AgencyLog", "MemberAgent", "build_action", "chain_head", "issue", "verify_receipt"]


def _as_arp(identity: Identity) -> _ArpIdentity:
    """The SDK Identity and sm_arp Identity derive the *same* did:key from a
    seed, so a receipt signed here is attributed to ``identity.did_key``."""
    return _ArpIdentity.from_seed(identity.private_key)


def issue(
    identity: Identity,
    *,
    action: dict[str, Any],
    principal_did: str | None = None,
    previous_receipt_hash: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Build and sign one ARP receipt as ``identity``.

    ``principal_did`` defaults to the member's own DID — an agent acting for
    itself. Pass it explicitly when the agent acts on behalf of another
    principal under a delegated authority.
    """
    receipt: dict[str, Any] = issue_receipt(
        _as_arp(identity),
        principal_did=principal_did or identity.did_key,
        action=action,
        previous_receipt_hash=previous_receipt_hash,
        **kwargs,
    )
    return receipt


def chain_head(log: AgencyLog, issuer_did: str) -> dict[str, Any] | None:
    """The receipt at the head of ``issuer_did``'s hash chain in ``log``, or None.

    The log orders by ``issued_at``, which is second-resolution and carries no
    tiebreaker, so several receipts issued within one second come back in an
    order the store does not define. Taking ``list_for_issuer(limit=1)`` at face
    value could therefore resume from a receipt that already has a successor and
    fork the chain. The chain itself is the authority: among the receipts that
    share the newest ``issued_at``, the head is the one no other receipt links
    to as its ``previous_receipt_hash``.
    """
    limit = 16
    while True:
        recent: list[dict[str, Any]] = log.list_for_issuer(issuer_did, limit=limit)
        if not recent:
            return None
        newest = recent[0]["issued_at"]
        group = [r for r in recent if r["issued_at"] == newest]
        # The newest second is fully in view once the window reaches an older
        # receipt or the end of the log; otherwise widen it.
        if len(group) < len(recent) or len(recent) < limit:
            break
        limit *= 2
    linked = {r.get("previous_receipt_hash") for r in group}
    heads = [r for r in group if chain_link(r) not in linked]
    if len(heads) != 1:
        raise ValueError(
            f"receipt chain for {issuer_did} is forked: {len(heads)} unlinked receipts "
            f"issued at {newest} — refusing to pick one and extend the fork"
        )
    return heads[0]


class MemberAgent:
    """A member identity plus its Agency Log.

    :meth:`record` issues a receipt, chains it to this agent's previous one,
    appends it to the log, and returns it — so producing a receipt is the
    default outcome of taking an action, not a separate bookkeeping step.
    """

    def __init__(self, identity: Identity, log: AgencyLog) -> None:
        self.identity = identity
        self.log = log
        # Resume the chain from whatever this issuer last wrote, so a restarted
        # agent continues its hash chain rather than forking a new genesis.
        head = chain_head(log, identity.did_key)
        self._last_link: str | None = chain_link(head) if head else None

    def record(
        self,
        *,
        category: str,
        human_summary: str,
        principal_did: str | None = None,
        **action_kwargs: Any,
    ) -> dict[str, Any]:
        """Issue, chain, log, and return a receipt for one action."""
        action = build_action(category=category, human_summary=human_summary, **action_kwargs)
        receipt = issue(
            self.identity,
            action=action,
            principal_did=principal_did,
            previous_receipt_hash=self._last_link,
        )
        self.log.append(receipt)
        self._last_link = chain_link(receipt)
        return receipt
