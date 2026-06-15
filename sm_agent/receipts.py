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
__all__ = ["AgencyLog", "MemberAgent", "build_action", "issue", "verify_receipt"]


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
        prior = log.list_for_issuer(identity.did_key, limit=1)
        self._last_link: str | None = chain_link(prior[0]) if prior else None

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
