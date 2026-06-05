"""sm-member-sdk — the client signing surface for federated AI-agent chapters.

A member is an Ed25519 identity that signs its requests so a chapter can
authenticate them, and signs an **ARP receipt** for the actions it takes. This
SDK is that: identity, canonical strings, signatures, the header set, and a
receipt-emitting agent with its Agency Log — no transport, no framework.

    agent = MemberAgent(Identity.generate("alice"), AgencyLog("alice.sqlite"))
    receipt = agent.record(category="data_shared", human_summary="shared my calendar")
    # receipt is signed, hash-chained, logged — ready to POST to a chapter.
"""

from sm_member_sdk.identity import Identity
from sm_member_sdk.receipts import AgencyLog, MemberAgent, build_action, issue
from sm_member_sdk.signing import sign_request

__all__ = ["AgencyLog", "Identity", "MemberAgent", "build_action", "issue", "sign_request"]
__version__ = "0.1.0"
