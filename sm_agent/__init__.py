"""sm-org-agent — the client signing surface for federated AI-agent servers.

A member is an Ed25519 identity that signs its requests so a server can
authenticate them, and signs an **ARP receipt** for the actions it takes. This
SDK is that: identity, canonical strings, signatures, the header set, and a
receipt-emitting agent with its Agency Log — no transport, no framework.

    agent = MemberAgent(Identity.generate("alice"), AgencyLog("alice.sqlite"))
    receipt = agent.record(category="data_shared", human_summary="shared my calendar")
    # receipt is signed, hash-chained, logged — ready to POST to a server.
"""

from sm_agent.identity import Identity
from sm_agent.receipts import AgencyLog, MemberAgent, build_action, issue, verify_receipt
from sm_agent.signing import make_nonce, now_ts, sign_request

__all__ = [
    "AgencyLog",
    "Identity",
    "MemberAgent",
    "build_action",
    "issue",
    "make_nonce",
    "now_ts",
    "sign_request",
    "verify_receipt",
]
__version__ = "0.1.0"
