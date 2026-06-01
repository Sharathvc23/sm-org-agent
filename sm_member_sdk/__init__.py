"""sm-member-sdk — the client signing surface for federated AI-agent chapters.

A member is an Ed25519 identity that signs its requests so a chapter can
authenticate them. This SDK is that and only that: identity, canonical strings,
signatures, and the header set — no transport, no framework.
"""

from sm_member_sdk.identity import Identity
from sm_member_sdk.signing import sign_request

__all__ = ["Identity", "sign_request"]
__version__ = "0.1.0"
