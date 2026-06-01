"""Signed-request construction — the client half of the protocol wire.

A chapter authenticates a request by re-deriving a *canonical string* from its
fields and verifying the Ed25519 signature over it. The client's only job is to
build that exact string, sign it, and attach the agreed headers. Two schemes:

- **v0.2** — ``body:agent_id:timestamp`` with ``X-Agent-Sig-Scheme: ed25519``.
- **v0.3** — ``METHOD:url_path:body:agent_id:timestamp:nonce`` with a per-request
  nonce and ``ed25519+nonce`` (replay-resistant).

Get one byte wrong here and the chapter rejects the signature, so these formats
are fixed by the spec, not a convenience.
"""

from __future__ import annotations

from sm_member_sdk import crypto
from sm_member_sdk.identity import Identity


def canonical_string(body: str, agent_id: str, timestamp: str) -> str:
    """The exact string an Ed25519 v0.2 signature is computed over."""
    return f"{body}:{agent_id}:{timestamp}"


def canonical_string_v03(
    method: str, url_path: str, body: str, agent_id: str, timestamp: str, nonce: str
) -> str:
    """The exact string an Ed25519 v0.3 signature is computed over."""
    return f"{method.upper()}:{url_path}:{body}:{agent_id}:{timestamp}:{nonce}"


def compose_headers(
    agent_id: str, did_key: str, timestamp: str, signature_b64: str
) -> dict[str, str]:
    """The header set a v0.2 signed request carries."""
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-DID-Key": did_key,
        "X-Agent-Sig-Scheme": "ed25519",
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Signature": signature_b64,
    }


def compose_headers_v03(
    agent_id: str, did_key: str, timestamp: str, nonce: str, signature_b64: str
) -> dict[str, str]:
    """The header set a v0.3 signed request carries (adds the per-request nonce)."""
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-DID-Key": did_key,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": signature_b64,
    }


def sign_request(
    identity: Identity,
    body: str,
    timestamp: str,
    *,
    method: str | None = None,
    url_path: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Build the signed-request headers for ``body`` from ``identity``.

    Supplying ``method``, ``url_path``, and ``nonce`` selects the v0.3 scheme;
    omitting them selects v0.2. Returns the header dict ready to attach to a
    request — the one call a client makes per request.
    """
    if method is not None and url_path is not None and nonce is not None:
        canonical = canonical_string_v03(method, url_path, body, identity.agent_id, timestamp, nonce)
        sig = crypto.ed25519_sign_message(canonical, identity.private_key_b64)
        return compose_headers_v03(identity.agent_id, identity.did_key, timestamp, nonce, sig)
    if method is not None or url_path is not None or nonce is not None:
        raise ValueError("v0.3 signing requires all of method, url_path, and nonce")
    canonical = canonical_string(body, identity.agent_id, timestamp)
    sig = crypto.ed25519_sign_message(canonical, identity.private_key_b64)
    return compose_headers(identity.agent_id, identity.did_key, timestamp, sig)
