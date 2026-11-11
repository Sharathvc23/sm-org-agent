"""Signed-request construction — the client half of the protocol wire.

A server authenticates a request by re-deriving a *canonical string* from its
fields and verifying the Ed25519 signature over it. The client's only job is to
build that exact string, sign it, and attach the agreed headers. Two schemes:

- **v0.2** — ``body:agent_id:timestamp`` with ``X-Agent-Sig-Scheme: ed25519``.
- **v0.3** — ``METHOD:url_path:body:agent_id:timestamp:nonce`` with a per-request
  nonce and ``ed25519+nonce`` (replay-resistant).

Get one byte wrong here and the server rejects the signature, so these formats
are fixed by the spec, not a convenience.

Two layers live here, on purpose:

- ``canonical_string*`` / ``compose_headers*`` are *pure formatters*: strings in,
  the exact wire bytes out, no validation. The conformance suite pins them with
  placeholder values, so they must accept whatever they are handed.
- :func:`sign_request` is the *composer* a client calls. It mints the values a
  caller did not supply (:func:`make_nonce`, :func:`now_ts`) and refuses values
  that are not what the spec says the headers carry, so a malformed nonce or
  timestamp fails here, at the client, rather than as a 401 from the server.
"""

from __future__ import annotations

import base64
import binascii
import secrets
import time

from sm_agent import crypto
from sm_agent.identity import Identity

NONCE_BYTES = 32
"""spec/0.3/signing.md: ``X-Agent-Nonce`` is 32 random bytes, standard base64 (44 chars)."""


def make_nonce() -> str:
    """A fresh v0.3 nonce: 32 random bytes as standard base64 with ``=`` padding."""
    return base64.b64encode(secrets.token_bytes(NONCE_BYTES)).decode()


def now_ts() -> str:
    """The current time as the string of integer Unix seconds ``X-Agent-Timestamp`` carries."""
    return str(int(time.time()))


def validate_nonce(nonce: str) -> str:
    """Return ``nonce`` iff it is the canonical standard-base64 encoding of 32 bytes."""
    try:
        raw = base64.b64decode(nonce, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"nonce must be standard base64 with padding, got {nonce!r}") from exc
    if len(raw) != NONCE_BYTES:
        raise ValueError(f"nonce must encode {NONCE_BYTES} bytes, got {len(raw)}")
    if base64.b64encode(raw).decode() != nonce:
        raise ValueError(f"nonce is not canonically encoded: {nonce!r}")
    return nonce


def validate_timestamp(timestamp: str) -> str:
    """Return ``timestamp`` iff it is a string of ASCII decimal digits (integer Unix seconds)."""
    if not (timestamp.isascii() and timestamp.isdigit()):
        raise ValueError(f"timestamp must be integer Unix seconds as a string, got {timestamp!r}")
    return timestamp


def canonical_string(body: str, agent_id: str, timestamp: str) -> str:
    """The exact string an Ed25519 v0.2 signature is computed over."""
    return f"{body}:{agent_id}:{timestamp}"


def canonical_string_v03(
    method: str, url_path: str, body: str, agent_id: str, timestamp: str, nonce: str
) -> str:
    """The exact string an Ed25519 v0.3 signature is computed over."""
    return f"{method.upper()}:{url_path}:{body}:{agent_id}:{timestamp}:{nonce}"


def compose_headers(agent_id: str, did_key: str, timestamp: str, signature_b64: str) -> dict[str, str]:
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
    timestamp: str | None = None,
    *,
    method: str | None = None,
    url_path: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Build the signed-request headers for ``body`` from ``identity``.

    Supplying ``method`` and ``url_path`` selects the v0.3 scheme; omitting both
    selects v0.2. ``timestamp`` defaults to :func:`now_ts` and, for v0.3,
    ``nonce`` defaults to :func:`make_nonce`. Supplied values are validated
    against what the spec says the headers carry (integer-seconds timestamp;
    32-byte standard-base64 nonce) and rejected with ``ValueError`` otherwise.
    Returns the header dict ready to attach to a request — the one call a
    client makes per request.
    """
    ts = validate_timestamp(now_ts() if timestamp is None else timestamp)
    if method is not None and url_path is not None:
        n = validate_nonce(make_nonce() if nonce is None else nonce)
        canonical = canonical_string_v03(method, url_path, body, identity.agent_id, ts, n)
        sig = crypto.ed25519_sign_message(canonical, identity.private_key_b64)
        return compose_headers_v03(identity.agent_id, identity.did_key, ts, n, sig)
    if method is not None or url_path is not None or nonce is not None:
        raise ValueError("v0.3 signing requires both method and url_path (nonce is optional)")
    canonical = canonical_string(body, identity.agent_id, ts)
    sig = crypto.ed25519_sign_message(canonical, identity.private_key_b64)
    return compose_headers(identity.agent_id, identity.did_key, ts, sig)
