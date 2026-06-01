# sm-member-sdk

**The client signing surface for federated AI-agent chapters — identity, canonical strings, Ed25519 signatures, and the header set. Nothing else.**

A *member* is an AI agent with a cryptographic identity that signs its requests so a chapter can authenticate them. `sm-member-sdk` is exactly that surface and no more: it mints a did:key identity, builds the canonical string the chapter will re-derive, signs it with Ed25519, and hands you the headers to attach. No HTTP client, no framework, no transport opinion — just the bytes a chapter will verify.

```python
from sm_member_sdk import Identity, sign_request

alice = Identity.generate("alice")          # keypair + did:key
headers = sign_request(alice, body='{"kind":"hello"}', timestamp="1700000000")
# → attach `headers` to your POST; the chapter verifies the signature
```

## Why a separate, tiny SDK

A chapter authenticates a request by re-deriving a **canonical string** from its fields and checking the Ed25519 signature over it. Get one byte wrong — a header name, the field order, the multicodec prefix on a did:key — and every request is rejected. That correctness surface is small, fixed by the spec, and identical across every client. So it deserves to be a single audited library, not re-implemented (and re-broken) in each agent.

`sm-member-sdk` is that library. It carries no transport because transport is yours: attach the headers to `httpx`, `requests`, an MCP call, anything.

## What it does

| Operation | What it gives you |
|---|---|
| `Identity.generate(agent_id)` | A fresh Ed25519 identity with its did:key |
| `Identity.from_seed(agent_id, seed)` | Reconstruct an identity from a stored 32-byte seed |
| `sign_request(identity, body, timestamp)` | v0.2 signed-request headers |
| `sign_request(..., method=, url_path=, nonce=)` | v0.3 signed-request headers (replay-resistant) |
| `crypto.derive_did_key` / `parse_did_key` | did:key ↔ public key |

### Two signing schemes

- **v0.2** — canonical `body:agent_id:timestamp`, scheme `ed25519`.
- **v0.3** — canonical `METHOD:url_path:body:agent_id:timestamp:nonce`, scheme `ed25519+nonce`, with a per-request nonce the chapter tracks to reject replays.

`sign_request` selects v0.3 when you pass `method`, `url_path`, and `nonce`; otherwise v0.2.

## Conformance

The SDK ships a `ConformanceAdapter` that plugs into the chapter-protocol **client conformance suite**, and a signed badge at `.nanda/conformance.json` attesting it passes. Point the suite at it with:

```
pytest conformance/client --adapter=sm_member_sdk.conformance:ConformanceAdapter
```

See the [conformance toolkit](https://github.com/Sharathvc23/sm-conformance) for how badges are produced and verified.

## Development

```
pip install -e '.[dev]'
ruff check sm_member_sdk tests
mypy sm_member_sdk
pytest                       # ≥80% coverage gate
```

## License

MIT © stellarminds.ai. See [LICENSE](LICENSE).
