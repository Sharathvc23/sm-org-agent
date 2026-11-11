# sm-org-agent

**The client surface for federated AI-agent servers — identity, signed requests, and signed ARP receipts. No transport, no framework.**

A *member* is an AI agent with a cryptographic identity. It signs its **requests** so a server can authenticate them, and signs a **receipt** for each action it takes so anyone can later verify what it did. `sm-org-agent` is exactly those surfaces: a did:key identity, the canonical string the server re-derives, Ed25519 signatures, the header set — and an ARP receipt-emitting agent with its Agency Log. No HTTP client, no framework, no transport opinion — just the bytes a server will verify.

```python
from sm_agent import Identity, sign_request

alice = Identity.generate("alice")          # keypair + did:key
headers = sign_request(alice, body='{"kind":"hello"}', method="POST", url_path="/api/hello")
# → v0.3 headers with a fresh 32-byte nonce and the current timestamp minted for you;
#   attach `headers` to your POST and the server verifies the signature
```

## Why a separate, tiny SDK

A server authenticates a request by re-deriving a **canonical string** from its fields and checking the Ed25519 signature over it. Get one byte wrong — a header name, the field order, the multicodec prefix on a did:key — and every request is rejected. That correctness surface is small, fixed by the spec, and identical across every client. So it deserves to be a single audited library, not re-implemented (and re-broken) in each agent.

`sm-org-agent` is that library. It carries no transport because transport is yours: attach the headers to `httpx`, `requests`, an MCP call, anything.

## What it does

| Operation | What it gives you |
|---|---|
| `Identity.generate(agent_id)` | A fresh Ed25519 identity with its did:key |
| `Identity.from_seed(agent_id, seed)` | Reconstruct an identity from a stored 32-byte seed |
| `Identity(agent_id, seed, public_key, did_key)` | Direct construction; refuses parts that disagree with the seed |
| `sign_request(identity, body, method=, url_path=)` | v0.3 signed-request headers (replay-resistant) — the default to reach for |
| `sign_request(identity, body)` | v0.2 signed-request headers, for a server that advertises only v0.2 |
| `make_nonce()`, `now_ts()` | A spec-shaped `X-Agent-Nonce` / `X-Agent-Timestamp`, when you want to mint them yourself |
| `MemberAgent(identity, AgencyLog(...))` | A receipt-emitting agent + its Agency Log |
| `agent.record(category=, human_summary=, ...)` | Issue + hash-chain + log a signed ARP receipt |
| `issue(identity, action=, ...)` | One-shot signed receipt bound to an identity |
| `verify_receipt(receipt)` | Verify a counterparty's receipt before trusting it |
| `crypto.derive_did_key` / `parse_did_key` | did:key ↔ public key |

### Two signing schemes

- **v0.2** — canonical `body:agent_id:timestamp`, scheme `ed25519`.
- **v0.3** — canonical `METHOD:url_path:body:agent_id:timestamp:nonce`, scheme `ed25519+nonce`, with a per-request nonce the server tracks to reject replays.

`sign_request` selects v0.3 when you pass `method` and `url_path`; otherwise v0.2. `timestamp` defaults to `now_ts()` (integer Unix seconds as a string) and, for v0.3, `nonce` defaults to `make_nonce()` (32 random bytes, standard base64 with padding). Values you supply yourself are checked against those shapes and rejected with `ValueError` if they do not match, so a malformed header fails at the client rather than as a `401` from the server. The lower-level `canonical_string*` / `compose_headers*` functions are pure formatters and validate nothing — they are the surface the conformance suite pins byte-for-byte.

## Receipts (ARP)

Signing requests proves a member *spoke*; signing **receipts** proves what it *did*. A member emits an [Agency Receipt Protocol](https://github.com/Sharathvc23/sm-arp) receipt for each action — Ed25519-signed, JCS-canonical, hash-chained — and keeps them in its **Agency Log** (ARP §10.1). Emission is the default, not an add-on.

![ARP receipt flow](docs/figures/arp-receipt-flow.svg)

```python
from sm_agent import Identity, MemberAgent, AgencyLog

agent = MemberAgent(Identity.generate("alice"), AgencyLog("alice.sqlite"))
receipt = agent.record(category="data_shared", human_summary="shared my calendar")
# signed, hash-chained, logged — ready to POST to a server's /api/receipts
```

The same identity signs both requests and receipts; `did:key` derivation is byte-identical to the canonical [`sm_arp`](https://github.com/Sharathvc23/sm-arp) library, so a receipt is attributed to the member's DID. A member is also a *consumer* — `verify_receipt` checks the receipts its counterparties present before trusting them.

## Conformance

Be precise about what is asserted where, because the three things are easy to conflate:

- **This repo's own tests** (`pytest`, run by CI) pin the SDK against the spec formats with literal strings — canonical strings, header names and values, did:key derivation, signature round-trips, nonce/timestamp shapes, receipt chaining. They ship **no vector corpus**: there is no `vectors/` directory here, and nothing in `tests/` reads one.
- **The server-protocol client suite** lives in the umbrella repo ([nanda_chapter_protocol](https://github.com/Sharathvc23/nanda_chapter_protocol), `conformance/client/`) together with the JSON vectors it asserts. It reaches this SDK only through `sm_agent.conformance:ConformanceAdapter`, which delegates the six pure operations (did:key, v0.2/v0.3 canonical strings, sign, v0.2/v0.3 header sets) to the SDK's own functions, so the suite verifies the runtime, not a copy. Run it from an umbrella checkout with this package installed into the umbrella's environment:
  ```
  pip install -e /path/to/sm-org-agent
  pytest conformance/client/ --adapter=sm_agent.conformance:ConformanceAdapter
  ```
  At umbrella HEAD that is 51 tests; all pass. `.nanda/conformance.json` is the signed badge from such a run. Its `suite_digest` pins the corpus **at signing time** (47 vectors; 46 passed, 1 skipped), so it attests that run, not the suite as it stands today — re-run the command above for the current answer.
- **The ARP receipt suite** lives in [sm-arp](https://github.com/Sharathvc23/sm-arp) (`conformance/arp/`, vectors under `vectors/arp/0.1/`, not shipped in its wheel). `scripts/gen_arp_badge.py` runs those vectors through the SDK's `verify_receipt` surface and compares accept/reject against each vector's documented verdict; `.nanda/arp-conformance.json` is the signed result (22/22). It needs `ARP_REPO` pointing at a checkout and a signing key, so it is not part of this repo's CI.

Badges are minted and verified with the [conformance toolkit](https://github.com/Sharathvc23/sm-conformance); a badge certifies the suite digest it names and nothing broader.

## Development

```
pip install -e '.[dev]'
ruff check sm_agent tests
mypy sm_agent
pytest                       # ≥80% coverage gate
```

## License

MIT © stellarminds.ai. See [LICENSE](LICENSE).
