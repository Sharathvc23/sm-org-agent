# sm-agent: The Client Signing Surface for Federated AI Agents

## Abstract

For an AI agent to participate in a federated community, every request it sends must be provably from *it*. The mechanism is unglamorous and unforgiving: a cryptographic identity, a canonical string re-derived identically on both ends, and an Ed25519 signature over it. The surface is small and fixed by the protocol — and precisely because it is small and fixed, re-implementing it in each agent is how interoperability quietly breaks. `sm-agent` is that surface extracted once, correctly: did:key identity, canonical-string construction, signing, and the header set, with no transport and no framework attached.

## 1. Problem

A server authenticates an incoming request by reconstructing the exact string the client claims to have signed and verifying the signature against the presented public key. Every field matters: the order of `body:agent_id:timestamp`, the casing of `X-Agent-Sig-Scheme`, the `0xed01` multicodec prefix that turns a raw public key into a did:key. A single deviation is not a degraded experience — it is a `401`. The whole request is rejected.

When this logic is copy-pasted into every agent, three failures follow. Clients drift from the spec in small ways and only discover it against a live server. A client that *thinks* it is compatible cannot prove it. And a protocol upgrade (v0.2 → v0.3) has to be chased through every copy. The surface that makes federation possible becomes the surface that makes it fragile.

## 2. The Client Primitive

`sm-agent` is the client half of the wire, isolated from everything around it:

```
        your agent · transport · product        ← you write this
   ┌──────────────────────────────────────┐
   │            sm-agent              │     ← the client signing surface
   │  Identity · canonical · sign · headers│
   └──────────────────────────────────────┘
              Ed25519 · did:key                   ← the cryptographic floor
```

It depends only on `cryptography` and `base58`. It returns headers, not requests — you attach them to whatever transport you already use. The library has one job and is auditable in an afternoon.

## 3. Design Axioms

### 3.1 Build the bytes the server will verify, exactly

The canonical string and header set are not conveniences; they are the contract. The SDK produces them to the letter of the spec.

**Consequence:** the SDK is byte-for-byte equivalent to the reference implementation. The conformance suite asserts this against shared vectors — a deviation fails before any server is involved.

### 3.2 Transport is not our concern

Signing is pure: identity and request fields in, headers out. No sockets, no retries, no HTTP library.

**Consequence:** the SDK composes with any transport (`httpx`, `requests`, MCP, A2A) and stays tiny. The agent owns the network; the SDK owns the signature.

### 3.3 Two schemes, one call

v0.2 (`ed25519`) and v0.3 (`ed25519+nonce`, replay-resistant) share an identity and a did:key. `sign_request` selects the scheme from its arguments.

**Consequence:** upgrading a client from v0.2 to v0.3 is passing three more arguments, not rewriting its auth.

### 3.4 Conformance is mechanical

The SDK exposes its operations to a conformance adapter and ships a signed badge attesting it passes the client suite.

**Consequence:** "this client speaks the protocol" becomes a verifiable artifact, not a claim — exactly what a server or registry can demand before trusting a signature.

### 3.5 A member's actions leave receipts

Signing a request proves a member *spoke*. It does not record what it *did*. So a member also issues an [ARP](https://github.com/Sharathvc23/sm-arp) receipt for each action — the same Ed25519 identity, now signing a JCS-canonical, hash-chained envelope — and keeps them in an **Agency Log**. The receipt envelope is the one canonical `sm_arp` library, shared with the server, so `did:key` derivation and canonical bytes are byte-identical on both ends. A member verifies its counterparties' receipts through the same library before trusting them.

**Consequence:** the member is a first-class participant in a verifiable history, not just an authenticated caller. Its actions are attributable to its DID without a trusted intermediary, and it ships a second signed badge attesting it passes the ARP receipt suite — run mechanically through its own `verify_receipt` surface.

## 4. Where This Fits

`sm-agent` is the client end of a protocol whose server end is a server. A member mints an identity here, signs its requests *and its receipts* here, and sends them to a server that verifies both. The two were built and conformance-tested independently, against the same shared vectors and the same `sm_arp` receipt library — which is the point: neither has to trust the other's implementation, only the shared spec.

## 5. NANDA Alignment

[Project NANDA](https://projectnanda.org) frames the open Internet of Agents around four pillars, of which **CA** (decentralized identity) is the one a member embodies: a self-custodied did:key that signs its own requests. `sm-agent` is the conformant client expression of that pillar — the smallest correct way for an agent to *be* an identity on the wire.

## 6. Related Packages

| Package | Role |
|---|---|
| [`sm-conformance`](https://github.com/Sharathvc23/sm-conformance) | The conformance-badge toolkit — produces and verifies the signed badge this SDK ships |
| [`sm-arp`](https://github.com/Sharathvc23/sm-arp) | Agency Receipt Protocol — per-action signed receipts an agent emits above this signing layer |

---

*Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. [Stellarminds.ai](https://stellarminds.ai)*
