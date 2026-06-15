# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- **Server rename (Tier 4, brand only — wire frozen).** Prose and docstrings now use *server* vocabulary for the host the client talks to (was "chapter"). No code symbols, env vars, or wire formats changed: the canonical-string formats, header set, did:key derivation, and the `chapter_id` field remain frozen by the protocol. "member" is unchanged — it stays the role word. Conformance stays green.

### Added
- **ARP receipts.** The SDK is now ARP-native via the `sm_arp` consumable library:
  - `MemberAgent(identity, AgencyLog(...))` — `.record(category, human_summary, ...)` issues a signed receipt, hash-chains it to the agent's previous one (§6.4), appends to the Agency Log (§10.1), and returns it. Emission is the default, not an add-on; the chain resumes from an existing log across restarts.
  - `issue(identity, action=...)` — one-shot signed receipt bound to an identity; `principal_did` defaults to the member's own DID, overridable for delegated action.
  - `verify_receipt` — the consumer surface: verify a counterparty's receipt before trusting it.
- **Signed ARP conformance badge** at `.nanda/arp-conformance.json`, generated mechanically by `scripts/gen_arp_badge.py` (the canonical receipt vectors run through the SDK's `verify_receipt`).

`did:key` derivation is byte-identical to `sm_arp`, so receipts are attributed to the member's DID.

## [0.1.0] — 2026-06-01

Initial public release.

### Added
- `Identity` — Ed25519 keypair plus its derived did:key; `generate` and `from_seed`.
- `crypto` — did:key derivation/parsing, keypair generation, Ed25519 sign/verify.
- `signing` — v0.2 and v0.3 canonical strings, header sets, and the `sign_request` one-call signer.
- `ConformanceAdapter` — plugs the SDK into the server-protocol client conformance suite.
- Signed conformance badge at `.nanda/conformance.json`.
