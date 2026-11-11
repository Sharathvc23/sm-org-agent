# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] — 2026-11-11

Audit 2026-11. Everything listed under "Unreleased" before this release had in
fact shipped in the `0.1.0` wheel; it is folded into this entry and the version
bumped so the CHANGELOG and the package agree again.

### Added
- **`make_nonce()` / `now_ts()`.** Spec-shaped `X-Agent-Nonce` (32 random bytes, standard base64 with padding) and `X-Agent-Timestamp` (integer Unix seconds as a string). Exported from `sm_agent`.
- **`sign_request` mints what you do not supply.** `timestamp` is now optional (defaults to `now_ts()`); for v0.3, `nonce` is optional (defaults to `make_nonce()`), so v0.3 is selected by `method` + `url_path` alone. Supplied values are validated — `validate_nonce` (decodes to 32 bytes, canonical encoding) and `validate_timestamp` (ASCII digits only) — and rejected with `ValueError`. The pure formatters `canonical_string*` / `compose_headers*` are unchanged and validate nothing; they are the surface the conformance suite pins.
- **`receipts.chain_head(log, issuer_did)`** — the receipt at the head of an issuer's chain, resolved by the chain rather than by storage order.
- **`crypto.public_key_from_seed`.**

### Fixed
- **`Identity(...)` refused when its parts disagree.** The public key is derived from the seed and compared; a supplied public key or `did_key` that does not match raises `ValueError`. Previously a mismatched pair was accepted silently and signed with one key while advertising another.
- **Chain resume could fork on restart.** `MemberAgent` resumed from `list_for_issuer(limit=1)`, which orders by second-resolution `issued_at` with no tiebreaker, so with several receipts in one second (or an older receipt re-appended, which the log's idempotent `INSERT OR REPLACE` gives the newest rowid) a restart could continue from a receipt that already had a successor. Resume now finds the head among the newest second's receipts as the one no other receipt links to; a log that already holds two unlinked heads is a fork and is refused with `ValueError` rather than silently extended.
- **README** no longer implies this repo ships or consumes a vector corpus. It now states what each of the three suites asserts and where its vectors live, and that the checked-in badge pins the suite at its signing time (47 vectors) while the umbrella suite at HEAD has 51.

### Changed
- **Server rename (Tier 4, brand only — wire frozen).** Prose and docstrings now use *server* vocabulary for the host the client talks to (was "chapter"). No code symbols, env vars, or wire formats changed: the canonical-string formats, header set, did:key derivation, and the `chapter_id` field remain frozen by the protocol. "member" is unchanged — it stays the role word. Conformance stays green.

### Added
- **ARP receipts.** The SDK is now ARP-native via the `sm_arp` consumable library:
  - `MemberAgent(identity, AgencyLog(...))` — `.record(category, human_summary, ...)` issues a signed receipt, hash-chains it to the agent's previous one (§6.4), appends to the Agency Log (§10.1), and returns it. Emission is the default, not an add-on; the chain resumes from an existing log across restarts.
  - `issue(identity, action=...)` — one-shot signed receipt bound to an identity; `principal_did` defaults to the member's own DID, overridable for delegated action.
  - `verify_receipt` — the consumer surface: verify a counterparty's receipt before trusting it.
- **Signed ARP conformance badge** at `.nanda/arp-conformance.json`, generated mechanically by `scripts/gen_arp_badge.py` (the canonical receipt vectors run through the SDK's `verify_receipt`).

`did:key` derivation is byte-identical to `sm_arp`, so receipts are attributed to the member's DID.

(The "Server rename" and "ARP receipts" entries above shipped in the `0.1.0` wheel but were listed as unreleased until this release.)

## [0.1.0] — 2026-06-01

Initial public release.

### Added
- `Identity` — Ed25519 keypair plus its derived did:key; `generate` and `from_seed`.
- `crypto` — did:key derivation/parsing, keypair generation, Ed25519 sign/verify.
- `signing` — v0.2 and v0.3 canonical strings, header sets, and the `sign_request` one-call signer.
- `ConformanceAdapter` — plugs the SDK into the server-protocol client conformance suite.
- Signed conformance badge at `.nanda/conformance.json`.
