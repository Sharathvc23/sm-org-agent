# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-06-01

Initial public release.

### Added
- `Identity` — Ed25519 keypair plus its derived did:key; `generate` and `from_seed`.
- `crypto` — did:key derivation/parsing, keypair generation, Ed25519 sign/verify.
- `signing` — v0.2 and v0.3 canonical strings, header sets, and the `sign_request` one-call signer.
- `ConformanceAdapter` — plugs the SDK into the chapter-protocol client conformance suite.
- Signed conformance badge at `.nanda/conformance.json`.
