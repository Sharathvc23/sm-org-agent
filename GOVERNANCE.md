# Governance

## Scope

`sm-agent` is the client signing surface of the chapter protocol: identity (did:key), canonical-string construction, Ed25519 signing, and the header set, for v0.2 and v0.3. It is deliberately *not* a transport, an agent runtime, or a product. HTTP, retries, and agent behaviour live above this line, in your code.

## Versioning

- The package follows semantic versioning, independent of any protocol version.
- The **wire it produces** — canonical-string formats, header names and casing, did:key derivation, signature scheme labels — does not change within a major. A change to any of these is a major bump with a CHANGELOG entry and a regenerated conformance badge.
- Additive or configuration-only changes are minor or patch.

## Conformance

A build is conformant *iff* the client conformance suite passes against its adapter and the repository carries a green, signed `.nanda/conformance.json` pinned to that suite's vector digest. A passing badge is a precondition for any release tag. The signing key is a runtime key held outside CI; it is never committed.

## Contributions

Issues and pull requests are welcome. A change that touches the produced wire must keep conformance green and update the badge. All code keeps the gate green: `ruff`, `mypy --strict`, and `pytest` at or above the coverage floor.

## Attribution

Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. Maintained by [stellarminds.ai](https://stellarminds.ai).
