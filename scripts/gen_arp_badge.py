#!/usr/bin/env python3
"""Generate sm-org-agent's signed ARP conformance badge — mechanically.

Conformance is a run, not a declaration: this feeds the canonical ARP verifier
corpus through the SDK's own consumer surface (``sm_agent.verify_receipt``)
and counts accept-vs-reject against each vector's documented verdict, then signs
the result with the member runtime key via sm-conformance (rung 1, self-signed).

    pip install 'sm-arp[conformance]'           # brings in sm-conformance
    ARP_REPO=~/sm-arp \
    NANDA_RUNTIME_KEY=~/.config/nanda-runtime-keys/member-sdk.hex \
        python scripts/gen_arp_badge.py

The ARP corpus + badge tool live in the sm-arp repo (not shipped in its wheel),
so point ARP_REPO at a checkout. The signing key is a 32-byte Ed25519 seed in
hex; it is never committed. Writes .nanda/arp-conformance.json.
"""

from __future__ import annotations

import binascii
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from sm_arp import chain_link

from sm_agent import verify_receipt

ARP_REPO = Path(os.environ.get("ARP_REPO", str(Path.home() / "sm-arp"))).expanduser()
sys.path.insert(0, str(ARP_REPO))  # for conformance.arp.badge + its vectors/schema

from conformance.arp.badge import build_arp_badge  # noqa: E402

VECTORS = ARP_REPO / "vectors" / "arp" / "0.1"


def _priors() -> dict[str, dict]:
    priors: dict[str, dict] = {}
    for path in sorted(VECTORS.glob("*.json")):
        vector = json.loads(path.read_text())
        if vector["expected_outcome"] == "verify_pass":
            priors[chain_link(vector["receipt"])] = vector["receipt"]
    return priors


def run_corpus() -> tuple[int, int, int]:
    priors = _priors()
    passed = failed = skipped = 0
    for path in sorted(VECTORS.glob("*.json")):
        vector = json.loads(path.read_text())
        receipt = vector["receipt"]
        prev = receipt.get("previous_receipt_hash")
        res = verify_receipt(
            receipt,
            mode=vector.get("verifier_mode", "strict"),
            prior=priors.get(prev) if prev else None,
            check_chain=bool(prev),
        )
        if res.ok is (vector["expected_outcome"] == "verify_pass"):
            passed += 1
        else:
            failed += 1
            print(f"  MISMATCH {path.name}: expected pass={vector['expected_outcome']}, got {res.stage}")
    return passed, failed, skipped


def main() -> int:
    key_path = Path(
        os.environ.get("NANDA_RUNTIME_KEY", str(Path.home() / ".config/nanda-runtime-keys/member-sdk.hex"))
    ).expanduser()
    seed = binascii.unhexlify(key_path.read_text().strip())

    passed, failed, skipped = run_corpus()
    print(f"ARP corpus: {passed} passed, {failed} failed, {skipped} skipped")

    badge = build_arp_badge(
        "sm-org-agent",
        passed=passed,
        failed=failed,
        skipped=skipped,
        signing_key32=seed,
        signed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    )
    out = Path(__file__).resolve().parent.parent / ".nanda" / "arp-conformance.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(badge, indent=2) + "\n")
    print(f"wrote {out} (signed_by {badge['signed_by']})")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
