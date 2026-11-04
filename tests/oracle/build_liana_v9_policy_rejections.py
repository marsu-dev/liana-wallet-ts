#!/usr/bin/env python3
"""Build pinned Liana v9 policy-rejection fixtures from Rust oracle output."""
import json
import sys
from pathlib import Path

EXPECTED_ERROR = "Descriptor is not compatible with a Liana spending policy."
EXPECTED_IDS = ["taproot-recovery-hashlock", "taproot-primary-hashlock"]


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} ORACLE_TSV OUTPUT_JSON")
    source = Path(sys.argv[1])
    output = Path(sys.argv[2])
    cases = []
    for line_number, line in enumerate(source.read_text().splitlines(), 1):
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] != "R":
            raise SystemExit(f"malformed rejection oracle row at line {line_number}")
        _, case_id, descriptor, error = fields
        if case_id not in EXPECTED_IDS or any(case["id"] == case_id for case in cases):
            raise SystemExit(f"unexpected or duplicate rejection case at line {line_number}: {case_id}")
        if error != EXPECTED_ERROR:
            raise SystemExit(f"unexpected Rust rejection for {case_id}: {error}")
        cases.append({
            "id": case_id,
            "descriptor": descriptor,
            "reason": {
                "taproot-recovery-hashlock": "The Taproot recovery leaf combines a signer key, sha256 condition and older() timelock; pinned Liana rejects this non-key-only recovery policy.",
                "taproot-primary-hashlock": "The Taproot tree contains a signer key constrained by sha256 in a primary branch; pinned Liana rejects this non-key-only primary policy.",
            }[case_id],
            "expected": {"accepted": False, "error": error},
        })
    if [case["id"] for case in cases] != EXPECTED_IDS:
        raise SystemExit(f"expected rejection cases {EXPECTED_IDS}, got {[case['id'] for case in cases]}")

    fixture = {
        "id": "liana-v9-rust-policy-rejections",
        "provenance": {
            "lianaVersion": "9.0.0",
            "lianaCommit": "398e622596e7530a328de3027cb2c09905f708c6",
            "miniscriptVersion": "11.2.0",
            "rustc": "1.80.0 (051478957 2024-07-21)",
            "cargoLock": "Liana repository Cargo.lock at the pinned commit",
            "oracle": "LianaDescriptor::from_str; expected error message asserted by Rust harness",
            "testKeys": "Published public/test-only xpub material only; no seed or private key",
            "secretsOmitted": True,
        },
        "cases": cases,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"wrote {len(cases)} pinned rejection cases to {output}")


if __name__ == "__main__":
    main()
