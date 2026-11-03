#!/usr/bin/env python3
"""Build the checked-in fixture from stdout of the pinned Liana Rust oracle."""
import json
import sys
from pathlib import Path

EXPECTED_IDS = ["single-primary-recovery", "multisig-one-recovery", "multisig-distinct-branch-values", "multisig-multiple-recovery", "taproot-multi-a-multiple-recovery"]
EXPECTED_BRANCHES = {"receive", "change"}
EXPECTED_INDICES = {"0", "1"}


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} ORACLE_TSV OUTPUT_JSON")
    source = Path(sys.argv[1])
    output = Path(sys.argv[2])
    cases = {}
    for line_number, line in enumerate(source.read_text().splitlines(), 1):
        fields = line.split("\t")
        if fields[0] == "D" and len(fields) == 4:
            _, case_id, policy, descriptor = fields
            if case_id in cases:
                raise SystemExit(f"duplicate descriptor row for {case_id} at line {line_number}")
            cases[case_id] = {
                "id": case_id,
                "policy": policy,
                "descriptor": descriptor,
                "expected": {"receive": {}, "change": {}},
            }
        elif fields[0] == "V" and len(fields) == 6:
            _, case_id, branch, index, address, script = fields
            if case_id not in cases:
                raise SystemExit(f"vector before descriptor for {case_id} at line {line_number}")
            if branch not in EXPECTED_BRANCHES or index not in EXPECTED_INDICES:
                raise SystemExit(f"unexpected branch/index at line {line_number}")
            if not address.startswith("bc1p") or not script.startswith("5120"):
                raise SystemExit(f"unexpected mainnet P2TR output at line {line_number}")
            cases[case_id]["expected"][branch][index] = {
                "address": address,
                "scriptPubKey": script,
            }
        else:
            raise SystemExit(f"malformed oracle output at line {line_number}")

    if list(cases) != EXPECTED_IDS:
        raise SystemExit(f"expected case order {EXPECTED_IDS}, got {list(cases)}")
    for case in cases.values():
        for branch in EXPECTED_BRANCHES:
            if set(case["expected"][branch]) != EXPECTED_INDICES:
                raise SystemExit(f"incomplete {case['id']} {branch} vectors")

    fixture = {
        "id": "liana-v9-rust-taproot-multisig-vectors",
        "provenance": {
            "lianaVersion": "9.0.0",
            "lianaCommit": "398e622596e7530a328de3027cb2c09905f708c6",
            "miniscriptVersion": "11.2.0",
            "rustc": "1.80.0 (051478957 2024-07-21)",
            "cargoLock": "Liana repository Cargo.lock at the pinned commit",
            "network": "mainnet",
            "generator": "LianaPolicy::new and LianaDescriptor::new; outputs from LianaDescriptor::receive_descriptor/change_descriptor, derive indices 0 and 1 with verification_only Secp256k1, address(Network::Bitcoin), script_pubkey()",
            "testKeys": "Four deterministic test-only BIP32 roots; fixture contains public descriptors only, no seed or private keys",
            "secretsOmitted": True,
        },
        "cases": [cases[case_id] for case_id in EXPECTED_IDS],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"wrote {len(cases)} cases, {len(cases) * 4} address/script pairs to {output}")


if __name__ == "__main__":
    main()
