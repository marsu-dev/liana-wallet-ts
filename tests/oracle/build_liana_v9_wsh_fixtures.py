#!/usr/bin/env python3
"""Build the checked-in legacy P2WSH fixtures from pinned Liana Rust stdout."""
import json
import sys
from pathlib import Path

EXPECTED_IDS = ["legacy-single-primary-recovery", "legacy-2-of-3-primary-recovery", "legacy-multiple-recovery", "legacy-andor", "legacy-v2-threshold-recoveries"]
BRANCHES = {"receive", "change"}
INDICES = {"0", "1"}


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} ORACLE_TSV OUTPUT_DIRECTORY")
    source, output_dir = Path(sys.argv[1]), Path(sys.argv[2])
    cases = {}
    for line_number, line in enumerate(source.read_text().splitlines(), 1):
        fields = line.split("\t")
        if fields[0] == "D" and len(fields) == 3:
            _, case_id, descriptor = fields
            if case_id in cases:
                raise SystemExit(f"duplicate descriptor row for {case_id} at line {line_number}")
            cases[case_id] = {"descriptor": descriptor, "expected": {"receive": {}, "change": {}}}
        elif fields[0] == "V" and len(fields) == 6:
            _, case_id, branch, index, address, script = fields
            if case_id not in cases:
                raise SystemExit(f"vector before descriptor for {case_id} at line {line_number}")
            if branch not in BRANCHES or index not in INDICES:
                raise SystemExit(f"unexpected branch/index at line {line_number}")
            if not address.startswith("bc1q") or not script.startswith("0020"):
                raise SystemExit(f"unexpected mainnet P2WSH output at line {line_number}")
            vectors = cases[case_id]["expected"][branch]
            if index in vectors:
                raise SystemExit(f"duplicate vector row for {case_id} {branch} {index} at line {line_number}")
            vectors[index] = {"address": address, "scriptPubKey": script}
        else:
            raise SystemExit(f"malformed oracle output at line {line_number}")

    if list(cases) != EXPECTED_IDS:
        raise SystemExit(f"expected case order {EXPECTED_IDS}, got {list(cases)}")
    for case_id, case in cases.items():
        for branch in BRANCHES:
            if set(case["expected"][branch]) != INDICES:
                raise SystemExit(f"incomplete {case_id} {branch} vectors")

    generators = {
        "legacy-single-primary-recovery": "LianaPolicy::new_legacy and LianaDescriptor::new; receive/change descriptors derived at indices 0 and 1 with verification-only secp256k1; address and script_pubkey from Rust",
        "legacy-2-of-3-primary-recovery": "LianaPolicy::new_legacy with 2-of-3 primary and 2-of-3 recovery; LianaDescriptor::new; receive/change derived at indices 0 and 1; address and script_pubkey from Rust",
        "legacy-multiple-recovery": "LianaPolicy::new_legacy with 2-of-3 primary; recovery older(42) single-key, older(43) 2-of-3, older(1678) 1-of-3; LianaDescriptor::new; receive/change derived at indices 0 and 1; address and script_pubkey from Rust",
        "legacy-andor": "LianaDescriptor::from_str over wsh(andor(pk(recovery),older(42),pk(primary))); parsed semantic policy and receive/change addresses and scripts from pinned Rust at indices 0 and 1",
        "legacy-v2-threshold-recoveries": "LianaDescriptor::from_str over a mainnet-instantiated version of the three-recovery P2WSH shape in pinned liana/src/descriptors/mod.rs::bip32_derivs_pruning; primary 3-of-3, recovery older(3) 2-of-3 and older(6) 3-of-3 with distinct multipath values; policy mapping and Rust outputs asserted",
    }
    filenames = {
        "legacy-single-primary-recovery": "liana-v9-rust-legacy-wsh.json",
        "legacy-2-of-3-primary-recovery": "liana-v9-rust-legacy-wsh-multisig.json",
        "legacy-multiple-recovery": "liana-v9-rust-legacy-wsh-multiple-recovery.json",
        "legacy-andor": "liana-v9-rust-legacy-wsh-andor.json",
        "legacy-v2-threshold-recoveries": "liana-v9-rust-legacy-wsh-v2-thresholds.json",
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    for case_id in EXPECTED_IDS:
        fixture = {
            "id": f"liana-v9-rust-{case_id}-vectors",
            "provenance": {
                "lianaVersion": "9.0.0",
                "lianaCommit": "398e622596e7530a328de3027cb2c09905f708c6",
                "miniscriptVersion": "11.2.0",
                "rustc": "1.80.0 (051478957 2024-07-21)",
                "network": "mainnet",
                "generator": generators[case_id],
                "testKeys": "Descriptor includes only public test xpubs; no seed or private key is stored",
                "secretsOmitted": True,
            },
            "descriptor": cases[case_id]["descriptor"],
            "expected": cases[case_id]["expected"],
        }
        (output_dir / filenames[case_id]).write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"wrote {len(cases)} cases, {len(cases) * 4} address/script pairs to {output_dir}")


if __name__ == "__main__":
    main()
