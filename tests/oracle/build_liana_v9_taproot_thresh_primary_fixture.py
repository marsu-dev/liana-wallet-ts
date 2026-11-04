#!/usr/bin/env python3
"""Build a provenance-checked fixture from the pinned Liana Rust oracle output."""
import json
import sys
from pathlib import Path

from build_liana_v9_taproot_thresh_primary_input import (
    LIANA_COMMIT,
    MINISCRIPT_VERSION,
    RUSTC,
    SOURCE_CASE,
    SOURCE_ID,
    build_input,
)


def parse_output(path: Path, candidate: str) -> tuple[str, dict[str, dict[int, dict[str, str]]]]:
    descriptor_rows: list[str] = []
    policy_rows: list[list[str]] = []
    expected: dict[str, dict[int, dict[str, str]]] = {"receive": {}, "change": {}}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if fields[0] == "D" and len(fields) == 2:
            descriptor_rows.append(fields[1])
        elif fields[0] == "P":
            policy_rows.append(fields[1:])
        elif fields[0] == "V" and len(fields) == 5:
            _, branch, index_text, address, script = fields
            if branch not in expected or not index_text.isdigit():
                raise ValueError("invalid oracle branch or index")
            index = int(index_text)
            if index in expected[branch]:
                raise ValueError("duplicate oracle branch/index row")
            if not address.startswith("bc1p") or not script.startswith("5120") or len(script) != 68:
                raise ValueError("oracle output does not match mainnet Taproot format")
            expected[branch][index] = {"address": address, "scriptPubKey": script}
        else:
            raise ValueError(f"unexpected oracle output row: {line!r}")
    if len(descriptor_rows) != 1:
        raise ValueError("expected exactly one checksummed descriptor row")
    descriptor = descriptor_rows[0]
    if "#" not in descriptor or descriptor.rsplit("#", 1)[0] != candidate:
        raise ValueError("Rust descriptor body must exactly match the candidate input")
    if policy_rows != [["primary", "multi", "3", "3"], ["recovery", "26352", "multi", "2", "3"]]:
        raise ValueError("Rust did not infer the expected primary/recovery thresholds")
    if any(sorted(branch.keys()) != list(range(10)) for branch in expected.values()):
        raise ValueError("expected receive and change indices 0 through 9 exactly once")
    if sum(len(branch) for branch in expected.values()) != 20:
        raise ValueError("expected exactly twenty address/script pairs")
    return descriptor, expected


def build_fixture(source_path: Path, input_path: Path, output_path: Path) -> dict:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    provenance = source.get("provenance", {})
    if source.get("id") != SOURCE_ID:
        raise ValueError("unexpected source fixture id")
    if (
        provenance.get("lianaCommit") != LIANA_COMMIT
        or provenance.get("miniscriptVersion") != MINISCRIPT_VERSION
        or provenance.get("rustc") != RUSTC
        or provenance.get("network") != "mainnet"
    ):
        raise ValueError("source fixture must match pinned Liana, Miniscript, Rust, and mainnet")
    if input_path.read_text(encoding="utf-8").strip() != build_input(source_path):
        raise ValueError("input candidate does not match the exact source-fixture mutation")
    descriptor, expected = parse_output(output_path, input_path.read_text(encoding="utf-8").strip())
    return {
        "id": "liana-v9-rust-taproot-thresh-primary-vectors",
        "provenance": {
            "lianaVersion": "9.0.0",
            "lianaCommit": LIANA_COMMIT,
            "miniscriptVersion": MINISCRIPT_VERSION,
            "rustc": RUSTC,
            "cargoLock": "Liana repository Cargo.lock at the pinned commit",
            "network": "mainnet",
            "generator": "Pinned LianaDescriptor::from_str on the exact source-derived descriptor candidate; addresses and scriptPubKeys from receive_descriptor/change_descriptor with verification-only secp256k1",
            "secretsOmitted": True,
        },
        "sourceFixture": SOURCE_ID,
        "sourceCase": SOURCE_CASE,
        "transformation": "Replace only the primary multi_a(3,key1,key2,key3) leaf with the type-correct key-only thresh(3,pk(key1),s:pk(key2),s:pk(key3)); retain the recovery multi_a(2,...) leaf and the unspendable internal key.",
        "inferredPolicy": {
            "primary": {"threshold": 3, "keyCount": 3},
            "recovery": [{"older": 26352, "threshold": 2, "keyCount": 3}],
        },
        "descriptor": descriptor,
        "expected": expected,
    }


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json CANDIDATE.txt ORACLE.tsv OUTPUT.json")
    source_path, input_path, output_path, fixture_path = map(Path, sys.argv[1:])
    fixture = build_fixture(source_path, input_path, output_path)
    fixture_path.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
