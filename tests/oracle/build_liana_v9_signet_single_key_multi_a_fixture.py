#!/usr/bin/env python3
"""Build exact Signet outputs for the pinned Liana single-key multi_a parser vector."""
import json
import sys
from pathlib import Path

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
MINISCRIPT_VERSION = "11.2.0"
RUSTC = "1.80.0 (051478957 2024-07-21)"
EXPECTED_INDEXES = set(range(10))


def parse_vectors(path: Path) -> tuple[str, dict[str, dict[str, dict[str, str]]]]:
    descriptor = None
    expected: dict[str, dict[str, dict[str, str]]] = {"receive": {}, "change": {}}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        fields = line.split("\t")
        if fields[0] == "D":
            if len(fields) != 2 or descriptor is not None:
                raise ValueError(f"invalid or duplicate descriptor row at line {line_number}")
            descriptor = fields[1]
            continue
        if len(fields) != 5 or fields[0] != "V":
            raise ValueError(f"invalid Rust vector row at line {line_number}")
        _, branch, index_text, address, script = fields
        if branch not in expected:
            raise ValueError(f"unexpected branch at line {line_number}: {branch}")
        index = int(index_text)
        if str(index) != index_text or index not in EXPECTED_INDEXES:
            raise ValueError(f"unexpected index at line {line_number}: {index_text}")
        if index_text in expected[branch]:
            raise ValueError(f"duplicate {branch}/{index_text} row")
        if not address.startswith("tb1p"):
            raise ValueError(f"unexpected Signet Taproot address at {branch}/{index_text}")
        if len(script) != 68 or not script.startswith("5120") or any(c not in "0123456789abcdef" for c in script):
            raise ValueError(f"invalid P2TR scriptPubKey at {branch}/{index_text}")
        expected[branch][index_text] = {"address": address, "scriptPubKey": script}
    if descriptor is None:
        raise ValueError("missing pinned Rust Liana descriptor row")
    for branch, rows in expected.items():
        if set(map(int, rows)) != EXPECTED_INDEXES:
            raise ValueError(f"{branch} must contain exactly indices 0 through 9")
    return descriptor, expected


def build_fixture(source_path: Path, input_path: Path, vectors_path: Path) -> dict:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    provenance = source.get("provenance", {})
    if source.get("id") != "liana-v9-rust-signet-single-primary-recovery-vectors":
        raise ValueError("unexpected source fixture id")
    if provenance.get("lianaCommit") != LIANA_COMMIT or provenance.get("network") != "signet":
        raise ValueError("source fixture must be the pinned Signet vector")
    input_body = input_path.read_text(encoding="utf-8").strip()
    if input_body.count("v:multi_a(1,") != 1 or "older(36)" not in input_body:
        raise ValueError("input must be the single-key multi_a(1,key), older(36) mutation")
    descriptor, expected = parse_vectors(vectors_path)
    if "#" not in descriptor or descriptor.rsplit("#", 1)[0] != input_body:
        raise ValueError("Rust's serialized descriptor body does not match the exact candidate input")
    return {
        "id": "liana-v9-rust-signet-single-key-multi-a",
        "provenance": {
            "sourceFixture": "liana-v9-rust-signet-single-primary-recovery.json",
            "lianaVersion": "9.0.0",
            "lianaCommit": LIANA_COMMIT,
            "miniscriptVersion": MINISCRIPT_VERSION,
            "rustc": RUSTC,
            "network": "signet",
            "generator": "Mutate the pinned Rust single-primary Signet fixture from and_v(v:pk(key),older(36)) to and_v(v:multi_a(1,key),older(36)); parse with LianaDescriptor::from_str, assert primary/recovery PathInfo::Single mapping at older(36), then derive receive/change addresses and scriptPubKeys at indices 0..9",
            "extendedKeySerialization": "tpub (Network::Testnet); address network Signet",
            "secretsOmitted": True,
        },
        "transformation": "v:pk(key) -> v:multi_a(1,key) in the single recovery path; original multipath keys and timelock preserved",
        "inferredPolicy": {
            "primary": "PathInfo::Single",
            "recovery": {"older": 36, "path": "PathInfo::Single"},
        },
        "descriptor": descriptor,
        "expected": expected,
    }


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(f"Usage: {sys.argv[0]} COMMUNITY_FIXTURE.json INPUT_DESCRIPTOR_BODY.txt RUST_VECTORS.tsv OUTPUT.json")
    source_path, input_path, vectors_path, output_path = map(Path, sys.argv[1:])
    result = build_fixture(source_path, input_path, vectors_path)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
