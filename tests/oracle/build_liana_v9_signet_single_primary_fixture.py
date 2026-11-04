#!/usr/bin/env python3
"""Build 10x2 exact Signet outputs from the pinned Rust Liana harness."""
import json
import sys
from pathlib import Path

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
MINISCRIPT_VERSION = "11.2.0"
RUSTC = "1.80.0 (051478957 2024-07-21)"
EXPECTED_INDEXES = set(range(10))


def parse_vectors(path: Path) -> dict[str, dict[str, dict[str, str]]]:
    expected: dict[str, dict[str, dict[str, str]]] = {"receive": {}, "change": {}}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        fields = line.split("\t")
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
    for branch, rows in expected.items():
        if set(map(int, rows)) != EXPECTED_INDEXES:
            raise ValueError(f"{branch} must contain exactly receive/change indices 0 through 9")
    return expected


def build_fixture(source_path: Path, descriptor_path: Path, vectors_path: Path) -> dict:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    body = descriptor_path.read_text(encoding="utf-8").strip()
    if "#" in body:
        raise ValueError("Rust input must be the checksum-free multipath descriptor body")
    receive = source["receive"]["descriptor"].rsplit("#", 1)[0]
    change = source["change"]["descriptor"].rsplit("#", 1)[0]
    expected_body = receive.replace("/0/*", "/<0;1>/*")
    if expected_body != change.replace("/1/*", "/<0;1>/*") or body != expected_body:
        raise ValueError("Rust input must preserve the original community descriptor branches")
    return {
        "id": "liana-v9-rust-signet-single-primary-recovery-vectors",
        "provenance": {
            "source": source["provenance"]["source"],
            "lianaVersion": "9.0.0",
            "lianaCommit": LIANA_COMMIT,
            "miniscriptVersion": MINISCRIPT_VERSION,
            "rustc": RUSTC,
            "network": "signet",
            "generator": "LianaDescriptor::from_str; primary Single, recovery older(36) Single; receive_descriptor/change_descriptor, indices 0..9, address(Network::Signet), script_pubkey",
            "extendedKeySerialization": "tpub (Network::Testnet); address network Signet",
            "secretsOmitted": True,
        },
        "multipathDescriptorBody": body,
        "descriptors": {
            "receive": source["receive"]["descriptor"],
            "change": source["change"]["descriptor"],
        },
        "expected": parse_vectors(vectors_path),
    }


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(f"Usage: {sys.argv[0]} COMMUNITY_FIXTURE.json MULTIPATH_BODY.txt RUST_VECTORS.tsv OUTPUT.json")
    source_path, descriptor_path, vectors_path, output_path = map(Path, sys.argv[1:])
    result = build_fixture(source_path, descriptor_path, vectors_path)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
