#!/usr/bin/env python3
"""Build exact Signet vectors for a Liana descriptor with nonstandard multipath indexes."""
import json
import re
import sys
from pathlib import Path

from build_liana_v9_signet_single_primary_fixture import parse_vectors

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
MINISCRIPT_VERSION = "11.2.0"
RUSTC = "1.80.0 (051478957 2024-07-21)"


def build_fixture(source_path: Path, descriptor_path: Path, vectors_path: Path) -> dict:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    body = descriptor_path.read_text(encoding="utf-8").strip()
    if "#" in body:
        raise ValueError("Rust input must be a checksum-free multipath descriptor body")
    receive = source["receive"]["descriptor"].rsplit("#", 1)[0]
    change = source["change"]["descriptor"].rsplit("#", 1)[0]
    matches = re.findall(r"<(\d+);(\d+)>", body)
    if not matches or len(set(matches)) != 1:
        raise ValueError("all signer keys must use the same two-choice multipath pair")
    branches = tuple(map(int, matches[0]))
    if branches[0] == branches[1] or any(value < 0 or value >= 0x80000000 for value in branches):
        raise ValueError("multipath choices must be distinct normal child indexes")
    choice = f"<{branches[0]};{branches[1]}>"
    expected_body = receive.replace("/0/*", f"/{choice}/*")
    change_as_multipath = change.replace("/1/*", f"/{choice}/*")
    if expected_body != change_as_multipath or body != expected_body:
        raise ValueError("Rust input must preserve the community descriptor except for the explicit multipath choices")
    return {
        "id": f"liana-v9-rust-signet-single-primary-recovery-branches-{branches[0]}-{branches[1]}",
        "provenance": {
            "source": source["provenance"]["source"],
            "lianaVersion": "9.0.0",
            "lianaCommit": LIANA_COMMIT,
            "miniscriptVersion": MINISCRIPT_VERSION,
            "rustc": RUSTC,
            "network": "signet",
            "generator": "LianaDescriptor::from_str; primary Single, recovery older(36) Single; receive_descriptor/change_descriptor, indices 0..9, address(Network::Signet), script_pubkey",
            "extendedKeySerialization": "tpub (Network::Testnet); address network Signet",
            "multipathChoices": list(branches),
            "secretsOmitted": True,
        },
        "multipathDescriptorBody": body,
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
