#!/usr/bin/env python3
"""Build exact Rust outputs for the reverse-ordered Signet multipath candidate."""
import json
import sys
from pathlib import Path

from build_liana_v9_signet_single_primary_fixture import parse_vectors

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
MINISCRIPT_VERSION = "11.2.0"
RUSTC = "1.80.0 (051478957 2024-07-21)"
SOURCE_ID = "liana-v9-rust-signet-single-primary-recovery-vectors"



def build_fixture(source_path: Path, input_path: Path, vectors_path: Path) -> dict:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    provenance = source.get("provenance", {})
    if source.get("id") != SOURCE_ID:
        raise ValueError("unexpected source fixture id")
    if (
        provenance.get("lianaCommit") != LIANA_COMMIT
        or provenance.get("miniscriptVersion") != MINISCRIPT_VERSION
        or provenance.get("rustc") != RUSTC
        or provenance.get("network") != "signet"
    ):
        raise ValueError("source fixture must match the pinned Signet oracle versions")
    body = input_path.read_text(encoding="utf-8").strip()
    source_body = source.get("multipathDescriptorBody", "")
    expected_body = source_body.replace("/<0;1>/*", "/<19;7>/*")
    if source_body.count("/<0;1>/*") != 2 or body != expected_body:
        raise ValueError("Rust input must only reverse the original multipath choices to <19;7>")
    if body.count("/<19;7>/*") != 2:
        raise ValueError("both signer keys must use the ordered pair <19;7>")
    expected = parse_vectors(vectors_path)
    return {
        "id": "liana-v9-rust-signet-single-primary-recovery-branches-19-7",
        "provenance": {
            "sourceFixture": SOURCE_ID,
            "source": provenance["source"],
            "lianaVersion": "9.0.0",
            "lianaCommit": LIANA_COMMIT,
            "miniscriptVersion": MINISCRIPT_VERSION,
            "rustc": RUSTC,
            "network": "signet",
            "generator": "LianaDescriptor::from_str; primary Single, recovery older(36) Single; receive_descriptor/change_descriptor, indices 0..9, address(Network::Signet), script_pubkey",
            "extendedKeySerialization": "tpub (Network::Testnet); address network Signet",
            "multipathChoices": [19, 7],
            "secretsOmitted": True,
        },
        "transformation": "both signer multipath tuples changed from <0;1> to non-ascending <19;7>; receive/change follow exact tuple order",
        "multipathDescriptorBody": body,
        "expected": expected,
    }


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json INPUT_DESCRIPTOR_BODY.txt RUST_OUTPUT.tsv OUTPUT.json")
    source_path, input_path, vectors_path, output_path = map(Path, sys.argv[1:])
    result = build_fixture(source_path, input_path, vectors_path)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
