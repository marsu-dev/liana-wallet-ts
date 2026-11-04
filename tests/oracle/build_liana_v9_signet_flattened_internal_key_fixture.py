#!/usr/bin/env python3
"""Build the pinned Liana rejection fixture for a flattened internal key."""
import json
import sys
from pathlib import Path

from build_liana_v9_signet_flattened_internal_key_input import (
    LIANA_COMMIT,
    MINISCRIPT_VERSION,
    RUSTC,
    SOURCE_ID,
    build_input,
)


def build_fixture(source_path: Path, input_path: Path, output_path: Path) -> dict:
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
        raise ValueError("source fixture must match pinned Liana, Miniscript, Rust, and Signet")
    candidate = build_input(source_path)
    if input_path.read_text(encoding="utf-8").strip() != candidate:
        raise ValueError("candidate must be the exact flattened-internal-key mutation")

    rows = [line.split("\t") for line in output_path.read_text(encoding="utf-8").splitlines()]
    descriptor_rows = [row for row in rows if len(row) == 2 and row[0] == "D"]
    error_rows = [row for row in rows if len(row) == 2 and row[0] == "E"]
    if len(rows) != 2 or len(descriptor_rows) != 1 or len(error_rows) != 1:
        raise ValueError("oracle must return exactly one descriptor and one policy error")
    descriptor = descriptor_rows[0][1]
    if "#" not in descriptor or descriptor.rsplit("#", 1)[0] != candidate:
        raise ValueError("Rust-parsed descriptor body must exactly match the candidate")
    if error_rows[0][1] != "IncompatibleDesc":
        raise ValueError("pinned Liana must reject exactly as IncompatibleDesc")
    return {
        "id": "liana-v9-rust-signet-flattened-internal-key-rejection",
        "provenance": {
            "lianaVersion": "9.0.0",
            "lianaCommit": LIANA_COMMIT,
            "miniscriptVersion": MINISCRIPT_VERSION,
            "rustc": RUSTC,
            "cargoLock": "Liana repository Cargo.lock at the pinned commit",
            "network": "signet",
            "extendedKeySerialization": "tpub (Network::Testnet); descriptor context and addresses are Signet",
            "generator": "Pinned LianaDescriptor::from_str on the valid-checksum Signet descriptor; exact Liana policy rejection emitted by the Rust harness",
            "secretsOmitted": True,
        },
        "sourceFixture": SOURCE_ID,
        "transformation": "Change only the spendable internal primary key branch from /<0;1>/* to /0/*; the recovery signer remains on /<0;1>/*.",
        "expectedRejection": "IncompatibleDesc",
        "descriptor": descriptor,
    }


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json CANDIDATE.txt ORACLE.tsv OUTPUT.json")
    source_path, input_path, output_path, fixture_path = map(Path, sys.argv[1:])
    fixture = build_fixture(source_path, input_path, output_path)
    fixture_path.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
