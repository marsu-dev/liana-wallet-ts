#!/usr/bin/env python3
"""Build the exact pinned DuplicateOriginSamePath recovery rejection fixture."""
import json
import sys
from pathlib import Path

from build_liana_v9_duplicate_origin_recovery_input import (
    LIANA_COMMIT,
    MINISCRIPT_VERSION,
    RUSTC,
    SOURCE_CASE,
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
        or provenance.get("network") != "mainnet"
    ):
        raise ValueError("source fixture must match pinned Liana, Miniscript, Rust, and mainnet")
    candidate = build_input(source_path)
    if input_path.read_text(encoding="utf-8").strip() != candidate:
        raise ValueError("candidate must be the exact recovery-origin mutation")

    rows = [line.split("\t") for line in output_path.read_text(encoding="utf-8").splitlines()]
    descriptor_rows = [row for row in rows if len(row) == 2 and row[0] == "D"]
    error_rows = [row for row in rows if len(row) == 2 and row[0] == "E"]
    if len(rows) != 2 or len(descriptor_rows) != 1 or len(error_rows) != 1:
        raise ValueError("oracle must return exactly one descriptor and one policy error")
    descriptor = descriptor_rows[0][1]
    if "#" not in descriptor or descriptor.rsplit("#", 1)[0] != candidate:
        raise ValueError("Rust-parsed descriptor body must exactly match the candidate")
    if error_rows[0][1] != "DuplicateOriginSamePath":
        raise ValueError("pinned Liana must reject exactly as DuplicateOriginSamePath")
    return {
        "id": "liana-v9-rust-taproot-duplicate-origin-recovery-same-path",
        "provenance": {
            "lianaVersion": "9.0.0",
            "lianaCommit": LIANA_COMMIT,
            "miniscriptVersion": MINISCRIPT_VERSION,
            "rustc": RUSTC,
            "cargoLock": "Liana repository Cargo.lock at the pinned commit",
            "network": "mainnet",
            "generator": "Pinned LianaDescriptor::from_str on the valid-checksum descriptor; exact Liana policy rejection emitted by the Rust harness",
            "secretsOmitted": True,
        },
        "sourceFixture": SOURCE_ID,
        "sourceCase": SOURCE_CASE,
        "transformation": "Change only the recovery multi_a(2,...) second key origin fingerprint from 8dfc9b34 to 4ba43603; its xpub and derivation suffix, the primary policy, recovery timelock, and NUMS internal key remain unchanged.",
        "expectedRejection": "DuplicateOriginSamePath",
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
