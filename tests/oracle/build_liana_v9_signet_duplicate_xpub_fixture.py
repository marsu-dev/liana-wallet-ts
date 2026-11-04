#!/usr/bin/env python3
"""Build the pinned Liana negative fixture for duplicate xpub identities."""
import json
import sys
from pathlib import Path

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
SOURCE_ID = "liana-v9-rust-signet-single-primary-recovery-vectors"
MINISCRIPT_VERSION = "11.2.0"
RUSTC = "1.80.0 (051478957 2024-07-21)"


def read_rust_rows(path: Path) -> tuple[str, str]:
    descriptor = None
    rejection = None
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        fields = line.split("\t")
        if fields[0] == "D" and len(fields) == 2 and descriptor is None:
            descriptor = fields[1]
        elif fields[0] == "E" and len(fields) == 2 and rejection is None:
            rejection = fields[1]
        else:
            raise ValueError(f"invalid or duplicate Rust oracle row at line {line_number}")
    if descriptor is None or rejection is None:
        raise ValueError("Rust output must contain one descriptor and one rejection row")
    if rejection != "DuplicateKey":
        raise ValueError(f"unexpected pinned Liana rejection: {rejection}")
    return descriptor, rejection


def build_fixture(source_path: Path, input_path: Path, vectors_path: Path) -> dict:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    provenance = source.get("provenance", {})
    if source.get("id") != SOURCE_ID:
        raise ValueError("unexpected source fixture id")
    if provenance.get("lianaCommit") != LIANA_COMMIT or provenance.get("network") != "signet":
        raise ValueError("source fixture must be the pinned Signet vector")
    input_body = input_path.read_text(encoding="utf-8").strip()
    if input_body.count("[deadbeef/48'/1'/0'/2']") != 1:
        raise ValueError("candidate must change only the duplicate key's origin fingerprint")
    descriptor, rejection = read_rust_rows(vectors_path)
    if "#" not in descriptor or descriptor.rsplit("#", 1)[0] != input_body:
        raise ValueError("Rust-parsed descriptor body must match the exact candidate input")
    return {
        "id": "liana-v9-rust-signet-duplicate-xpub-different-fingerprint",
        "provenance": {
            "sourceFixture": SOURCE_ID,
            "lianaVersion": "9.0.0",
            "lianaCommit": LIANA_COMMIT,
            "miniscriptVersion": MINISCRIPT_VERSION,
            "rustc": RUSTC,
            "network": "signet",
            "generator": "Replace the single recovery xpub with the spendable internal primary xpub while changing only its origin fingerprint; parse descriptor syntax, then assert LianaDescriptor::from_str returns LianaDescError::Policy(LianaPolicyError::DuplicateKey)",
            "extendedKeySerialization": "tpub (Network::Testnet); descriptor address network Signet",
            "secretsOmitted": True,
        },
        "transformation": "recovery xpub/derivation path duplicates the primary internal xpub/derivation path; origin fingerprint differs",
        "expectedRejection": rejection,
        "descriptor": descriptor,
    }


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json INPUT_DESCRIPTOR_BODY.txt RUST_OUTPUT.tsv OUTPUT.json")
    source_path, input_path, vectors_path, output_path = map(Path, sys.argv[1:])
    output_path.write_text(json.dumps(build_fixture(source_path, input_path, vectors_path), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
