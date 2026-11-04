#!/usr/bin/env python3
"""Build the pinned Signet input with reverse-ordered multipath choices."""
import json
import sys
from pathlib import Path

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
MINISCRIPT_VERSION = "11.2.0"
RUSTC = "1.80.0 (051478957 2024-07-21)"
SOURCE_ID = "liana-v9-rust-signet-single-primary-recovery-vectors"
BRANCHES = (19, 7)


def without_checksum(descriptor: str) -> str:
    if "#" not in descriptor:
        raise ValueError("source descriptor must have a checksum")
    return descriptor.rsplit("#", 1)[0]


def build_input(source_path: Path) -> str:
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
    original = source.get("multipathDescriptorBody", "")
    if original.count("/<0;1>/*") != 2:
        raise ValueError("expected exactly two multipath signer suffixes in the source descriptor")
    choice = f"<{BRANCHES[0]};{BRANCHES[1]}>"
    receive = without_checksum(source["descriptors"]["receive"])
    change = without_checksum(source["descriptors"]["change"])
    candidate = receive.replace("/0/*", f"/{choice}/*")
    if candidate != change.replace("/1/*", f"/{choice}/*"):
        raise ValueError("receive and change source descriptors differ beyond their branch value")
    expected = original.replace("/<0;1>/*", f"/{choice}/*")
    if candidate != expected or candidate.count(f"/{choice}/*") != 2 or "<0;1>" in candidate:
        raise ValueError("candidate must only reverse both ordered multipath choices to <19;7>")
    return candidate


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json OUTPUT_DESCRIPTOR_BODY.txt")
    source_path, output_path = map(Path, sys.argv[1:])
    output_path.write_text(build_input(source_path) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
