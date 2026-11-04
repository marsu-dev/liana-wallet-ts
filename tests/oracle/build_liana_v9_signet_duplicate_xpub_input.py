#!/usr/bin/env python3
"""Build a valid-checksum candidate with duplicate primary/recovery xpub identity."""
import json
import re
import sys
from pathlib import Path

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
SOURCE_ID = "liana-v9-rust-signet-single-primary-recovery-vectors"
MULTIPATH_SUFFIX = "/<0;1>/*"


def build_input(source_path: Path) -> str:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    provenance = source.get("provenance", {})
    if source.get("id") != SOURCE_ID:
        raise ValueError("unexpected source fixture id")
    if provenance.get("lianaCommit") != LIANA_COMMIT or provenance.get("network") != "signet":
        raise ValueError("source fixture must be the pinned Signet vector")
    body = source.get("multipathDescriptorBody", "")
    if body.count(MULTIPATH_SUFFIX) != 2:
        raise ValueError("expected exactly two multipath keys")
    internal_start = body.index("[")
    internal_end = body.index(MULTIPATH_SUFFIX, internal_start) + len(MULTIPATH_SUFFIX)
    recovery_start = body.index("and_v(")
    recovery_key_start = body.index("[", recovery_start)
    recovery_key_end = body.index(MULTIPATH_SUFFIX, recovery_key_start) + len(MULTIPATH_SUFFIX)
    internal_key = body[internal_start:internal_end]
    original_recovery_key = body[recovery_key_start:recovery_key_end]
    duplicate_recovery_key, count = re.subn(r"^\[[0-9a-fA-F]{8}", "[deadbeef", internal_key, count=1)
    if count != 1 or duplicate_recovery_key == internal_key or duplicate_recovery_key[9:] != internal_key[9:]:
        raise ValueError("failed to preserve xpub/derivation identity while changing only the fingerprint")
    if original_recovery_key == duplicate_recovery_key:
        raise ValueError("candidate must be a changed recovery key")
    return f"{body[:recovery_key_start]}{duplicate_recovery_key}{body[recovery_key_end:]}"


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json OUTPUT_DESCRIPTOR_BODY.txt")
    source_path, output_path = map(Path, sys.argv[1:])
    output_path.write_text(build_input(source_path) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
