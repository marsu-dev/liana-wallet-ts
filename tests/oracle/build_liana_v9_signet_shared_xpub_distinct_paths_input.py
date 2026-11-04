#!/usr/bin/env python3
"""Reuse the same public xpub on distinct ordered multipath derivation tuples."""
import json
import sys
from pathlib import Path

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
MINISCRIPT_VERSION = "11.2.0"
RUSTC = "1.80.0 (051478957 2024-07-21)"
SOURCE_ID = "liana-v9-rust-signet-single-primary-recovery-vectors"


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
    body = source.get("multipathDescriptorBody", "")
    if body.count("/<0;1>/*") != 2 or body.count("and_v(v:pk(") != 1:
        raise ValueError("expected the pinned single-primary, single-recovery descriptor shape")
    internal_key = body[3:body.index(",")]
    recovery_key_start = body.index("and_v(v:pk(") + len("and_v(v:pk(")
    recovery_key_end = body.index(")", recovery_key_start)
    recovery_key = body[recovery_key_start:recovery_key_end]
    if recovery_key == internal_key or recovery_key.count("/<0;1>/*") != 1:
        raise ValueError("source fixture must use separate multipath xpubs for primary and recovery")
    same_xpub_reversed_path = internal_key.replace("/<0;1>/*", "/<1;0>/*")
    candidate = body.replace(recovery_key, same_xpub_reversed_path, 1)
    if candidate.count("/<0;1>/*") != 1 or candidate.count("/<1;0>/*") != 1:
        raise ValueError("candidate must preserve the primary path and reverse only the recovery path")
    if candidate.replace(same_xpub_reversed_path, recovery_key, 1) != body:
        raise ValueError("candidate must change only the recovery key expression")
    return candidate


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json OUTPUT_DESCRIPTOR_BODY.txt")
    source_path, output_path = map(Path, sys.argv[1:])
    output_path.write_text(build_input(source_path) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
