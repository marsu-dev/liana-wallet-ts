#!/usr/bin/env python3
"""Build a pinned-Liana candidate by encoding a one-key recovery as multi_a(1,key)."""
import json
import sys
from pathlib import Path

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"


def build_input(source_path: Path) -> str:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    if source.get("id") != "liana-v9-rust-signet-single-primary-recovery-vectors":
        raise ValueError("unexpected source fixture id")
    provenance = source.get("provenance", {})
    if provenance.get("lianaCommit") != LIANA_COMMIT or provenance.get("network") != "signet":
        raise ValueError("source fixture must be the pinned Signet vector")
    body = source.get("multipathDescriptorBody", "")
    if body.count("v:pk(") != 1:
        raise ValueError("expected exactly one single-key recovery pk() expression")
    candidate = body.replace("v:pk(", "v:multi_a(1,", 1)
    if candidate.count("v:multi_a(1,") != 1 or "older(36)" not in candidate:
        raise ValueError("candidate mutation did not preserve the single-key older(36) recovery")
    return candidate


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} COMMUNITY_RUST_FIXTURE.json OUTPUT_DESCRIPTOR_BODY.txt")
    source_path, output_path = map(Path, sys.argv[1:])
    output_path.write_text(build_input(source_path) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
