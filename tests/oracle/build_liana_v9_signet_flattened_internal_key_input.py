#!/usr/bin/env python3
"""Flatten only the spendable Taproot internal key, keeping recovery multipath."""
import json
import sys
from pathlib import Path

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
MINISCRIPT_VERSION = "11.2.0"
RUSTC = "1.80.0 (051478957 2024-07-21)"
SOURCE_ID = "liana-v9-rust-signet-single-primary-recovery-vectors"
MULTIPATH_SUFFIX = "/<0;1>/*"
FIXED_SUFFIX = "/0/*"


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
        raise ValueError("source fixture must match pinned Liana, Miniscript, Rust, and Signet")
    body = source.get("multipathDescriptorBody", "")
    recovery_start = body.index("and_v(")
    primary_part, recovery_part = body[:recovery_start], body[recovery_start:]
    if primary_part.count(MULTIPATH_SUFFIX) != 1 or recovery_part.count(MULTIPATH_SUFFIX) != 1:
        raise ValueError("expected one multipath internal key and one multipath recovery signer")
    internal_branch = primary_part.index(MULTIPATH_SUFFIX)
    candidate = f"{body[:internal_branch]}{FIXED_SUFFIX}{body[internal_branch + len(MULTIPATH_SUFFIX):]}"
    candidate_recovery_start = candidate.index("and_v(")
    if FIXED_SUFFIX not in candidate[:candidate_recovery_start] or MULTIPATH_SUFFIX in candidate[:candidate_recovery_start]:
        raise ValueError("only the spendable internal primary key should have a fixed branch")
    if MULTIPATH_SUFFIX not in candidate[candidate_recovery_start:] or FIXED_SUFFIX in candidate[candidate_recovery_start:]:
        raise ValueError("recovery signer must remain multipath and unchanged")
    if candidate[candidate_recovery_start:] != body[recovery_start:]:
        raise ValueError("recovery policy and timelock must remain byte-identical")
    if candidate.replace(FIXED_SUFFIX, MULTIPATH_SUFFIX, 1) != body:
        raise ValueError("candidate must change only the internal key branch")
    return candidate


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json OUTPUT_DESCRIPTOR_BODY.txt")
    source_path, output_path = map(Path, sys.argv[1:])
    output_path.write_text(build_input(source_path) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
