#!/usr/bin/env python3
"""Rewrite the primary multi_a as an equivalent key-only threshold policy candidate."""
import json
import sys
from pathlib import Path

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
MINISCRIPT_VERSION = "11.2.0"
RUSTC = "1.80.0 (051478957 2024-07-21)"
SOURCE_ID = "liana-v9-rust-taproot-multisig-vectors"
SOURCE_CASE = "multisig-one-recovery"


def build_input(source_path: Path) -> str:
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
        raise ValueError("source fixture must match the pinned mainnet oracle versions")
    cases = [item for item in source.get("cases", []) if item.get("id") == SOURCE_CASE]
    if len(cases) != 1:
        raise ValueError("expected exactly one source case for 3-of-3 primary and 2-of-3 recovery")
    original = cases[0]["descriptor"].rsplit("#", 1)[0]
    start = original.index("multi_a(3,")
    end = original.index(")", start) + 1
    source_policy = original[start:end]
    args = source_policy[len("multi_a("):-1].split(",")
    if len(args) != 4 or args[0] != "3":
        raise ValueError("source primary must be the expected 3-of-3 multi_a policy")
    keys = args[1:]
    if len(set(keys)) != 3:
        raise ValueError("source primary keys must be distinct")
    threshold_keys = [f"pk({keys[0]})", *(f"s:pk({key})" for key in keys[1:])]
    candidate_policy = f"thresh(3,{','.join(threshold_keys)})"
    candidate = original.replace(source_policy, candidate_policy, 1)
    if candidate.count("thresh(3,") != 1 or "multi_a(3," in candidate:
        raise ValueError("candidate must replace only the primary multi_a(3,...) policy")
    if candidate.replace(candidate_policy, source_policy, 1) != original:
        raise ValueError("candidate must preserve all descriptor content outside the primary policy")
    return candidate


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} TAPROOT_FIXTURE.json OUTPUT_DESCRIPTOR_BODY.txt")
    source_path, output_path = map(Path, sys.argv[1:])
    output_path.write_text(build_input(source_path) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
