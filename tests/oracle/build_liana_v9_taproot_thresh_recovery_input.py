#!/usr/bin/env python3
"""Replace only the recovery multi_a with a type-correct key-only threshold candidate."""
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
    recovery_start = original.index("and_v(v:multi_a(2,")
    start = original.index("multi_a(2,", recovery_start)
    end = original.index(")", start) + 1
    source_policy = original[start:end]
    args = source_policy[len("multi_a("):-1].split(",")
    if len(args) != 4 or args[0] != "2":
        raise ValueError("source recovery must be the expected 2-of-3 multi_a policy")
    keys = args[1:]
    if len(set(keys)) != 3:
        raise ValueError("source recovery keys must be distinct")
    threshold_keys = [f"pk({keys[0]})", *(f"s:pk({key})" for key in keys[1:])]
    candidate_policy = f"thresh(2,{','.join(threshold_keys)})"
    candidate = original.replace(source_policy, candidate_policy, 1)
    if candidate.count("multi_a(2,") != 0 or candidate.count("thresh(2,") != 1:
        raise ValueError("candidate must replace only the recovery multi_a(2,...) policy")
    if candidate.replace(candidate_policy, source_policy, 1) != original:
        raise ValueError("candidate must preserve all descriptor content outside recovery policy")
    if "multi_a(3," not in candidate or "older(26352)" not in candidate:
        raise ValueError("primary multisig and recovery timelock must remain unchanged")
    return candidate


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} TAPROOT_FIXTURE.json OUTPUT_DESCRIPTOR_BODY.txt")
    source_path, output_path = map(Path, sys.argv[1:])
    output_path.write_text(build_input(source_path) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
