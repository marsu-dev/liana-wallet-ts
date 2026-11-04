#!/usr/bin/env python3
"""Duplicate only one primary origin fingerprint to test Liana's signer rule."""
import json
import re
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
        raise ValueError("source fixture must match pinned Liana, Miniscript, Rust, and mainnet")
    cases = [item for item in source.get("cases", []) if item.get("id") == SOURCE_CASE]
    if len(cases) != 1:
        raise ValueError("expected exactly one 3-of-3 primary source case")
    original = cases[0]["descriptor"].rsplit("#", 1)[0]
    start = original.index("multi_a(3,")
    end = original.index(")", start) + 1
    source_policy = original[start:end]
    args = source_policy[len("multi_a("):-1].split(",")
    if len(args) != 4 or args[0] != "3":
        raise ValueError("source primary must be the expected 3-of-3 multi_a policy")
    keys = args[1:]
    origins = [re.match(r"^\[([0-9a-fA-F]{8})\]", key) for key in keys]
    if any(origin is None for origin in origins):
        raise ValueError("each source primary key must have an 8-hex fingerprint origin")
    fingerprints = [origin.group(1).lower() for origin in origins if origin]
    if fingerprints != ["4ba43603", "8dfc9b34", "56c4fac3"]:
        raise ValueError("source primary fingerprints do not match the pinned public test roots")
    first_origin = origins[0]
    second_origin = origins[1]
    assert first_origin is not None and second_origin is not None
    replacement = f"[{first_origin.group(1)}]" + keys[1][second_origin.end():]
    if replacement == keys[1] or replacement[second_origin.end():] != keys[1][second_origin.end():]:
        raise ValueError("candidate must change only the second key's origin fingerprint")
    candidate_keys = [keys[0], replacement, keys[2]]
    candidate_policy = f"multi_a(3,{','.join(candidate_keys)})"
    candidate = original.replace(source_policy, candidate_policy, 1)
    if candidate.replace(candidate_policy, source_policy, 1) != original:
        raise ValueError("candidate must preserve all descriptor content outside the selected origin")
    if candidate.count("and_v(v:multi_a(2,") != 1 or "older(26352)" not in candidate:
        raise ValueError("recovery policy and timelock must remain unchanged")
    candidate_primary_origins = [re.match(r"^\[([0-9a-fA-F]{8})\]", key) for key in candidate_keys]
    candidate_fingerprints = [origin.group(1).lower() for origin in candidate_primary_origins if origin]
    if candidate_fingerprints != ["4ba43603", "4ba43603", "56c4fac3"]:
        raise ValueError("candidate must duplicate the primary origin fingerprint exactly once")
    return candidate


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json OUTPUT_DESCRIPTOR_BODY.txt")
    source_path, output_path = map(Path, sys.argv[1:])
    output_path.write_text(build_input(source_path) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
