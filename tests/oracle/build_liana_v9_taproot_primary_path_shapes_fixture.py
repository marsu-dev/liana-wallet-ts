#!/usr/bin/env python3
"""Convert pinned Rust policy-shape probe output into a fail-closed fixture."""
import json
import sys
from pathlib import Path

SOURCE_ID = "liana-v9-rust-taproot-multisig-vectors"
CASE_ID = "multisig-one-recovery"
EXPECTED_IDS = {
    "primary-multisig-then-single-key",
    "primary-single-key-then-multisig",
    "two-primary-multisig-leaves",
    "two-primary-single-key-leaves",
}
PINNED = {
    "lianaVersion": "9.0.0",
    "lianaCommit": "398e622596e7530a328de3027cb2c09905f708c6",
    "miniscriptVersion": "11.2.0",
    "rustc": "1.80.0 (051478957 2024-07-21)",
    "network": "mainnet",
    "secretsOmitted": True,
}


def build_fixture(source_path: Path, candidates_path: Path, oracle_path: Path) -> dict:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    candidate_data = json.loads(candidates_path.read_text(encoding="utf-8"))
    if source.get("id") != SOURCE_ID or candidate_data.get("sourceFixture") != SOURCE_ID:
        raise ValueError("unexpected source fixture id")
    if candidate_data.get("sourceCase") != CASE_ID:
        raise ValueError("candidate set must derive from the pinned multisig-one-recovery case")
    if any(source.get("provenance", {}).get(key) != value for key, value in PINNED.items()):
        raise ValueError("source fixture provenance does not match the pinned Liana, Miniscript, Rust, and mainnet")
    if candidate_data.get("provenance") != PINNED:
        raise ValueError("candidate provenance must match pinned Liana, Miniscript, Rust, and mainnet")
    source_case = next((case for case in source.get("cases", []) if case.get("id") == CASE_ID), None)
    if source_case is None:
        raise ValueError("source fixture is missing the expected policy case")

    candidates = candidate_data.get("cases", [])
    ids = [case.get("id") for case in candidates]
    if len(ids) != len(EXPECTED_IDS) or set(ids) != EXPECTED_IDS:
        raise ValueError("candidate set does not contain exactly the four pinned primary-shape cases")

    records: dict[str, dict[str, str]] = {case_id: {} for case_id in EXPECTED_IDS}
    for raw in oracle_path.read_text(encoding="utf-8").splitlines():
        fields = raw.split("\t", 2)
        if len(fields) != 3 or fields[0] not in records or fields[1] in records[fields[0]]:
            raise ValueError("oracle output contains malformed, unexpected, or duplicate rows")
        records[fields[0]][fields[1]] = fields[2]

    for case in candidates:
        case_id = case["id"]
        rows = records[case_id]
        if set(rows) != {"D", "A" if case["expected"]["accepted"] else "R"}:
            raise ValueError(f"Rust must produce exactly one parsed descriptor and the expected result for {case_id}")
        body, separator, checksum = case["descriptor"].rpartition("#")
        if not separator or len(checksum) != 8 or rows["D"] != case["descriptor"]:
            raise ValueError(f"Rust-parsed descriptor/checksum mismatch for {case_id}")
        result = rows.get("A", rows.get("R"))
        expected = case["expected"]
        if expected["accepted"]:
            want = (
                f"primary=Multi({expected['primary']['threshold']},{expected['primary']['keyCount']});"
                "recovery="
                + ",".join(
                    f"{entry['older']}:Multi({entry['threshold']},{entry['keyCount']})"
                    for entry in expected["recovery"]
                )
            )
            if result != want:
                raise ValueError(f"pinned Rust policy mapping mismatch for {case_id}: {result!r}")
        elif result != expected["error"]:
            raise ValueError(f"pinned Rust rejection mismatch for {case_id}: {result!r}")

    return {
        "id": candidate_data["id"],
        "provenance": PINNED,
        "sourceFixture": SOURCE_ID,
        "sourceCase": CASE_ID,
        "purpose": "parser-derived Taproot primary-path extraction boundary cases; rejection-only vectors add no address/script pairs",
        "cases": [
            {
                "id": case["id"],
                "transformation": case["transformation"],
                "expected": case["expected"],
                "descriptor": case["descriptor"],
            }
            for case in candidates
        ],
    }


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json CANDIDATES.json ORACLE.tsv OUTPUT.json")
    source_path, candidates_path, oracle_path, fixture_path = map(Path, sys.argv[1:])
    fixture = build_fixture(source_path, candidates_path, oracle_path)
    fixture_path.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
    print(fixture_path)


if __name__ == "__main__":
    main()
