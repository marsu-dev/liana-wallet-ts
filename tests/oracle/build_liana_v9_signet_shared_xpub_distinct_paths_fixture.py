#!/usr/bin/env python3
"""Build a parser-derived positive vector for one xpub with distinct ordered paths."""
import json
import sys
from pathlib import Path

from build_liana_v9_signet_shared_xpub_distinct_paths_input import build_input
from build_liana_v9_signet_single_primary_fixture import parse_vectors

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
MINISCRIPT_VERSION = "11.2.0"
RUSTC = "1.80.0 (051478957 2024-07-21)"
SOURCE_ID = "liana-v9-rust-signet-single-primary-recovery-vectors"


def build_fixture(source_path: Path, input_path: Path, vectors_path: Path) -> dict:
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
    body = input_path.read_text(encoding="utf-8").strip()
    if body != build_input(source_path):
        raise ValueError("Rust input must equal the exact shared-xpub/distinct-path mutation")
    internal_key = body[3:body.index(",")]
    recovery_key_start = body.index("and_v(v:pk(") + len("and_v(v:pk(")
    recovery_key_end = body.index(")", recovery_key_start)
    recovery_key = body[recovery_key_start:recovery_key_end]
    if not internal_key.endswith("/<0;1>/*") or not recovery_key.endswith("/<1;0>/*"):
        raise ValueError("expected internal <0;1> and recovery <1;0> derivation tuples")
    if internal_key.removesuffix("/<0;1>/*") != recovery_key.removesuffix("/<1;0>/*"):
        raise ValueError("primary and recovery must reuse the same originated xpub with distinct ordered paths")
    return {
        "id": "liana-v9-rust-signet-shared-xpub-distinct-derivation-paths",
        "provenance": {
            "sourceFixture": SOURCE_ID,
            "source": provenance["source"],
            "lianaVersion": "9.0.0",
            "lianaCommit": LIANA_COMMIT,
            "miniscriptVersion": MINISCRIPT_VERSION,
            "rustc": RUSTC,
            "network": "signet",
            "generator": "LianaDescriptor::from_str accepts the same originated xpub with internal <0;1> and recovery <1;0> derivation paths; primary/recovery PathInfo::Single, recovery older(36), receive/change indices 0..9",
            "extendedKeySerialization": "tpub (Network::Testnet); address network Signet",
            "multipathChoices": [[0, 1], [1, 0]],
            "secretsOmitted": True,
        },
        "transformation": "recovery reuses the internal key's originated tpub but reverses its ordered derivation tuple; Liana accepts the distinct (xpub, DerivPaths) identities",
        "multipathDescriptorBody": body,
        "expected": parse_vectors(vectors_path),
    }


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json INPUT_DESCRIPTOR_BODY.txt RUST_OUTPUT.tsv OUTPUT.json")
    source_path, input_path, vectors_path, output_path = map(Path, sys.argv[1:])
    output_path.write_text(json.dumps(build_fixture(source_path, input_path, vectors_path), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
