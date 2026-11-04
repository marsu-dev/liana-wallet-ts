#!/usr/bin/env python3
"""Add a primary key leaf sharing the internal signer's fingerprint on a distinct xpub."""
import json
import re
import sys
from pathlib import Path

LIANA_COMMIT = "398e622596e7530a328de3027cb2c09905f708c6"
MINISCRIPT_VERSION = "11.2.0"
RUSTC = "1.80.0 (051478957 2024-07-21)"
SOURCE_ID = "liana-v9-rust-signet-single-primary-recovery-vectors"
INTERNAL_FINGERPRINT = "07fd816d"
RECOVERY_FINGERPRINT = "da855a1f"
MULTIPATH_SUFFIX = "/<0;1>/*"


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
    original = source.get("multipathDescriptorBody", "")
    if not original.startswith("tr(") or original.count(",and_v(") != 1:
        raise ValueError("expected one Taproot internal key and one source recovery leaf")
    internal_end = original.index(",", len("tr("))
    internal = original[len("tr("):internal_end]
    if not internal.startswith(f"[{INTERNAL_FINGERPRINT}/") or internal.count(MULTIPATH_SUFFIX) != 1:
        raise ValueError("source internal signer must be the pinned multipath xpub")
    recovery = original[internal_end + 1:-1]
    if not recovery.startswith("and_v(v:pk(") or not recovery.endswith(")"):
        raise ValueError("source recovery leaf must be the pinned key-and-older form")
    recovery_key = recovery[len("and_v(v:pk("):-len("),older(36))")]
    origin = re.match(r"^\[([0-9a-fA-F]{8})/", recovery_key)
    if origin is None or origin.group(1).lower() != RECOVERY_FINGERPRINT:
        raise ValueError("source recovery key origin does not match pinned Signet fixture")
    if recovery_key.count(MULTIPATH_SUFFIX) != 1:
        raise ValueError("source recovery signer must retain the two-choice multipath suffix")
    primary_key = recovery_key.replace(f"[{RECOVERY_FINGERPRINT}/", f"[{INTERNAL_FINGERPRINT}/", 1)
    primary_key = primary_key.replace(MULTIPATH_SUFFIX, f"/0{MULTIPATH_SUFFIX}", 1)
    if primary_key == recovery_key or primary_key.replace(f"[{INTERNAL_FINGERPRINT}/", f"[{RECOVERY_FINGERPRINT}/", 1).replace("/0" + MULTIPATH_SUFFIX, MULTIPATH_SUFFIX, 1) != recovery_key:
        raise ValueError("new primary leaf must change only fingerprint and add its /0/ branch")
    if primary_key.split("]", 1)[1].split("/", 1)[0] != recovery_key.split("]", 1)[1].split("/", 1)[0]:
        raise ValueError("primary leaf must reuse the recovery xpub")
    internal_xpub = internal.split("]", 1)[1].split("/", 1)[0]
    primary_xpub = primary_key.split("]", 1)[1].split("/", 1)[0]
    if internal_xpub == primary_xpub:
        raise ValueError("primary leaf and internal signer must use distinct xpubs")
    candidate = f"tr({internal},{{pk({primary_key}),{recovery}}})"
    if candidate.replace(f"{{pk({primary_key}),", "", 1).replace("}", "", 1) != original:
        raise ValueError("candidate must add only the checked primary key leaf")
    if candidate.count(f"[{INTERNAL_FINGERPRINT}/") < 2 or "older(36)" not in candidate:
        raise ValueError("candidate must duplicate the internal origin only in primary and preserve recovery timelock")
    return candidate


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} SOURCE_FIXTURE.json OUTPUT_DESCRIPTOR_BODY.txt")
    source_path, output_path = map(Path, sys.argv[1:])
    output_path.write_text(build_input(source_path) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
