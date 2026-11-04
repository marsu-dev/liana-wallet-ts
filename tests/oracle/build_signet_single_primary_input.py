#!/usr/bin/env python3
"""Create a two-choice Signet descriptor input from the preserved community fixture."""
import json
import sys
from pathlib import Path


def without_checksum(descriptor: str) -> str:
    if "#" not in descriptor:
        raise ValueError("source branch descriptor is missing its checksum")
    return descriptor.rsplit("#", 1)[0]


def combined_multipath(source_path: Path, receive_branch: int = 0, change_branch: int = 1) -> str:
    branches = (receive_branch, change_branch)
    if branches[0] == branches[1] or any(value < 0 or value >= 0x80000000 for value in branches):
        raise ValueError("multipath choices must be distinct normal child indexes")
    fixture = json.loads(source_path.read_text(encoding="utf-8"))
    receive = without_checksum(fixture["receive"]["descriptor"])
    change = without_checksum(fixture["change"]["descriptor"])
    if "<" in receive or "<" in change:
        raise ValueError("expected fixed-branch descriptors from the community fixture")
    if receive.count("/0/*") == 0 or receive.count("/0/*") != change.count("/1/*"):
        raise ValueError("receive/change signer branch counts do not match")
    choice = f"<{receive_branch};{change_branch}>"
    multipath = receive.replace("/0/*", f"/{choice}/*")
    change_as_multipath = change.replace("/1/*", f"/{choice}/*")
    if multipath != change_as_multipath:
        raise ValueError("receive and change descriptors differ beyond their branch values")
    return multipath


def main() -> None:
    if len(sys.argv) not in (3, 5):
        raise SystemExit(f"Usage: {sys.argv[0]} COMMUNITY_FIXTURE.json OUTPUT_DESCRIPTOR.txt [RECEIVE_INDEX CHANGE_INDEX]")
    source_path, output_path = map(Path, sys.argv[1:3])
    branches = (0, 1) if len(sys.argv) == 3 else tuple(map(int, sys.argv[3:5]))
    output_path.write_text(combined_multipath(source_path, *branches) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
