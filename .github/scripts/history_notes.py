"""Print the HISTORY.md section for one version. Exit 2 when it is absent."""

from __future__ import annotations

import re
import sys
from pathlib import Path

_HEADING = re.compile(r"^(\d+\.\d+(?:\.\d+)?)(?:\s+\([^)]*\))?\s*$")


def section_body(text: str, version: str) -> str | None:
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        match = _HEADING.match(line)
        if match and match.group(1) == version:
            start = index
            break
    if start is None:
        return None

    body_start = start + 1
    if body_start < len(lines) and re.fullmatch(r"-+", lines[body_start]):
        body_start += 1

    body: list[str] = []
    for line in lines[body_start:]:
        if _HEADING.match(line):
            break
        body.append(line)
    notes = "\n".join(body).strip()
    return notes or None


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: history_notes.py HISTORY.md VERSION", file=sys.stderr)
        return 1
    notes = section_body(Path(sys.argv[1]).read_text(encoding="utf-8"), sys.argv[2])
    if notes is None:
        return 2
    print(notes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
