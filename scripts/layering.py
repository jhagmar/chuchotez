#!/usr/bin/env python3
"""Fail if the domain crate takes third-party deps or host IO."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"
DOMAIN = ("chuchotez-domain",)
FORBIDDEN_SOURCE = re.compile(
    r"\bstd::(fs|net|os|process|thread|env)\b|\bSystemTime\b|\bInstant\b"
)


def cargo_toml_deps(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    deps: list[str] = []
    in_deps = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            in_deps = line in (
                "[dependencies]",
                "[dev-dependencies]",
                "[build-dependencies]",
            )
            continue
        if in_deps:
            name = line.split("=", 1)[0].strip()
            if name:
                deps.append(name)
    return deps


def main() -> int:
    failed = False
    for name in DOMAIN:
        crate = CRATES / name
        toml_path = crate / "Cargo.toml"
        if not toml_path.is_file():
            print(f"{toml_path} is missing", file=sys.stderr)
            failed = True
            continue
        deps = cargo_toml_deps(toml_path)
        if deps:
            print(f"{name} has dependencies: {', '.join(deps)}", file=sys.stderr)
            failed = True
        src = crate / "src"
        for rs in sorted(src.rglob("*.rs")):
            text = rs.read_text(encoding="utf-8")
            if FORBIDDEN_SOURCE.search(text):
                print(f"{rs.relative_to(ROOT)} uses host IO", file=sys.stderr)
                failed = True
    if failed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
