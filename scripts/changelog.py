#!/usr/bin/env python3
"""Práce s CHANGELOG.md.

  scripts/changelog.py check              – kontrola formátu a toho, že verze z Cargo.toml má záznam
  scripts/changelog.py section 0.3.1      – vypíše text sekce (popis GitHub Release)
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADING = re.compile(r"^## \[(?P<ver>[^\]]+)\](?: - (?P<date>\d{4}-\d{2}-\d{2}))?\s*$")


def sections(text):
    """[(verze, datum, tělo)] v pořadí výskytu."""
    out, cur = [], None
    for line in text.splitlines():
        m = HEADING.match(line)
        if m:
            cur = [m["ver"], m["date"], []]
            out.append(cur)
        elif line.startswith("[") and "]: http" in line:
            cur = None  # odkazy na konci souboru
        elif cur is not None:
            cur[2].append(line)
    return [(v, d, "\n".join(b).strip()) for v, d, b in out]


def cargo_version():
    m = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M)
    return m[1]


def semver_key(v):
    return tuple(int(x) for x in re.findall(r"\d+", v.split("-")[0])[:3])


def check(text):
    errors = []
    secs = sections(text)
    names = [s[0] for s in secs]
    if not names or names[0] != "Unreleased":
        errors.append("the first section must be ## [Unreleased]")
    versions = [s for s in secs if s[0] != "Unreleased"]
    for ver, date, body in versions:
        if not re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?", ver):
            errors.append(f"[{ver}] is not a semantic version")
        if not date:
            errors.append(f"[{ver}] has no date (## [{ver}] - YYYY-MM-DD)")
        if not body:
            errors.append(f"[{ver}] is empty")
        if f"[{ver}]: http" not in text:
            errors.append(f"missing link reference [{ver}]: https://…")
    keys = [semver_key(v) for v, _, _ in versions]
    if keys != sorted(keys, reverse=True):
        errors.append("versions are not in descending order")
    if len(set(names)) != len(names):
        errors.append("duplicate section")
    cv = cargo_version()
    if cv not in names:
        errors.append(f"Cargo.toml version {cv} has no ## [{cv}] section")
    return errors


def main():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if len(sys.argv) >= 2 and sys.argv[1] == "check":
        errors = check(text)
        for e in errors:
            print(f"CHANGELOG.md: {e}", file=sys.stderr)
        if not errors:
            print(f"CHANGELOG.md OK (Cargo.toml version {cargo_version()} documented)")
        sys.exit(1 if errors else 0)
    if len(sys.argv) == 3 and sys.argv[1] == "section":
        ver = sys.argv[2].removeprefix("v")
        for v, _, body in sections(text):
            if v == ver and body:
                print(body)
                return
        print(f"CHANGELOG.md has no non-empty section for {ver}", file=sys.stderr)
        sys.exit(1)
    print(__doc__, file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
