#!/usr/bin/env python3
"""Vygeneruje THIRD-PARTY-LICENSES.txt pro crates, které jsou zkompilované do binárky cdctl.

MIT, Apache-2.0, ISC, BSD i další licence vyžadují, aby se s binárkou šířily jejich texty
a copyright. Skript projde strom závislostí pro cílovou platformu, najde licenční soubory
v rozbalených zdrojích (~/.cargo/registry) a identické texty seskupí.

Použití: scripts/third_party_licenses.py [--target x86_64-unknown-linux-musl] [-o soubor]
Exit 1, pokud některý crate nemá ani licenční soubor, ani SPDX licenci.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

LICENSE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|COPYRIGHT|UNLICENSE)([-_.].*)?$", re.I)


def cargo(*args):
    return subprocess.run(["cargo", *args], check=True, capture_output=True, text=True).stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="x86_64-unknown-linux-musl")
    ap.add_argument("--features", default="cli")
    ap.add_argument("-o", "--output", default="THIRD-PARTY-LICENSES.txt")
    a = ap.parse_args()

    meta = json.loads(cargo("metadata", "--format-version", "1", "--features", a.features,
                            "--filter-platform", a.target))
    root = meta["resolve"]["root"]
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}

    # Projdi jen „normal“ závislosti (ne dev/build); proc-macro crates do binárky nejdou.
    seen, stack = set(), [root]
    while stack:
        nid = stack.pop()
        for dep in nodes[nid]["deps"]:
            kinds = {k["kind"] for k in dep["dep_kinds"]}
            if None not in kinds:  # None = normal
                continue
            if dep["pkg"] not in seen:
                seen.add(dep["pkg"])
                stack.append(dep["pkg"])

    # Přesná množina podle `cargo tree` (metadata sjednocuje featury i s dev-závislostmi).
    tree = cargo("tree", "-e", "normal", "--target", a.target, "--features", a.features,
                 "--prefix", "none", "--format", "{p}")
    in_binary = {tuple(line.split()[:2]) for line in tree.splitlines() if line.strip()}

    crates = []
    for pid in seen:
        p = pkgs[pid]
        if any("proc-macro" in t["kind"] for t in p["targets"]):
            continue
        if (p["name"], "v" + p["version"]) not in in_binary:
            continue
        crates.append(p)
    crates.sort(key=lambda p: (p["name"], p["version"]))

    groups, missing, rows = {}, [], []
    for p in crates:
        d = os.path.dirname(p["manifest_path"])
        files = sorted(f for f in os.listdir(d) if LICENSE_FILE.match(f) and os.path.isfile(os.path.join(d, f)))
        if p.get("license_file"):
            lf = os.path.join(d, p["license_file"])
            if os.path.isfile(lf) and os.path.basename(lf) not in files:
                files.append(os.path.relpath(lf, d))
        ident = f'{p["name"]} {p["version"]}'
        rows.append((ident, p.get("license") or "(see file)", p.get("repository") or ""))
        if not files:
            if not p.get("license"):
                missing.append(ident)
            groups.setdefault(("spdx", p["license"]), []).append(ident)
            continue
        for f in files:
            text = open(os.path.join(d, f), encoding="utf-8", errors="replace").read().strip()
            key = hashlib.sha256(text.encode()).hexdigest()
            groups.setdefault(("text", key, text), []).append(f"{ident} ({f})")

    out = []
    out.append("THIRD-PARTY SOFTWARE NOTICES AND LICENSES")
    out.append(f"cdctl includes the following {len(crates)} Rust crates (target {a.target}).\n")
    w = max(len(r[0]) for r in rows)
    for ident, lic, repo in rows:
        out.append(f"  {ident:<{w}}  {lic:<35} {repo}")
    out.append("")
    for key, users in sorted(groups.items(), key=lambda kv: kv[1][0]):
        out.append("=" * 78)
        out.append("Used by: " + ", ".join(users))
        out.append("-" * 78)
        if key[0] == "spdx":
            out.append(f"Licensed under {key[1]} (no license file shipped in the crate; "
                       "see https://spdx.org/licenses/).")
        else:
            out.append(key[2])
        out.append("")
    with open(a.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    print(f"{a.output}: {len(crates)} crates, {len(groups)} distinct license texts", file=sys.stderr)
    if missing:
        print("crates without any license information: " + ", ".join(missing), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
