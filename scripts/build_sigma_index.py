#!/usr/bin/env python3
"""Build a technique -> public Sigma rules index for the ATT&CK Analysis
Workbench from the SigmaHQ/sigma repository.

For every rule under rules/ it extracts the title, level, status and the
MITRE ATT&CK technique tags (attack.tXXXX), then inverts that into a
per-technique index used by the Detection Designer to suggest open-source
rules for uncovered techniques.

Usage:
    # from a local checkout or an extracted tarball
    python3 scripts/build_sigma_index.py path/to/sigma-repo

    # tarball straight from GitHub
    curl -sL -o sigma.tar.gz https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz
    mkdir sigma-master && tar xzf sigma.tar.gz -C sigma-master --strip-components=1
    python3 scripts/build_sigma_index.py sigma-master

Output: data/sigma-index.json and public/data/sigma-index.json

Each entry is [path, title, level, status] where path is relative to the
repository root (rule URL = https://github.com/SigmaHQ/sigma/blob/master/<path>).
"""
import json
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

TECH_TAG = re.compile(r"^\s*-\s+attack\.(t\d{4}(?:\.\d{3})?)\s*$", re.IGNORECASE)
FIELD = re.compile(r"^(title|level|status):\s*(.+?)\s*$")

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
STATUS_ORDER = {"stable": 0, "test": 1, "experimental": 2}


def parse_rule(path):
    """Cheap line-level parse — enough for title/level/status/attack tags,
    avoids a YAML dependency."""
    title = level = status = None
    techniques = []
    in_tags = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith(" "):
            in_tags = line.startswith("tags:")
            m = FIELD.match(line)
            if m:
                val = m.group(2).strip("'\"")
                if m.group(1) == "title" and title is None:
                    title = val
                elif m.group(1) == "level" and level is None:
                    level = val
                elif m.group(1) == "status" and status is None:
                    status = val
            continue
        if in_tags:
            m = TECH_TAG.match(line)
            if m:
                techniques.append(m.group(1).upper())
    return title, level, status, techniques


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    repo = Path(sys.argv[1])
    rules_dir = repo / "rules"
    if not rules_dir.is_dir():
        sys.exit(f"error: {rules_dir} not found — pass the SigmaHQ repo root")

    index = defaultdict(list)
    rule_count = 0
    for path in sorted(rules_dir.rglob("*.yml")):
        title, level, status, techniques = parse_rule(path)
        if not title or not techniques:
            continue
        rule_count += 1
        rel = str(path.relative_to(repo))
        for tid in set(techniques):
            index[tid].append([rel, title, level or "", status or ""])

    # Best rules first: stable before experimental, critical before low.
    for entries in index.values():
        entries.sort(key=lambda e: (
            STATUS_ORDER.get(e[3], 9),
            LEVEL_ORDER.get(e[2], 9),
            e[1].lower(),
        ))

    out = {
        "generated": date.today().isoformat(),
        "source": "https://github.com/SigmaHQ/sigma",
        "ruleCount": rule_count,
        "techniques": dict(sorted(index.items())),
    }

    repo_root = Path(__file__).resolve().parent.parent
    payload = json.dumps(out, separators=(",", ":"))
    destinations = [
        repo_root / "data" / "sigma-index.json",
        repo_root / "public" / "data" / "sigma-index.json",
    ]
    for dest in destinations:
        dest.parent.mkdir(exist_ok=True)
        dest.write_text(payload)
    size_kb = destinations[0].stat().st_size // 1024
    print(
        f"Wrote {', '.join(str(d) for d in destinations)} ({size_kb} KB) — "
        f"{rule_count} Sigma rules with ATT&CK tags across {len(index)} techniques"
    )


if __name__ == "__main__":
    main()
