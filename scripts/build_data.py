#!/usr/bin/env python3
"""Build a compact dataset for the ATT&CK Analysis Workbench from the MITRE
ATT&CK Enterprise STIX bundle.

Extracts tactics, techniques, groups, software, campaigns, mitigations and
the relationships between them.

Usage:
    python3 scripts/build_data.py path/to/enterprise-attack.json

Download the bundle from:
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

Output: data/attack-data.json and public/data/attack-data.json
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
MD_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")


def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def is_active(obj):
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def clean_desc(text, limit=None):
    """First paragraph, citations and markdown links stripped."""
    para = (text or "").split("\n")[0].strip()
    para = CITATION.sub("", para)
    para = MD_LINK.sub(r"\1", para)
    if limit and len(para) > limit:
        para = para[: limit - 1].rsplit(" ", 1)[0] + "…"
    return para


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)

    bundle = json.loads(Path(sys.argv[1]).read_text())
    objects = bundle["objects"]

    # stix id -> (attack id, bucket)
    stix_index = {}
    tactics_by_stix = {}
    techniques, groups, software, campaigns, mitigations = {}, {}, {}, {}, {}
    strategies_by_stix, analytics_by_stix = {}, {}
    logsource_index = {}  # "name" -> int index into the logsources catalog

    def logsource_id(name):
        if name not in logsource_index:
            logsource_index[name] = len(logsource_index)
        return logsource_index[name]

    for obj in objects:
        if not is_active(obj):
            continue
        t = obj["type"]
        eid = external_id(obj)
        if not eid:
            continue

        if t == "x-mitre-tactic":
            tactics_by_stix[obj["id"]] = {
                "id": eid,
                "name": obj["name"],
                "shortname": obj["x_mitre_shortname"],
            }
        elif t == "attack-pattern":
            techniques[eid] = {
                "name": obj["name"],
                "desc": clean_desc(obj.get("description"), 320),
                "tactics": [
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ],
                "sub": obj.get("x_mitre_is_subtechnique", False),
            }
            stix_index[obj["id"]] = (eid, "technique")
        elif t == "intrusion-set":
            groups[eid] = {
                "name": obj["name"],
                "aliases": [a for a in obj.get("aliases", []) if a != obj["name"]],
                "desc": clean_desc(obj.get("description")),
                "techniques": set(),
                "software": set(),
            }
            stix_index[obj["id"]] = (eid, "group")
        elif t in ("malware", "tool"):
            software[eid] = {
                "name": obj["name"],
                "type": t,
                "aliases": [
                    a for a in obj.get("x_mitre_aliases", []) if a != obj["name"]
                ],
                "desc": clean_desc(obj.get("description")),
                "techniques": set(),
            }
            stix_index[obj["id"]] = (eid, "software")
        elif t == "campaign":
            campaigns[eid] = {
                "name": obj["name"],
                "aliases": [a for a in obj.get("aliases", []) if a != obj["name"]],
                "desc": clean_desc(obj.get("description")),
                "first_seen": (obj.get("first_seen") or "")[:7],
                "last_seen": (obj.get("last_seen") or "")[:7],
                "techniques": set(),
                "software": set(),
                "groups": set(),
            }
            stix_index[obj["id"]] = (eid, "campaign")
        elif t == "x-mitre-detection-strategy":
            strategies_by_stix[obj["id"]] = {
                "id": eid,
                "name": obj["name"],
                "analytic_refs": obj.get("x_mitre_analytic_refs", []),
            }
        elif t == "x-mitre-analytic":
            analytics_by_stix[obj["id"]] = {
                "id": eid,
                "desc": clean_desc(obj.get("description"), 340),
                "platforms": obj.get("x_mitre_platforms", []),
                "logs": [
                    [logsource_id(ref["name"]), (ref.get("channel") or "")[:90]]
                    for ref in obj.get("x_mitre_log_source_references", [])
                    if ref.get("name")
                ],
                "tuning": [
                    m["field"] for m in obj.get("x_mitre_mutable_elements", [])
                    if m.get("field")
                ],
            }
        elif t == "course-of-action":
            mitigations[eid] = {
                "name": obj["name"],
                "desc": clean_desc(obj.get("description")),
                "techniques": set(),
            }
            stix_index[obj["id"]] = (eid, "mitigation")

    # Tactic display order comes from the matrix object.
    tactic_order = []
    for obj in objects:
        if obj["type"] == "x-mitre-matrix" and is_active(obj):
            tactic_order = [
                tactics_by_stix[ref]
                for ref in obj.get("tactic_refs", [])
                if ref in tactics_by_stix
            ]
            break

    # Relationships.
    detections = {}  # technique attack id -> {det, detName, analytics: [...]}
    for obj in objects:
        if obj["type"] != "relationship" or not is_active(obj):
            continue
        rel = obj.get("relationship_type")

        # detects: detection-strategy -> attack-pattern
        if rel == "detects":
            strat = strategies_by_stix.get(obj.get("source_ref"))
            tgt = stix_index.get(obj.get("target_ref"))
            if strat and tgt and tgt[1] == "technique":
                detections[tgt[0]] = {
                    "det": strat["id"],
                    "detName": strat["name"],
                    "analytics": [
                        analytics_by_stix[ref]
                        for ref in strat["analytic_refs"]
                        if ref in analytics_by_stix
                    ],
                }
            continue

        src = stix_index.get(obj.get("source_ref"))
        dst = stix_index.get(obj.get("target_ref"))
        if not src or not dst:
            continue
        (sid, skind), (did, dkind) = src, dst

        if rel == "uses":
            if skind == "group" and dkind == "technique":
                groups[sid]["techniques"].add(did)
            elif skind == "group" and dkind == "software":
                groups[sid]["software"].add(did)
            elif skind == "software" and dkind == "technique":
                software[sid]["techniques"].add(did)
            elif skind == "campaign" and dkind == "technique":
                campaigns[sid]["techniques"].add(did)
            elif skind == "campaign" and dkind == "software":
                campaigns[sid]["software"].add(did)
        elif rel == "attributed-to" and skind == "campaign" and dkind == "group":
            campaigns[sid]["groups"].add(did)
        elif rel == "mitigates" and skind == "mitigation" and dkind == "technique":
            mitigations[sid]["techniques"].add(did)

    def finalize(bucket):
        return {
            eid: {
                k: sorted(v) if isinstance(v, set) else v
                for k, v in obj.items()
            }
            for eid, obj in sorted(bucket.items())
        }

    version = next(
        (o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"),
        None,
    )

    out = {
        "attackVersion": version,
        "tactics": tactic_order,
        "techniques": finalize(techniques),
        "groups": finalize(groups),
        "software": finalize(software),
        "campaigns": finalize(campaigns),
        "mitigations": finalize(mitigations),
        "logsources": [
            name for name, _ in sorted(logsource_index.items(), key=lambda kv: kv[1])
        ],
        "detections": dict(sorted(detections.items())),
    }

    repo_root = Path(__file__).resolve().parent.parent
    payload = json.dumps(out, separators=(",", ":"))
    destinations = [
        repo_root / "data" / "attack-data.json",
        repo_root / "public" / "data" / "attack-data.json",
    ]
    for dest in destinations:
        dest.parent.mkdir(exist_ok=True)
        dest.write_text(payload)
    size_kb = destinations[0].stat().st_size // 1024
    print(
        f"Wrote {', '.join(str(dest) for dest in destinations)} ({size_kb} KB) — ATT&CK v{version}: "
        f"{len(tactic_order)} tactics, {len(techniques)} techniques, "
        f"{len(groups)} groups, {len(software)} software, "
        f"{len(campaigns)} campaigns, {len(mitigations)} mitigations, "
        f"{len(detections)} detection strategies "
        f"({sum(len(d['analytics']) for d in detections.values())} analytics, "
        f"{len(logsource_index)} log sources)"
    )


if __name__ == "__main__":
    main()
