# ATT&CK Analysis Workbench

An interactive analysis workbench for [MITRE ATT&CK®](https://attack.mitre.org/) Enterprise. Explore the relationships between threat groups, software, techniques, tactics, campaigns and mitigations — then build a **threat profile** and turn it into actionable outputs: a technique heatmap, a prioritized detection-engineering worklist, and a mitigation investment ranking. Fully static site: no backend, no build step, ready for GitHub Pages.

> Not related to MITRE's own [ATT&CK Workbench](https://github.com/mitre-attack/attack-workbench-frontend) (a tool for editing ATT&CK datasets). This project consumes the official dataset for SOC / detection engineering / CTI analysis.

## Who is it for

- **CTI analysts** — actor dossiers, ecosystem graphs, technique-overlap peer analysis, combined footprints, Navigator layer exports.
- **Detection engineers** — a scored worklist of what to detect and why, visibility verdicts against your real telemetry, per-technique detection cards with MITRE analytics, exportable detection plans.
- **SOC leads** — coverage KPIs, mitigation ROI ranking, blind-spot lists, exec-ready artifacts.

## Take a tour

First visit opens a tour launcher (also available anytime via the **✦ Tour** button). Four interactive, role-based walkthroughs stage a live example (APT29 + Lazarus Group) inside the app, spotlight each control, and offer to restore your own data at the end:

- **Platform overview** (~2 min) — views, search, threat profile, detail panel.
- **CTI Analyst** (~4 min) — actor dossiers, ecosystem graph, combined footprint, Navigator export.
- **Detection Engineer** (~5 min) — telemetry declaration, priority scoring, detection cards, backlog, plan export.
- **SOC Lead** (~3 min) — coverage KPIs, mitigation ROI, blind spots, exec reporting.

Tours are deep-linkable too: `#tour=cti`, `#tour=engineer`, `#tour=soc` (optionally with a step, e.g. `#tour=engineer:6`).

## The workflow

1. **Explore** — an expandable relationship graph. Search for any entity (group, malware, technique, campaign, mitigation), add it to the canvas, and double-click nodes to expand their relationships: who uses what, which campaigns deployed which malware, what mitigates what.
2. **Build a threat profile** — from any group/software/campaign panel, click *＋ Threat profile*. The profile (persisted in your browser) represents the adversaries you care about.
3. **Matrix** — the ATT&CK matrix as a heatmap. Cell intensity shows how many profile entities use each technique (or global group usage when the profile is empty). Toggle sub-techniques, filter to profile-only, and **export as an ATT&CK Navigator layer**.
4. **Detection Designer** — the detection-engineering workbench (see below).
5. **Defense Planner** — mitigations ranked by weighted coverage of your profile's techniques: which single control blunts the most of what these actors actually do. Also surfaces the profile's most-used techniques and its **blind spots** (techniques with no mapped mitigation).

Deep links work: `#matrix`, `#detect`, `#defense`, any ATT&CK ID (`#G0016`, `#T1055.001`), or a detection card directly (`#detect=T1053.005`).

## Detection Designer (SOC / detection engineering / CTI)

Answers *what should we detect* and *why*:

- **Prioritized worklist** — every technique in scope (threat profile, or all groups) ranked by a transparent score: **threat** (usage by your profiled actors, 0–50) + **prevalence** (global group usage, log-scaled, 0–30) + **exposure** (+20 when ATT&CK maps no mitigation, i.e. detection is the only control).
- **Telemetry profile** — tick the log sources your SOC actually ingests (266 sources from ATT&CK's analytics corpus, grouped by product, with presets for Windows/Linux/macOS/Cloud/Network). Each technique gets a **Full / Partial / Blind** visibility verdict computed against it, plus an overall visibility percentage.
- **Detection cards** per technique — *Why detect this* (CTI context: profiled actors, global actor count, campaigns), *What to collect* (channel-level log sources, ✓/✗ against your telemetry), *Detection use-cases* (ATT&CK v18+ analytics: behavior description, platforms, required log sources, tuning knobs).
- **Backlog tracking** — mark techniques To review / Planned / Implemented / N-A (persisted locally); summary cards show rule coverage at a glance.
- **Exports** — full detection plan as **Markdown** (for wikis/tickets) or **JSON** (machine-readable backlog: scores, visibility, required log sources, analytic IDs), plus per-technique card copy.

## Running locally

Any static file server works:

```bash
git clone https://github.com/<you>/attack-analysis-workbench.git
cd attack-analysis-workbench
python3 -m http.server 8000
# open http://localhost:8000
```

## Project structure

```
attack-analysis-workbench/
├── index.html              # single page: topbar, tabs, the four views, side panel
├── css/style.css           # all styling (dark theme, no framework)
├── js/
│   ├── app.js              # state (S), data load, indexes, search, threat profile, tabs, deep links
│   ├── graph.js            # Explore: expandable D3 force-directed relationship graph
│   ├── matrix.js           # Matrix: tactics × techniques heatmap + Navigator layer export
│   ├── detect.js           # Detection Designer: scoring, telemetry model, cards, backlog, exports
│   ├── defense.js          # Defense Planner: mitigation ranking, blind spots
│   ├── panel.js            # universal entity detail panel with cross-navigation
│   └── tour.js             # guided tours: engine + persona walkthrough definitions
├── data/attack-data.json   # compact snapshot generated from the official STIX bundle
└── scripts/build_data.py   # regenerates data/attack-data.json from enterprise-attack.json
```

All user state (threat profile, telemetry, detection backlog, tour flag) lives in `localStorage` — nothing leaves the browser.

## Updating the data

The site ships with a compact snapshot (`data/attack-data.json`) generated from the official ATT&CK STIX bundle. To refresh it:

```bash
curl -LO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
python3 scripts/build_data.py enterprise-attack.json
```

The script extracts active (non-revoked, non-deprecated) tactics, techniques, groups, software, campaigns and mitigations, plus the `uses`, `attributed-to`, `mitigates` and `detects` relationships between them. From the ATT&CK v18+ detection model it also extracts detection strategies, analytics (description, platforms, channel-level log source references, mutable/tuning elements) and a normalized log-source catalog.

## Deploying to GitHub Pages

Push the repo to GitHub, then **Settings → Pages → Deploy from a branch** (`main`, root). Done — everything is static. The site will be served at `https://<you>.github.io/attack-analysis-workbench/`.

## Stack

- [D3.js v7](https://d3js.org/) (force simulation, zoom, drag) via CDN
- Vanilla JS / CSS — no framework, no bundler

## License & attribution

ATT&CK data © The MITRE Corporation, used under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). This project is not affiliated with or endorsed by MITRE.
