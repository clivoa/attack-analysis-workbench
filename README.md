# ATT&CK Analysis Workbench

An interactive analysis workbench for [MITRE ATT&CK®](https://attack.mitre.org/) Enterprise. Explore the relationships between threat groups, software, techniques, tactics, campaigns and mitigations — then build a **threat profile** and turn it into actionable outputs: a technique heatmap, a prioritized detection-engineering worklist, and a mitigation investment ranking. Import your **deployed detection rules** to run a three-layer gap analysis (threat × telemetry × rules) and get **SigmaHQ rule suggestions** for the gaps. Fully static site: no backend, built with Vite for GitHub Pages.

> Not related to MITRE's own [ATT&CK Workbench](https://github.com/mitre-attack/attack-workbench-frontend) (a tool for editing ATT&CK datasets). This project consumes the official dataset for SOC / detection engineering / CTI analysis.

## Who is it for

- **CTI analysts** — actor dossiers, ecosystem graphs, technique-overlap peer analysis, combined footprints, Navigator layer exports.
- **Detection engineers** — a scored worklist of what to detect and why, visibility verdicts against your real telemetry, rule-coverage gap analysis against your imported rule inventory, SigmaHQ rule suggestions per technique, per-technique detection cards with MITRE analytics, exportable detection plans.
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
3. **Matrix** — the ATT&CK matrix as a heatmap. Cell intensity shows how many profile entities use each technique (or global group usage when the profile is empty). Toggle sub-techniques, filter to profile-only, overlay your **rule coverage** (green outline = covered by an imported rule, dashed red = used by the profile but no rule), and **export as an ATT&CK Navigator layer**.
4. **Detection Designer** — the detection-engineering workbench (see below).
5. **Defense Planner** — mitigations ranked by weighted coverage of your profile's techniques: which single control blunts the most of what these actors actually do. Also surfaces the profile's most-used techniques and its **blind spots** (techniques with no mapped mitigation).

Deep links work: `#matrix`, `#detect`, `#defense`, any ATT&CK ID (`#G0016`, `#T1055.001`), or a detection card directly (`#detect=T1053.005`).

## Detection Designer (SOC / detection engineering / CTI)

Answers *what should we detect* and *why*:

- **Prioritized worklist** — every technique in scope (threat profile, or all groups) ranked by a transparent score: **threat** (usage by your profiled actors, 0–50) + **prevalence** (global group usage, log-scaled, 0–30) + **exposure** (+20 when ATT&CK maps no mitigation, i.e. detection is the only control).
- **Telemetry profile** — tick the log sources your SOC actually ingests (266 sources from ATT&CK's analytics corpus, grouped by product, with presets for Windows/Linux/macOS/Cloud/Network). Each technique gets a **Full / Partial / Blind** visibility verdict computed against it, plus an overall visibility percentage.
- **Detection cards** per technique — *Why detect this* (CTI context: profiled actors, global actor count, campaigns), *What to collect* (channel-level log sources, ✓/✗ against your telemetry), *Detection use-cases* (ATT&CK v18+ analytics: behavior description, platforms, required log sources, tuning knobs).
- **Rule inventory & gap analysis** — import the detection rules you actually have deployed (see formats below). Every technique in the worklist gets a **✓ rule / no rule** verdict, the summary shows your **rule coverage %** and the count of **gaps ready to close** (no rule, but telemetry already available — the cheapest wins), and a dedicated filter isolates covered / uncovered / actionable-gap techniques. Coverage rolls up across the hierarchy: a rule tagged with a sub-technique counts toward its parent, and a parent-level rule covers its sub-techniques (marked *via TXXXX*).
- **SigmaHQ rule suggestions** — each detection card lists the top public [SigmaHQ](https://github.com/SigmaHQ/sigma) rules for that technique (stable/critical first, linked to GitHub), from a bundled index of ~2,800 ATT&CK-tagged rules across ~390 techniques. Sub-techniques with no rules of their own fall back to the parent technique.
- **Backlog tracking** — mark techniques To review / Planned / Implemented / N-A (persisted locally); summary cards show backlog progress at a glance.
- **Exports** — full detection plan as **Markdown** (for wikis/tickets) or **JSON** (machine-readable backlog: scores, visibility, rule coverage, required log sources, analytic IDs), plus per-technique card copy.

### Importing your rules

**Detection Designer → Your detection rules → Import rules…** (multiple files allowed, stored only in your browser). Supported formats:

| Format | How techniques are matched |
|---|---|
| **Sigma YAML** (`.yml`/`.yaml`) | `title:`, `status:` and `attack.tXXXX` entries under `tags:` — the same convention SigmaHQ uses |
| **CSV** (`.csv`) | header row with a name column (`name`/`title`/`rule`), a technique column (`technique`/`attack`/`mitre`/`tid` — any cell text containing `T####`/`T####.###` IDs) and an optional `status` column |
| **JSON** (`.json`) | an array of objects with `name`/`title` + `techniques`/`technique`/`attack` (string or array) + optional `status`/`enabled` |
| **ATT&CK Navigator layer** (`.json`) | each `techniqueID` with a positive (or absent) score is marked covered, as a single inventory entry named after the layer |

Rules with status `disabled`, `deprecated`, `unsupported` or `enabled: false` are kept in the inventory but don't count toward coverage. Example CSV:

```csv
rule_name,techniques,status
Credential Dumping via LSASS,T1003.001,active
Process Injection Detector,"T1055, T1055.001",active
Scheduled Task Creation,T1053.005,disabled
```

## Running locally

Install dependencies and run the Vite dev server:

```bash
git clone https://github.com/<you>/attack-analysis-workbench.git
cd attack-analysis-workbench
npm install
npm run dev
```

For a production preview, run `npm run build` followed by `npm run preview`.

## Project structure

```
attack-analysis-workbench/
├── src/
│   ├── index.html          # single page: topbar, tabs, the four views, side panel
│   ├── main.js             # Vite entrypoint
│   ├── css/style.css       # all styling (dark + light themes)
│   └── js/
│       ├── app.js          # state (S), data load, indexes, search, threat profile, tabs, deep links
│       ├── graph.js        # Explore: expandable D3 force-directed relationship graph
│       ├── matrix.js       # Matrix: tactics x techniques heatmap + Navigator layer export
│       ├── detect.js       # Detection Designer: scoring, telemetry model, cards, backlog, exports
│       ├── rules.js        # rule inventory: Sigma/CSV/JSON import, coverage layer, SigmaHQ suggestions
│       ├── defense.js      # Defense Planner: mitigation ranking, blind spots
│       ├── panel.js        # universal entity detail panel with cross-navigation
│       └── tour.js         # guided tours: engine + persona walkthrough definitions
├── public/data/            # attack-data.json + sigma-index.json copied into the production build
├── data/                   # source copies of the compact datasets
├── vite.config.js          # GitHub Pages base path and build settings
└── scripts/
    ├── build_data.py       # regenerates attack-data.json from enterprise-attack.json
    └── build_sigma_index.py # regenerates sigma-index.json from the SigmaHQ repo
```

All user state (threat profile, telemetry, rule inventory, detection backlog, theme, tour flag) lives in `localStorage` — nothing leaves the browser.

## Updating the data

The site ships with a compact snapshot generated from the official ATT&CK STIX bundle. To refresh it:

```bash
curl -LO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
python3 scripts/build_data.py enterprise-attack.json
```

The script updates both `data/attack-data.json` and `public/data/attack-data.json`.

The script extracts active (non-revoked, non-deprecated) tactics, techniques, groups, software, campaigns and mitigations, plus the `uses`, `attributed-to`, `mitigates` and `detects` relationships between them. From the ATT&CK v18+ detection model it also extracts detection strategies, analytics (description, platforms, channel-level log source references, mutable/tuning elements) and a normalized log-source catalog.

The SigmaHQ suggestion index is refreshed the same way, from a checkout or tarball of the [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) repository:

```bash
curl -sL -o sigma.tar.gz https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz
mkdir sigma-master && tar xzf sigma.tar.gz -C sigma-master --strip-components=1
python3 scripts/build_sigma_index.py sigma-master
```

It parses every rule under `rules/`, keeps title, level, status and the `attack.tXXXX` tags, and writes an inverted technique → rules index to `data/sigma-index.json` and `public/data/sigma-index.json` (rules sorted stable-before-experimental, critical-before-low).

## Deploying to GitHub Pages

GitHub Pages must use **GitHub Actions**, not "Deploy from a branch". The workflow in `.github/workflows/deploy.yml` builds the Vite app into `dist/` and deploys that artifact.

In the repository settings, go to **Settings → Pages → Build and deployment → Source** and select **GitHub Actions**. After pushing to `main`, the site will be served at `https://<you>.github.io/attack-analysis-workbench/`.

## Stack

- [D3.js v7](https://d3js.org/) (force simulation, zoom, drag)
- Vite
- Vanilla JS / CSS — no framework

## License & attribution

ATT&CK data © The MITRE Corporation, used under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). This project is not affiliated with or endorsed by MITRE.
