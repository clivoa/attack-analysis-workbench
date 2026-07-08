# Shared Guide — How to Use Workbench Exports

**For:** All personas (CTI, Detection Engineers, SOC Leadership)  
**Purpose:** Practical step-by-step guide to export and use threat intelligence from the Workbench  

---

## Quick Start (5 minutes)

### 1️⃣ Load a Threat Profile

```
Workbench Home → Search: "APT29"
↓
Click "✓ Threat Profile" button
↓
Profile added to bar at top
↓
Repeat for more actors/campaigns
```

### 2️⃣ Choose Your Export Format

| Goal | Format | Click |
|------|--------|-------|
| **Share with team** | Navigator Layer (JSON) | Matrix Tab → Export → Layer |
| **Detection planning** | Backlog (JSON/Markdown) | Detection Tab → Export → Backlog |
| **Report writing** | Markdown Cards | Detection Tab → Click any card |
| **Data integration** | JSON bulk export | Any Tab → Settings → Export All |

### 3️⃣ Export & Use

```
Example: Detection Engineer workflow

1. Load profile: APT29 + Lazarus
2. Set telemetry: [✓] Windows [✓] Sysmon [ ] Linux
3. Export → Backlog (JSON)
4. Open in text editor or pipe to Jira:

   cat backlog.json | jq '.techniques[] | select(.threat_score > 70)'
```

---

## Export Formats Explained

### Format 1: Navigator Layer (JSON)

**What it is:** Annotated ATT&CK matrix in JSON format

**File size:** ~50-200 KB  
**Tool:** MITRE ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/)

**Use cases:**
- ✅ Share with stakeholders (interactive visualization)
- ✅ Document threat profile (version control in git)
- ✅ Compare multiple profiles (side-by-side in Navigator)
- ✅ Team collaboration (see comments, annotations)

**Example JSON structure:**
```json
{
  "version": "4.4",
  "name": "APT29 + Lazarus Group",
  "techniques": [
    {
      "techniqueID": "T1059",
      "score": 100,
      "color": "#FF0000",
      "comment": "Critical — used by both groups"
    }
  ]
}
```

**How to use:**
```
1. Export from Workbench
2. Save as: profile-apt29-lazarus-2025.json
3. Go to: https://mitre-attack.github.io/attack-navigator/
4. Click: "New Layer" → "Import" → Select file
5. OR: Copy JSON → "New Layer" → "Import from text" → Paste
6. Share: Click "Share" button → Send link
```

---

### Format 2: Detection Backlog (JSON)

**What it is:** Prioritized list of detection engineering work items

**File size:** ~100-500 KB  
**Tool:** Any JSON parser (Jira, Excel, Python, etc.)

**Use cases:**
- ✅ Ticketing system integration (Jira, Azure DevOps)
- ✅ Prioritization algorithms (sort by threat_score)
- ✅ Tracking progress (mark status = done/in_progress)
- ✅ Automation (pipe to monitoring tools)

**Example JSON structure:**
```json
{
  "profile": "APT29 + Lazarus Group",
  "generated": "2025-07-08T14:32:00Z",
  "techniques": [
    {
      "id": "T1059.001",
      "name": "PowerShell",
      "threat_score": 98,
      "prevalence_score": 30,
      "exposure_score": 0,
      "total_score": 98,
      "visibility": "Full",
      "status": "in_progress",
      "required_log_sources": ["WinEventLog:Security"],
      "mitigations": ["M1026"],
      "link": "https://attack.mitre.org/techniques/T1059/001/"
    }
  ]
}
```

**How to use:**

**Option A: Manual Jira integration**
```
1. Export Backlog (JSON) from Workbench
2. Open Jira → Projects → Detection → Create Issue
3. Copy/paste key fields:
   - Title: T1059.001 PowerShell (Score: 98)
   - Description: (paste from backlog)
   - Priority: (based on threat_score)
4. Repeat for each technique
```

**Option B: Automated Jira integration**
```bash
#!/bin/bash
# jira-create-from-backlog.sh

cat backlog.json | jq '.techniques[] | select(.threat_score > 70)' | while read -r line; do
  TECH=$(echo "$line" | jq -r '.id')
  NAME=$(echo "$line" | jq -r '.name')
  SCORE=$(echo "$line" | jq -r '.total_score')
  
  curl -X POST \
    -H "Authorization: Bearer $JIRA_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"fields\": {
        \"project\": {\"key\": \"DET\"},
        \"summary\": \"$TECH — $NAME (Score: $SCORE)\",
        \"priority\": {\"name\": \"High\"}
      }
    }" \
    https://jira.company.com/rest/api/3/issue
done
```

---

### Format 3: Detection Cards (Markdown)

**What it is:** Detailed write-up per technique with context

**File size:** ~1-5 KB per technique  
**Tool:** Any markdown editor (Notion, Confluence, GitHub, etc.)

**Use cases:**
- ✅ Team documentation (why we care about this technique)
- ✅ Detection rule templates (pseudo-code + alerts)
- ✅ Training material (analyst education)
- ✅ Audit trail (proof of detection coverage)

**Example markdown structure:**
```markdown
## T1059.001 — PowerShell

### Threat Profile
- **APT29:** 83% of campaigns use PowerShell
- **Lazarus:** 81% of campaigns
- **Global Prevalence:** 92% (very common)

### Detection Status
- **Visibility:** Full (Windows Security Logs)
- **Mitigation:** Partial (M1026 - Privileged Account Management)
- **Status:** In Progress (3 rules implemented)

### Data Required
- Windows Security Event 4688 (Process Creation)
- PowerShell Module Logging (Event 4103)
- Sysmon Event 1 (Process Create)

### Detection Rules
1. Suspicious PowerShell Arguments (-enc, -nop)
2. PowerShell Credential Access (Get-Credential)
3. Remote PowerShell Sessions (Enter-PSSession)

### References
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/001/)
- [CAR-2016-04-004](https://car.mitre.org/analytics/CAR-2016-04-004/)
```

**How to use:**

**Option A: View in Workbench**
```
1. Detection Tab → Click any technique row
2. Card opens in side panel
3. Copy text (Ctrl+A, Ctrl+C)
4. Paste into wiki/documentation
```

**Option B: Export all cards**
```bash
# Extract all detection cards from backlog
cat backlog.json | jq -r '.techniques[] | 
  "## \(.id) — \(.name)\n\n### Score: \(.total_score)\n\n### Data Required\n" + 
  (.required_log_sources | join("\n- "))' > detection-cards.md
```

---

## Workflow Patterns

### Pattern 1: CTI → Detection (Weekly Briefing)

```
Monday Morning:
  CTI Analyst creates threat profile
    ↓
  Exports Navigator Layer
    ↓
  Posts link in Slack + team wiki
    ↓
  
Team Reviews:
  Detection Engineer checks profile
    ↓
  Loads into Workbench
    ↓
  Exports Detection Backlog
    ↓
  
Prioritization:
  Creates Jira tickets for top-10 techniques
    ↓
  Estimates effort
    ↓
  Plans sprint work
    ↓
  
Week 1-2: Build detection rules
Week 3: Test & tune
Week 4: Deploy + baseline
```

---

### Pattern 2: SOC Coverage Review (Monthly)

```
Start of Month:
  SOC Lead loads threat profile
    ↓
  Applies current telemetry settings
    ↓
  
Matrix View:
  Reviews heatmap
    ↓
  Identifies blind spots
    ↓
  
Export: Detection Backlog
  Sort by: threat_score DESC, visibility ASC
    ↓
  Filter: visibility = "Blind"
    ↓
  Generate: report (CSV, Markdown)
    ↓
  
Analysis:
  Count blind spots per tactic
    ↓
  Calculate: "% techniques undetected"
    ↓
  Identify: "Which tool/data would solve this?"
    ↓
  
Recommendation:
  "EDR/XDR would reduce blind spots from 18 → 3"
    ↓
  Budget request: $42K for 500 endpoints
    ↓
  Present to leadership
```

---

### Pattern 3: Compliance Audit (Quarterly)

```
Auditor Question:
  "Can you cover APT-X techniques?"
    ↓
CTI Response:
  Loads APT-X profile in Workbench
    ↓
  Exports Navigator Layer
    ↓
  Annotates colors: Green=covered, Red=gap
    ↓
  
Auditor Reviews:
  Opens layer in Navigator
    ↓
  Sees visual coverage per tactic
    ↓
  Clicks cells for technique details
    ↓
  
Documentation:
  CTI provides:
    - Navigator Layer (JSON)
    - Threat Profile Report (Markdown)
    - Detection Backlog (JSON)
    - Detection Rules (per technique)
    ↓
  Auditor approves: "Acceptable coverage"
```

---

## Troubleshooting

### Problem: Can't find threat actor

**Solution:**
```
1. Search for ATT&CK ID: "G0016" (APT29)
2. Search for alias: "Cozy Bear", "Midnight Blizzard"
3. Browse by campaign: "Operation ..."
4. If not found: Use generic profile (manually add techniques)
```

### Problem: Export file is too large

**Solution:**
```
1. Filter by tactic before export
2. Export only techniques above threat_score 50
3. Export only techniques with visibility="Full"
4. Use JSON lines format (one line per technique) instead of pretty-print
```

### Problem: Backlog JSON won't import to Jira

**Solution:**
```
1. Validate JSON: cat backlog.json | jq . > /dev/null
2. Check for special characters: Remove or escape quotes
3. Check Jira API version: Ensure v3 compatibility
4. Test with curl first: curl -X POST -d @backlog.json ...
```

### Problem: Navigator Layer color doesn't show

**Solution:**
```
1. Use hex colors only: "#FF0000" (not "red")
2. Check score range: minValue/maxValue must match
3. Refresh browser: Ctrl+Shift+Del (clear cache)
4. Re-import layer from file
```

---

## Best Practices

### ✅ DO

- ✅ **Version your exports:** `profile-apt29-2025-06-v2.json`
- ✅ **Document timestamp:** "Exported 2025-07-08 14:32 UTC"
- ✅ **Include context:** "Profile: APT29 + Lazarus Group"
- ✅ **Validate JSON:** Always run `jq .` before sharing
- ✅ **Store in git:** Version control your profiles
- ✅ **Comment in Navigator:** Explain why each technique matters
- ✅ **Filter exports:** Only include relevant techniques
- ✅ **Automate:** Use scripts for recurring exports

### ❌ DON'T

- ❌ **Share unvalidated JSON** — Will cause import errors
- ❌ **Use public links permanently** — Navigator links expire
- ❌ **Store sensitive data in profiles** — Only use public ATT&CK IDs
- ❌ **Forget to update monthly** — Profiles become stale
- ❌ **Export everything** — Filter by relevance first
- ❌ **Manual Jira creation** — Automate with scripts
- ❌ **Use old data versions** — Update ATT&CK data monthly

---

## Integration Examples

### Integration 1: Export to Splunk

```bash
#!/bin/bash
# export-to-splunk.sh

BACKLOG="backlog.json"
HEC_URL="https://splunk.company.com:8088/services/collector"
HEC_TOKEN="$SPLUNK_HEC_TOKEN"

cat "$BACKLOG" | jq '.techniques[]' | while read -r technique; do
  curl -k -X POST \
    -H "Authorization: Splunk $HEC_TOKEN" \
    -d "{\"event\": $technique, \"sourcetype\": \"attack_technique\"}" \
    "$HEC_URL"
done
```

### Integration 2: Export to PagerDuty

```bash
#!/bin/bash
# create-pagerduty-from-profile.sh

cat backlog.json | jq '.techniques[] | select(.threat_score > 80)' | while read -r line; do
  TITLE=$(echo "$line" | jq -r '.id + " — " + .name')
  SCORE=$(echo "$line" | jq -r '.total_score')
  
  curl -X POST \
    -H "Authorization: Token token=$PAGERDUTY_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"incidents\": [{
        \"type\": \"incident_reference\",
        \"title\": \"$TITLE (Score: $SCORE)\",
        \"body\": {\"type\": \"incident_body\", \"details\": \"$line\"},
        \"urgency\": \"high\"
      }]
    }" \
    https://api.pagerduty.com/incidents
done
```

### Integration 3: Export to Notion

```python
#!/usr/bin/env python3
# export-to-notion.py

import json
import requests

NOTION_TOKEN = "Bearer $NOTION_TOKEN"
DATABASE_ID = "your-db-id"

with open("backlog.json") as f:
    backlog = json.load(f)

for technique in backlog["techniques"]:
    page_data = {
        "parent": {"database_id": DATABASE_ID},
        "properties": {
            "Technique": {"title": [{"text": {"content": technique["name"]}}]},
            "ID": {"rich_text": [{"text": {"content": technique["id"]}}]},
            "Score": {"number": technique["total_score"]},
            "Visibility": {"select": {"name": technique["visibility"]}},
        }
    }
    
    response = requests.post(
        "https://api.notion.com/v1/pages",
        json=page_data,
        headers={"Authorization": NOTION_TOKEN}
    )
    print(f"✅ {technique['id']} → Notion")
```

---

## File Organization Template

**Recommended folder structure:**

```
attack-analysis-workbench/
├── exports/                    # All exports go here
│   ├── navigator-layers/       # JSON layers for Navigator
│   │   ├── apt29-2025-06.json
│   │   ├── lazarus-2025-06.json
│   │   └── regional-threats-2025-q3.json
│   │
│   ├── detection-backlogs/     # JSON backlogs for ticketing
│   │   ├── windows-backlog-2025-06.json
│   │   ├── linux-backlog-2025-06.json
│   │   └── cloud-backlog-2025-06.json
│   │
│   ├── threat-reports/         # Markdown threat profiles
│   │   ├── apt29-profile.md
│   │   ├── lazarus-profile.md
│   │   └── combined-2025-q3.md
│   │
│   └── monthly-kpis/           # SOC coverage reports
│       ├── coverage-2025-06.md
│       ├── coverage-2025-07.md
│       └── blind-spots-trend.csv
```

---

## Quick Reference Card

| Export Type | File Format | Tool | Audience | Frequency |
|-------------|-------------|------|----------|-----------|
| Navigator Layer | JSON | Navigator (web) | CTI, Leadership | Monthly |
| Detection Backlog | JSON | Jira, Python | Detection Engineering | Weekly |
| Threat Report | Markdown | Wiki, Confluence | All teams | Monthly |
| Coverage Report | Markdown | Google Docs | SOC Leadership | Monthly |
| KPI Dashboard | CSV/JSON | Splunk, PowerBI | Executives | Weekly |

---

**Last Updated:** 2025-07-08  
**Tool:** Attack Analysis Workbench v2.0  
**Questions?** See full documentation: `docs/examples/README.md`
