# CTI Analyst — Using Navigator Layers

**Goal:** Learn how to export threat profiles from the Workbench and share them as interactive ATT&CK Navigator layers.

---

## What is a Navigator Layer?

A **Navigator Layer** is a JSON file that annotates the ATT&CK matrix with:
- ✅ Which techniques are used by your threat actor(s)
- 🎨 Visual highlighting (colors, heat mapping)
- 📝 Comments and metadata
- 🔗 Shareable link for team collaboration

The layer opens in **MITRE ATT&CK Navigator** (free, browser-based tool).

**Example:** https://mitre-attack.github.io/attack-navigator/

---

## Workflow: Export Profile → Share Layer

### Step 1: Build Your Threat Profile in Workbench

```
1. Open Attack Analysis Workbench
2. Search for threat actor → Click "✓ Threat Profile" button
   Examples: "APT29", "Lazarus", "Conti", "Wizard Spider"
3. Add more actors (click + button, repeat step 2)
4. Profile builds in real-time
```

**Result:** Your profile bar shows: `[APT29] [Lazarus Group]` (example)

---

### Step 2: Review Profile in Matrix View

```
1. Click "Matrix" tab
2. See heatmap of techniques — intensity = how many profiled actors use it
3. Hover any cell → tooltip shows actors and their prevalence
```

**Color Intensity Meaning:**
- 🔴 Dark red: Technique used by BOTH actors (high threat)
- 🟠 Orange: Technique used by ONE actor (medium threat)
- 🟡 Yellow: Technique used by 1-2 actors (lower threat)
- ⚪ Gray: Technique NOT used by any profiled actor

---

### Step 3: Export Navigator Layer

```
Matrix Tab → Top-right menu → "Export Navigator Layer" button
```

**What you get:** JSON file named `navigator-layer.json`

**File contents:**
```json
{
  "version": "4.4",
  "name": "APT29 + Lazarus Group",
  "description": "Combined technique profile of two state-sponsored APTs",
  "domain": "enterprise-attack",
  "gradient": {
    "minValue": 0,
    "maxValue": 3,
    "minColor": "#F0F0F0",
    "maxColor": "#FF0000"
  },
  "techniques": [
    {
      "techniqueID": "T1059",
      "tactic": "execution",
      "color": "#FF5733",
      "score": 100,
      "comment": "Command scripting — both groups use extensively"
    },
    {
      "techniqueID": "T1087",
      "tactic": "discovery",
      "color": "#FF5733",
      "score": 90,
      "comment": "Account enumeration — reconnaissance phase"
    },
    {
      "techniqueID": "T1565",
      "tactic": "impact",
      "color": "#FFFFFF",
      "score": 0,
      "comment": "Not typically used by either group"
    }
  ]
}
```

---

## Using the Layer in Navigator

### Method 1: Direct Upload

```
1. Go to https://mitre-attack.github.io/attack-navigator
2. Click "New Layer" (top left)
3. Click "Import" → Select file (navigator-layer.json)
4. Matrix appears with your threat actor annotations
```

### Method 2: Copy-Paste JSON

```
1. Open navigator-layer.json in text editor
2. Copy all content (Ctrl+A, Ctrl+C)
3. Go to Navigator
4. Click "New Layer" → "Import from text"
5. Paste JSON (Ctrl+V)
6. Click "Open"
```

### Method 3: Share Link (Collaboration)

**After importing in Navigator:**
1. Click "Share" button (top-right)
2. Navigator generates shareable link
3. Send to team: https://mitre-attack.github.io/attack-navigator/layers/data=...
4. Team can view, modify, save their own copies

**Note:** Link expires after some time; save the JSON file permanently.

---

## Visual Customization in Navigator

Once layer is open, you can:

### 🎨 Change Colors

```
1. Right-click any technique
2. Select "Edit annotation"
3. Choose color from picker
4. Add comment for context
```

**Color Convention Suggestion:**
- 🔴 Red (#FF0000): Critical threat, must-detect
- 🟠 Orange (#FFA500): High threat
- 🟡 Yellow (#FFD700): Medium threat
- 🟢 Green (#00FF00): Acknowledged, low impact
- 🔵 Blue (#0000FF): Monitored by us
- ⚫ Gray (#808080): Not relevant

### 📝 Add Comments

```
Example technique: T1053.005 — Scheduled Task
Comment: "Lazarus used in 62% of campaigns; APT29 in 55%. 
Priority for Windows log source: Security Event 106."
```

### 🔍 Filter & Search

```
Navigator Features:
- Filter by Tactic: "Show only Execution techniques"
- Filter by Platform: "Show only Windows"
- Search: "Show techniques mentioning 'credential'"
```

### 📊 Data Table View

```
Switch from matrix view → Table view:
Technique | Tactic | Score | Comment | Platform
────────────────────────────────────────────────────
T1059     | Exec   | 100   | Heavy use | Multiple
T1087     | Disc   | 90    | Recon    | Windows
```

---

## Integration with Detection Engineering

### Handoff: CTI → Detection

**As CTI Analyst:**
1. ✅ Export layer from Workbench
2. ✅ Customize colors/comments in Navigator
3. ✅ Share JSON file with Detection Engineer
4. ✅ Add link to ticket or wiki

**Detection Engineer then:**
1. Loads threat profile into Workbench (Detection Designer tab)
2. Applies actual telemetry (Windows logs, EDR, etc.)
3. Exports Detection Backlog prioritized by threat score
4. Uses your layer as reference for "why we care about these techniques"

---

## Advanced: Batch Create Multiple Layers

**Scenario:** Create layers for your top-10 threat actors (individual profiles).

### Python Script Template

```python
import json
import requests

# Download MITRE ATT&CK data
response = requests.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
attack_data = response.json()

# List of actors (ATT&CK IDs)
actors = ["G0016", "G0032", "G0050", "G0075"]  # APT29, Lazarus, APT3, Wizard Spider

for actor_id in actors:
    # Fetch actor techniques via ATT&CK API
    techniques = get_actor_techniques(actor_id)
    
    # Build layer JSON
    layer = {
        "version": "4.4",
        "name": f"Threat Actor {actor_id}",
        "domain": "enterprise-attack",
        "techniques": [
            {
                "techniqueID": t["id"],
                "score": 100,
                "color": "#FF0000"
            }
            for t in techniques
        ]
    }
    
    # Save file
    with open(f"layer-{actor_id}.json", "w") as f:
        json.dump(layer, f, indent=2)
    
    print(f"✅ Created layer-{actor_id}.json")
```

---

## Collaboration Workflow

### Scenario: CTI Team Reviews Threat Profile

```
1. CTI Lead creates profile in Workbench (APT29 + Lazarus)
2. Exports Navigator Layer
3. Posts JSON file + link in Slack
4. Team members:
   - Open link in browser
   - Add comments (e.g., "We see this in honeypots")
   - Export their annotated version
5. Merge comments in final version
6. Store final JSON in git repo
```

**Git Integration:**
```bash
# Track layers in version control
git add docs/layers/apt29-lazarus-2025-q3.json
git commit -m "Update threat actor profile — new campaign identified"
git push

# Share link: rawgit.com/yourrepo/docs/layers/apt29-lazarus-2025-q3.json
```

---

## Troubleshooting

### Problem: Layer JSON won't import

**Solutions:**
1. Validate JSON syntax: Use https://jsonlint.com
2. Check `version` field: Must be "4.4" or compatible
3. Verify `domain` field: Must be "enterprise-attack" (not "mobile-attack")
4. Check `techniqueID` format: Must be "T1234" or "T1234.005"

### Problem: Techniques don't appear in matrix

**Solutions:**
1. Verify technique IDs are correct (use search in ATT&CK)
2. Check that `tactic` field matches ATT&CK format (e.g., "execution", not "Execution")
3. Ensure no duplicate technique IDs in layer

### Problem: Colors look wrong

**Solutions:**
1. Use hex colors only (e.g., "#FF0000", not "red")
2. Check color contrast for visibility
3. Reset to default: Refresh page

---

## Sharing Best Practices

### ✅ DO

- ✅ Document your threat profile context (why these actors?)
- ✅ Include timestamp (when was this created/updated?)
- ✅ Version your layers (layer-apt29-2025-06-v2.json)
- ✅ Share JSON files in secure locations (git, internal wiki)
- ✅ Include scoring explanation (why is this technique a 100?)

### ❌ DON'T

- ❌ Share links that expire
- ❌ Include false positives (techniques not actually used)
- ❌ Use inconsistent color schemes across team
- ❌ Forget to validate JSON syntax
- ❌ Store sensitive attribution data in public repos

---

## Real-World Example

### Your Team's Threat Profile

**File:** `layers/regional-threat-actors-q3-2025.json`

```json
{
  "version": "4.4",
  "name": "Regional APTs — Q3 2025",
  "description": "Top threats to financial sector in APAC region",
  "domain": "enterprise-attack",
  "sorting": 0,
  "metadata": [
    {
      "name": "Created",
      "value": "2025-07-08"
    },
    {
      "name": "Source",
      "value": "Attack Analysis Workbench v2.0"
    },
    {
      "name": "Threat Level",
      "value": "High"
    }
  ],
  "gradient": {
    "minValue": 0,
    "maxValue": 100,
    "minColor": "#FFFFFF",
    "maxColor": "#FF0000"
  },
  "techniques": [
    {
      "techniqueID": "T1059",
      "tactic": "execution",
      "color": "#FF0000",
      "score": 100,
      "comment": "All 5 profiled actors use command execution"
    },
    {
      "techniqueID": "T1087",
      "tactic": "discovery",
      "color": "#FF8800",
      "score": 85,
      "comment": "Account discovery — typical reconnaissance"
    },
    {
      "techniqueID": "T1565",
      "tactic": "impact",
      "color": "#FFFFFF",
      "score": 0,
      "comment": "Data manipulation — not typical for financial theft"
    }
  ]
}
```

**Share in your Slack:**
```
🔴 Updated threat profile: Regional APTs Q3 2025
📊 Preview: [Navigator Link]
📁 JSON: docs/layers/regional-threat-actors-q3-2025.json
👥 Team review: Comment in #intel channel
```

---

## Next Steps

1. **Create your first layer** using Workbench Matrix export
2. **Share with team** via Navigator link
3. **Collect feedback** in Slack/wiki
4. **Version it** in git
5. **Pass to Detection Engineering** with threat context

---

**Last Updated:** 2025-07-08  
**Tool:** Attack Analysis Workbench v2.0 + MITRE ATT&CK Navigator  
**Questions?** See main README: `docs/examples/README.md`
