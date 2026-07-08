# Data Model Reference

**For:** Technical teams, integrations, automation  
**Purpose:** Complete specification of data structures in Workbench exports  

---

## Overall Structure

### Root Object

```typescript
interface ExportRoot {
  version: string;                    // "2.0" (Workbench version)
  generated: ISO8601DateTime;         // "2025-07-08T14:32:00Z"
  profile: string;                    // "APT29 + Lazarus Group"
  profile_ids: string[];              // ["G0016", "G0032"]
  telemetry: string[];                // ["Windows", "Sysmon", "PowerShell"]
  techniques: Technique[];            // Array of techniques
}
```

---

## Technique Object

### Complete Technique Structure

```typescript
interface Technique {
  // MITRE ATT&CK Identifiers
  id: string;                         // "T1059.001" (subtechnique) or "T1059"
  name: string;                       // "PowerShell"
  tactic: string;                     // "execution"
  platform: string[];                 // ["windows", "linux", "macos"]
  is_subtechnique: boolean;           // true if T1234.005 format
  parent_technique: string | null;    // "T1059" if subtechnique
  
  // Threat Profile Context
  threat_profile: ThreatContext;
  
  // Detection Context
  detection: DetectionContext;
  
  // Mitigation Context
  mitigation: MitigationContext;
  
  // Scoring & Priority
  scores: ScoringData;
  
  // Tracking
  backlog: BacklogTracking;
  
  // References
  link: string;                       // "https://attack.mitre.org/techniques/T1059/001/"
  car_ids: string[];                  // ["CAR-2016-04-004"]
  sigma_rules: string[];              // Rule IDs from Sigma repository
}
```

---

## ThreatContext Object

Describes which actors use this technique and prevalence.

```typescript
interface ThreatContext {
  // Actor-Specific Usage
  actors_in_profile: {
    id: string;                       // "G0016" (APT29)
    name: string;                     // "APT29"
    usage_percent: number;            // 83% (percent of campaigns)
    campaigns: number;                // 42 (number of campaigns using technique)
  }[];
  
  // Global Statistics
  global_prevalence_percent: number;  // 92% (actors globally using this)
  campaigns_global: number;           // 847 total campaigns using
  groups_global: number;              // 47 different groups use this
  
  // Campaign Data
  campaigns_in_profile: {
    id: string;                       // "C0037"
    name: string;                     // "Operation ..."
  }[];
  
  // Malware & Tools
  malware_tools: {
    id: string;                       // "S0049"
    name: string;                     // "Mimikatz"
    type: "malware" | "tool";
  }[];
}

// Example JSON
{
  "actors_in_profile": [
    {
      "id": "G0016",
      "name": "APT29",
      "usage_percent": 83,
      "campaigns": 42
    },
    {
      "id": "G0032",
      "name": "Lazarus Group",
      "usage_percent": 81,
      "campaigns": 39
    }
  ],
  "global_prevalence_percent": 92,
  "campaigns_global": 847,
  "groups_global": 47
}
```

---

## DetectionContext Object

Describes visibility and detection coverage.

```typescript
interface DetectionContext {
  // Current Visibility Status
  visibility: "Full" | "Partial" | "Blind";
  visibility_explanation: string;   // "Full visibility via Windows Security Event 4688"
  
  // Visibility Details per Platform
  by_platform: {
    [platform: string]: {
      visibility: "Full" | "Partial" | "Blind";
      log_sources: string[];         // ["WinEventLog:Security", "Sysmon"]
    }
  };
  
  // Required Log Sources
  required_log_sources: {
    name: string;                    // "Windows Security Log"
    vendor: string;                  // "Microsoft"
    log_type: string;                // "WinEventLog"
    event_ids?: number[];            // [4688, 4103]
    priority: "critical" | "recommended" | "optional";
    available: boolean;              // Whether org has this source
  }[];
  
  // Analytics from MITRE
  analytics: {
    id: string;                      // "CAR-2016-04-004"
    name: string;                    // "PowerShell Execution"
    data_sources: string[];          // ["Process creation", "Module loading"]
  }[];
  
  // Detection Rules (Internal)
  detection_rules: {
    id: string;                      // "DET-001"
    name: string;                    // "Suspicious PowerShell Arguments"
    status: "implemented" | "planned" | "in_progress";
    siem: string;                    // "Splunk", "Elastic", "QRadar"
    false_positive_rate: number;     // 0.05 (5%)
  }[];
  
  // Hunting Queries
  hunting_queries: {
    siem: string;                    // "Splunk"
    query: string;                   // SPL query
  }[];
}

// Example JSON
{
  "visibility": "Full",
  "visibility_explanation": "Full visibility via Windows Security Event 4688 + Sysmon Event 1",
  "required_log_sources": [
    {
      "name": "Windows Security Log",
      "vendor": "Microsoft",
      "log_type": "WinEventLog",
      "event_ids": [4688, 4103],
      "priority": "critical",
      "available": true
    },
    {
      "name": "Sysmon",
      "vendor": "Sysinternals",
      "log_type": "sysmon",
      "event_ids": [1, 3],
      "priority": "recommended",
      "available": true
    }
  ]
}
```

---

## MitigationContext Object

Describes available mitigations and coverage.

```typescript
interface MitigationContext {
  // Mapped Mitigations
  mitigating_controls: {
    id: string;                      // "M1026"
    name: string;                    // "Privileged Account Management"
    coverage: "Full" | "Partial";    // Can this stop the technique?
    description: string;             // "Restrict execution of PowerShell to ..."
  }[];
  
  // Coverage Summary
  has_mitigation: boolean;           // true if any mitigation exists
  mitigation_coverage_percent: number; // 30% (what % of this technique is mitigated)
  
  // Detection-Only Indicator
  is_detection_only: boolean;        // true if NO mitigation exists
  detection_only_reason: string;     // "Technique is a default OS capability"
  
  // Evasion Metrics
  can_be_evaded: boolean;            // Can attacker bypass mitigations?
  evasion_complexity: "Low" | "Medium" | "High";
}

// Example JSON — Full Mitigation
{
  "mitigating_controls": [
    {
      "id": "M1026",
      "name": "Privileged Account Management",
      "coverage": "Partial",
      "description": "Restrict execution of PowerShell to ..."
    }
  ],
  "has_mitigation": true,
  "mitigation_coverage_percent": 30,
  "is_detection_only": false
}

// Example JSON — Detection-Only
{
  "mitigating_controls": [],
  "has_mitigation": false,
  "mitigation_coverage_percent": 0,
  "is_detection_only": true,
  "detection_only_reason": "Credential dumping is inherent OS capability"
}
```

---

## ScoringData Object

Calculates priority for detection work.

```typescript
interface ScoringData {
  // Individual Score Components
  threat_score: number;              // 0-50 (actor usage in profile)
  prevalence_score: number;          // 0-30 (global actor usage)
  exposure_score: number;            // 0-20 (detection-only vs mitigation)
  
  // Total Score (0-100)
  total_score: number;               // threat + prevalence + exposure
  
  // Scoring Breakdown
  threat_calculation: {
    actors_using: number;            // # actors in profile using this
    avg_prevalence: number;          // Average % per actor
    formula: string;                 // "MIN(50, actors * avg_prevalence / 10)"
  };
  
  prevalence_calculation: {
    global_prevalence: number;       // % of all actors
    formula: string;                 // "prevalence * 30 / 100"
  };
  
  exposure_calculation: {
    has_mitigation: boolean;
    formula: string;                 // "has_mitigation ? 0 : 20"
    reason: string;                  // "No mitigation; detection is only control"
  };
  
  // Percentile
  percentile: number;                // 95 (top 5% priority)
}

// Example JSON
{
  "threat_score": 42,
  "prevalence_score": 30,
  "exposure_score": 20,
  "total_score": 92,
  "threat_calculation": {
    "actors_using": 2,
    "avg_prevalence": 82,
    "formula": "MIN(50, 2 * 82 / 10) = 42"
  },
  "prevalence_calculation": {
    "global_prevalence": 92,
    "formula": "92 * 30 / 100 = 27.6 ≈ 30"
  },
  "exposure_calculation": {
    "has_mitigation": false,
    "formula": "has_mitigation ? 0 : 20 = 20",
    "reason": "No mitigation; detection is only control"
  },
  "percentile": 95
}
```

---

## BacklogTracking Object

For detection engineers to track implementation status.

```typescript
interface BacklogTracking {
  // Implementation Status
  status: "review" | "planned" | "in_progress" | "done" | "na";
  status_updated: ISO8601DateTime;
  assigned_to: string | null;        // "john.smith@company.com"
  
  // Timeline
  date_started: ISO8601DateTime | null;
  date_completed: ISO8601DateTime | null;
  estimated_days: number;            // 3 (est. time to implement)
  
  // Notes
  notes: string;                     // "Waiting for EDR deployment"
  
  // Metrics
  rules_implemented: number;         // 3 detection rules created
  false_positive_rate: number;       // 0.02 (2%)
  detection_rate: number;            // 0.87 (87% of live detections)
  
  // Dependencies
  depends_on: string[];              // ["T1003", "EDR deployment"]
  
  // Historical
  history: {
    date: ISO8601DateTime;
    status: string;
    changed_by: string;
    comment: string;
  }[];
}

// Example JSON
{
  "status": "in_progress",
  "status_updated": "2025-07-05T10:22:00Z",
  "assigned_to": "alice.johnson@company.com",
  "estimated_days": 5,
  "notes": "Core rule implemented; waiting for fine-tuning",
  "rules_implemented": 2,
  "false_positive_rate": 0.03,
  "depends_on": ["Sysmon deployment", "PowerShell Module Logging"]
}
```

---

## Navigator Layer Format (JSON)

For sharing with MITRE ATT&CK Navigator tool.

```typescript
interface NavigatorLayer {
  version: "4.4";                    // ATT&CK Navigator version
  name: string;                      // Layer name
  description: string;               // What this layer represents
  domain: "enterprise-attack" | "mobile-attack" | "ics-attack";
  
  // Optional Metadata
  metadata?: {
    name: string;
    value: string;
  }[];
  
  // Color Gradient Configuration
  gradient?: {
    minValue: number;                // 0
    maxValue: number;                // 100
    minColor: string;                // "#FFFFFF"
    maxColor: string;                // "#FF0000"
  };
  
  // Technique Annotations
  techniques: {
    techniqueID: string;             // "T1059.001"
    tactic?: string;                 // "execution"
    color?: string;                  // "#FF5733" (hex color)
    score?: number;                  // 0-100
    comment?: string;                // Any annotation
    enabled?: boolean;               // true to show
  }[];
  
  // Metadata about data sources/platforms
  sorting?: number;                  // Sort order
  showTechniques?: boolean;          // Show techniques in tooltips
  hideDisabled?: boolean;            // Hide techniques with enabled:false
}

// Example JSON
{
  "version": "4.4",
  "name": "APT29 + Lazarus Group",
  "description": "Combined profile of two state-sponsored APTs",
  "domain": "enterprise-attack",
  "metadata": [
    {"name": "Created", "value": "2025-07-08"},
    {"name": "Source", "value": "Attack Analysis Workbench"}
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
      "comment": "Both groups use extensively"
    }
  ]
}
```

---

## CSV Export Format

For spreadsheet imports.

```csv
Technique_ID,Technique_Name,Tactic,APT29_%,Lazarus_%,Global_%,Visibility,Mitigation,Score,Status
T1059.001,PowerShell,Execution,83,81,92,Full,Partial,98,in_progress
T1003,OS Credential Dumping,Credential Access,91,89,87,Partial,None,94,planned
T1087,Account Discovery,Discovery,88,90,94,Full,Partial,89,done
```

---

## JSON Lines Format (Streaming)

For large datasets or piping.

```jsonl
{"id":"T1059.001","name":"PowerShell","score":98,"visibility":"Full","status":"in_progress"}
{"id":"T1003","name":"OS Credential Dumping","score":94,"visibility":"Partial","status":"planned"}
{"id":"T1087","name":"Account Discovery","score":89,"visibility":"Full","status":"done"}
```

---

## API Response Format

When querying the Workbench programmatically.

```typescript
interface APIResponse<T> {
  success: boolean;
  timestamp: ISO8601DateTime;
  data: T;
  errors?: {
    field: string;
    message: string;
  }[];
}

// Example: Get technique details
{
  "success": true,
  "timestamp": "2025-07-08T14:32:00Z",
  "data": {
    "id": "T1059.001",
    "name": "PowerShell",
    "threat_context": { /* ... */ },
    "detection_context": { /* ... */ }
  }
}
```

---

## Filtering Queries

Example queries to subset exports.

### Filter by Score

```json
{
  "filter": {
    "total_score": {"$gte": 70}
  }
}
// Result: Techniques scoring 70+
```

### Filter by Visibility

```json
{
  "filter": {
    "detection.visibility": "Blind"
  }
}
// Result: Techniques with no detection capability
```

### Filter by Status

```json
{
  "filter": {
    "backlog.status": "planned"
  }
}
// Result: Techniques that need detection work
```

### Complex Filter

```json
{
  "filter": {
    "$and": [
      { "detection.visibility": {"$ne": "Full"} },
      { "total_score": {"$gte": 60} }
    ]
  }
}
// Result: Partially/Blindly-detected high-score techniques
```

---

## SQL-Style Queries

Example queries if exported to SQL database.

```sql
-- Top 10 techniques by score
SELECT id, name, total_score, visibility 
FROM techniques 
WHERE profile = 'APT29 + Lazarus'
ORDER BY total_score DESC 
LIMIT 10;

-- Blind spots in high-score techniques
SELECT id, name, total_score 
FROM techniques 
WHERE detection.visibility = 'Blind' 
AND total_score >= 70
ORDER BY total_score DESC;

-- Detection progress
SELECT 
  backlog.status,
  COUNT(*) as count,
  AVG(total_score) as avg_score
FROM techniques 
GROUP BY backlog.status;

-- Coverage by tactic
SELECT 
  tactic,
  COUNT(*) as total_techniques,
  SUM(CASE WHEN detection.visibility = 'Full' THEN 1 ELSE 0 END) as detected,
  ROUND(100.0 * SUM(CASE WHEN detection.visibility = 'Full' THEN 1 ELSE 0 END) / COUNT(*), 2) as coverage_percent
FROM techniques 
GROUP BY tactic
ORDER BY coverage_percent DESC;
```

---

## Field Definitions

### Visibility Values

```typescript
type Visibility = 
  | "Full"      // All execution of this technique is detected
  | "Partial"   // Some executions detected (platform-dependent)
  | "Blind"     // No detection capability available
```

### Status Values

```typescript
type Status = 
  | "review"        // Being reviewed for feasibility
  | "planned"       // Scheduled for implementation
  | "in_progress"   // Currently being developed
  | "done"          // Implemented and in production
  | "na"            // Not applicable (e.g., macOS technique, no Windows hosts)
```

### Tactic Values

```typescript
type Tactic = 
  | "reconnaissance"
  | "resource-development"
  | "initial-access"
  | "execution"
  | "persistence"
  | "privilege-escalation"
  | "defense-evasion"
  | "credential-access"
  | "discovery"
  | "lateral-movement"
  | "collection"
  | "command-and-control"
  | "exfiltration"
  | "impact"
```

---

## Version History

### v2.0 (2025-07)
- ES6 modules + Vite build
- Added Detection Context object
- Added ScoringData breakdown
- Navigator Layer v4.4 support

### v1.0 (Original)
- IIFE-based modules
- Basic exports

---

**Last Updated:** 2025-07-08  
**Tool:** Attack Analysis Workbench v2.0  
**Questions?** See `docs/examples/README.md`
