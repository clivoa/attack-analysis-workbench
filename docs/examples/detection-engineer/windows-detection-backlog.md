# Detection Engineer — Windows Detection Backlog

**Profile:** APT29 + Lazarus Group  
**Telemetry:** Windows (Security Event Logs, Sysmon)  
**Generated:** 2025-07-08  
**Priority Filter:** Threat Score ≥ 50  

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| **Total Techniques in Profile** | 89 |
| **Techniques for Detection** | 72 |
| **Windows-Relevant Techniques** | 65 |
| **Currently Visible** | 31 (48%) |
| **Partially Visible** | 18 (28%) |
| **Blind** | 16 (24%) |
| **Detection-Only** (no mitigation) | 21 (32%) |

**Coverage Gap:** 52% of profiled techniques lack adequate Windows visibility. Recommend expanding telemetry to EDR/XDR for blind coverage.

---

## Top Priorities (Threat Score 80+)

### 🔴 CRITICAL — Must-Have (Next 2 Weeks)

#### 1. **T1059.001 — PowerShell**

| Field | Value |
|-------|-------|
| **Threat Score** | 98 |
| **Prevalence** | 92% (82/89 actors globally) |
| **Actors (Profiled)** | APT29 (83%), Lazarus (81%) |
| **Visibility** | ✅ FULL |
| **Mitigation** | ⚠️ Partial (M1026 — Privileged Account Management) |
| **Status** | In Progress |

**Why Critical:**
- Both actors use PowerShell extensively (C2, lateral movement, data exfil)
- High global prevalence = high noise + high signal
- Detection-only: While M1026 helps, PowerShell execution is unavoidable

**Data Required:**
```
✅ Windows Security Logs
  - Event 4688 (Process Creation) — with CommandLine enabled
  - Event 4103 (Module Logging) — PowerShell modules loaded
  
✅ Sysmon
  - Event 1 (Process Create) — command line arguments
  - Event 3 (Network Connection) — C2 callbacks
  
✅ PowerShell Transcription
  - All script content logged to log file
  - High volume but critical for threat hunting
```

**Detection Strategy:**

```
Rule 1: Suspicious PowerShell Execution Patterns
Conditions:
  - Process = powershell.exe OR pwsh.exe
  - CommandLine contains: -enc, -nop, -NoProfile, -ExecutionPolicy
  - SourceIP not in [trusted_admin_ranges]
Alert: High | Threshold: Any occurrence
MITRE: T1059.001 | Severity: High

Rule 2: PowerShell Credential Access
Conditions:
  - Module Logging shows: Invoke-Expression, Invoke-WebRequest
  - Script block contains: Get-Credential, Import-Clixml
Alert: Critical | Threshold: Any occurrence
MITRE: T1059.001 | Severity: Critical

Rule 3: PowerShell Lateral Movement
Conditions:
  - TargetServerName != localhost
  - Module contains: New-PSSession, Enter-PSSession
  - TargetAccount != (domain_admins_list)
Alert: High | Threshold: Any occurrence
MITRE: T1059.001 | Severity: High
```

**Analytics (MITRE):**
- CAR-2016-04-004: PowerShell Execution
- CAR-2016-04-005: Remote PowerShell Sessions

---

#### 2. **T1003 — OS Credential Dumping**

| Field | Value |
|-------|-------|
| **Threat Score** | 94 |
| **Prevalence** | 87% (global) |
| **Actors (Profiled)** | APT29 (91%), Lazarus (89%) |
| **Visibility** | ⚠️ PARTIAL |
| **Mitigation** | ❌ NONE |
| **Status** | Planned |

**Why Critical:**
- **Detection-Only:** No mitigation maps to this technique
- Both actors use Mimikatz, comsvcs.dll, or native tools
- Indicator of compromise on high-value targets

**Data Required:**
```
⚠️ Windows Security Logs
  - Event 4689 (Process Termination) — catch lsass.exe crashes
  - Event 4657 (Registry Modified) — HKLM\System\CurrentControlSet\Control\Lsa
  
✅ Sysmon
  - Event 1 (Process Create) — mimikatz.exe, sekurlsa
  - Event 10 (ProcessAccess) — lsass.exe access
  - Event 11 (FileCreate) — .dmp files (memory dumps)
  
❌ MISSING (Recommend Adding)
  - Memory forensics capability
  - EDR telemetry (e.g., CrowdStrike, Microsoft Defender)
  - GPU memory dumps detection
```

**Detection Strategy:**

```
Rule 1: Mimikatz Execution (Direct)
Conditions:
  - FileName matches: *mimikatz* OR *sekurlsa* OR *psexec*
  - ParentProcess in: [explorer.exe, cmd.exe, powershell.exe]
Alert: Critical | Threshold: Any occurrence
MITRE: T1003 | Severity: Critical

Rule 2: Process Access to LSASS
Conditions:
  - TargetImage = %SystemRoot%\System32\lsass.exe
  - SourceImage NOT IN [wininit.exe, services.exe, lsm.exe]
  - AccessMask = 0x1010 OR 0x1428 (read/dump)
Alert: High | Threshold: Any occurrence
MITRE: T1003 | Severity: High

Rule 3: Registry LSA Modification
Conditions:
  - TargetObject = HKLM\System\CurrentControlSet\Control\Lsa\*
  - ProcessName NOT in [lsass.exe, services.exe, svchost.exe]
  - EventType = SetValue
Alert: Medium | Threshold: 1+ per hour
MITRE: T1003 | Severity: Medium
```

**Testing:**
```bash
# Safe reproduction (in lab only)
rundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).Id out.dmp
# Should trigger Rule 2: Process Access to LSASS
```

---

#### 3. **T1087 — Account Discovery**

| Field | Value |
|-------|-------|
| **Threat Score** | 89 |
| **Prevalence** | 94% |
| **Actors (Profiled)** | APT29 (88%), Lazarus (90%) |
| **Visibility** | ✅ FULL |
| **Mitigation** | ⚠️ Partial (M1027 — Operator User Account Management) |
| **Status** | Done |

**Why Critical:**
- Precursor to privilege escalation & lateral movement
- High baseline noise (legitimate admins do this)
- Tuning required to reduce false positives

**Data Required:**
```
✅ Windows Security Logs
  - Event 4688 (Process Create) — net.exe, Get-LocalUser, whoami
  - Event 4798 (User Enumeration) — QueryUserInfo calls
  
✅ Sysmon
  - Event 1 (Process Create) — discovery tools
  - Event 3 (Network) — LDAP queries to DC
```

**Detection Rules (ALREADY IMPLEMENTED):**

```
Rule 1: Suspicious Account Enumeration
Status: ✅ Active (Splunk index=main, alert=true)
Trigger: 3+ discovery commands in 60 seconds
Exclude: admin_accounts_list, scheduled_tasks, service_accounts
False Positive Rate: 2% (tuned)
```

---

### 🟠 HIGH Priority (Threat Score 60-79)

#### 4. **T1566 — Phishing (Email)**

| Field | Value |
|-------|-------|
| **Threat Score** | 76 |
| **Prevalence** | 89% |
| **Actors (Profiled)** | APT29 (67%), Lazarus (91%) |
| **Visibility** | ⚠️ PARTIAL |
| **Mitigation** | ✅ Full (M1017 — User Training) |
| **Status** | Planned |

**Data Required:**
```
⚠️ Email Logs
  - Attachment hashes
  - URL patterns
  - Sender domain reputation
  
✅ Proxy/Firewall
  - Malicious URL detection
  - File reputation scores
```

---

#### 5. **T1071 — Application Layer Protocol**

| Field | Value |
|-------|-------|
| **Threat Score** | 71 |
| **Prevalence** | 82% |
| **Actors (Profiled)** | APT29 (79%), Lazarus (83%) |
| **Visibility** | ⚠️ PARTIAL |
| **Mitigation** | ❌ NONE |
| **Status** | In Progress |

**Detection Strategy:**

```
Rule 1: Suspicious HTTP User-Agent
Conditions:
  - UserAgent matches: *WinHTTP*, *Curl*, *wget*, *Powershell*
  - SourceIP in [company_networks]
  - NOT from [approved_admin_tools]
Alert: Medium | Threshold: Baseline deviation

Rule 2: DNS Tunneling Detection
Conditions:
  - DNSQuery length > 200 chars
  - DNSQueryType NOT in [A, AAAA, MX, NS]
  - Frequency > 10 queries/min to same domain
Alert: High | Threshold: Any occurrence
```

---

## Medium Priority (Threat Score 40-59)

### Planned Detections (Next Sprint)

| Rank | Technique | Score | Visibility | Status |
|------|-----------|-------|------------|----|
| 6 | T1547 — Boot or Logon Autostart | 58 | Partial | Planned |
| 7 | T1547.001 — Registry Run Keys | 56 | Full | Planned |
| 8 | T1543 — Create or Modify Sys Process | 52 | Partial | Planned |
| 9 | T1543.003 — Windows Service | 51 | Full | In Progress |
| 10 | T1136 — Create Account | 48 | Full | Done |

---

## Blind Spots (Priority for EDR Implementation)

### Visibility = BLIND (0 log sources)

These techniques have **NO detection capability** without additional telemetry:

```
- T1559.001 — COM & OLE Automation (Office macros)
- T1547.004 — Winlogon Helper DLL (persistence via DLL)
- T1547.008 — LSASS Driver (kernel-level persistence)
- T1547.013 — XDG Autostart Entries (Linux only)
- T1574 — Hijack Execution Flow (DLL Search Order)
- T1197 — BITS Jobs (Background Intelligent Transfer Service)
- T1218 — System Binary Proxy Execution (Living-off-the-land)
```

**Recommendation:**
- Implement EDR/XDR (CrowdStrike, Microsoft Defender for Endpoint, Carbon Black)
- Deploy behavior-based detection (anomaly detection, ML models)
- Add kernel telemetry (Sysmon advanced options, ETW)

---

## Export: JSON Backlog for Ticketing

```json
{
  "profile": "APT29 + Lazarus Group",
  "generated": "2025-07-08T14:32:00Z",
  "telemetry": ["Windows", "Sysmon", "PowerShell Transcription"],
  "techniques": [
    {
      "id": "T1059.001",
      "name": "PowerShell",
      "tactic": "Execution",
      "threat_score": 98,
      "prevalence_score": 30,
      "exposure_score": 0,
      "total_score": 98,
      "visibility": "Full",
      "status": "in_progress",
      "required_log_sources": [
        "WinEventLog:Security (Event 4688)",
        "WinEventLog:Security (Event 4103)",
        "PowerShell:Operational"
      ],
      "mitigations": ["M1026"],
      "detection_rules": 3,
      "link": "https://attack.mitre.org/techniques/T1059/001/"
    },
    {
      "id": "T1003",
      "name": "OS Credential Dumping",
      "tactic": "Credential Access",
      "threat_score": 94,
      "prevalence_score": 30,
      "exposure_score": 20,
      "total_score": 94,
      "visibility": "Partial",
      "status": "planned",
      "required_log_sources": [
        "Sysmon:ProcessAccess (Event 10)",
        "WinEventLog:Security (Event 4689)"
      ],
      "mitigations": [],
      "detection_rules": 0,
      "link": "https://attack.mitre.org/techniques/T1003/"
    }
  ]
}
```

**Use Case:** Pipe to Jira
```bash
cat backlog.json | jq '.techniques | .[] | {
  summary: "\(.name) (Score: \(.total_score))",
  description: "Technique: \(.id)\nThreat: \(.threat_score)\nVisibility: \(.visibility)",
  priority: (if .total_score > 80 then "High" elif .total_score > 60 then "Medium" else "Low" end),
  labels: [.tactic, .visibility]
}'
```

---

## Next Steps

1. **Phase 1 (This Week):** Validate top-5 detection rules
2. **Phase 2 (Next 2 Weeks):** Implement Rules 1-10
3. **Phase 3 (30 Days):** Expand to all 65 Windows techniques
4. **Phase 4 (60 Days):** Evaluate EDR/XDR for blind coverage

---

**Last Updated:** 2025-07-08  
**Tool:** Attack Analysis Workbench v2.0  
**Questions?** See `docs/examples/shared/how-to-use-exports.md`
