# SOC Lead — Monthly Coverage Report

**Period:** July 2025  
**Threat Profile:** APT29 + Lazarus Group (Regional Focus)  
**Organization:** Financial Services (APAC)  
**Prepared by:** Security Operations Team  

---

## Executive Summary

### 🎯 Key Findings

| Metric | Value | Trend | Status |
|--------|-------|-------|--------|
| **Threat Techniques Coverage** | 56% | ↑ +8% | ⚠️ Needs improvement |
| **Blind Spots (Detection-Only)** | 18 | ↑ +3 | 🔴 Critical |
| **Detection Rules Implemented** | 31 | ↑ +5 | 🟢 Good |
| **Mitigation Controls Active** | 42 | ↔️ No change | 🟡 Adequate |
| **Telemetry Data Sources** | 7 | ↑ +1 | 🟢 Improving |
| **Rules with False Positive Rate > 10%** | 4 | ↓ -2 | 🟢 Improving |

### 📊 Coverage by Tactic

```
Reconnaissance     ████░░░░░░ 42% (8 of 19 techniques detected)
Resource Dev       ██████░░░░ 58% (11 of 19)
Initial Access     ██████████ 100% (3 of 3)
Execution          ████████░░ 82% (11 of 14)
Persistence        ██████░░░░ 63% (7 of 11)
Privilege Escal    ██████░░░░ 63% (5 of 8)
Defense Evasion    ████░░░░░░ 44% (7 of 16)
Credential Access  ████████░░ 81% (9 of 11)
Discovery          ███████░░░ 77% (7 of 9)
Lateral Movement   ██████████ 100% (7 of 7)
Collection         ████████░░ 81% (9 of 11)
Command & Control  ██████░░░░ 62% (5 of 8)
Exfiltration       ████████░░ 85% (6 of 7)
Impact             ███░░░░░░░ 28% (2 of 7)
```

### 📈 Trend Analysis

```
Coverage Trajectory (Last 3 Months):
May:   38% ─────┐
June:  48%      ├─ +10% improvement through Detection Engineer rules
July:  56%      │
Target (Q3): 75% ────────── Gap: 19 techniques to cover

Velocity: +9% per month
To reach 75%: ~2 more months at current pace
Acceleration needed: Add 3+ detection engineers
```

---

## Coverage by Actor

### APT29 (Russia, Espionage)

```
Techniques Attributed: 134
Our Coverage: 78 techniques (58%)
Blind Spots: 56 techniques (42%)

Coverage Breakdown:
- Execution tactics: ✅ Strong (82%)
- Persistence: ⚠️ Weak (54%)
- Defense Evasion: 🔴 Critical gap (38%)
```

**Risk Assessment:** MEDIUM-HIGH
- Likely detection scenario: Initial access + reconnaissance detected
- Blind gap: Post-compromise persistence and lateral movement

### Lazarus Group (North Korea, Financial)

```
Techniques Attributed: 118
Our Coverage: 67 techniques (57%)
Blind Spots: 51 techniques (43%)

Coverage Breakdown:
- Execution tactics: ✅ Strong (79%)
- Command & Control: ⚠️ Weak (50%)
- Impact: 🔴 Critical gap (29%)
```

**Risk Assessment:** MEDIUM-HIGH
- Likely detection scenario: Initial compromise detected
- Blind gap: C2 communications, lateral movement, exfiltration

---

## Blind Spots Analysis

### 🔴 CRITICAL Blind Spots (Mitigation-Free Techniques)

These techniques have **NO mitigation** in ATT&CK, making **detection the only control**:

```
Count: 18 blind techniques in threat profile
Impact: 31% of our attack surface uncontrolled
Risk: Any exploit in these areas goes undetected without new telemetry
```

**Top 5 Blind Techniques (by actor usage):**

| Rank | Technique | Usage | Our Detection | Risk |
|------|-----------|-------|---------------|------|
| 1 | T1559.001 — COM/OLE Automation | 89% | ❌ None | 🔴 CRITICAL |
| 2 | T1218.009 — Regsvcs/Regasm | 76% | ❌ None | 🔴 CRITICAL |
| 3 | T1197 — BITS Jobs | 72% | ❌ None | 🔴 CRITICAL |
| 4 | T1574.008 — DLL Search Order | 68% | ❌ None | 🔴 CRITICAL |
| 5 | T1547.008 — LSASS Driver | 45% | ❌ None | 🔴 CRITICAL |

**Business Impact:** If any of these are exploited, we have no automated detection. Response = incident triage + manual investigation.

**Recommendation:** **EDR/XDR Implementation (See below)**

---

## Mitigation ROI Analysis

### Question: "Where should we invest next?"

**Approach:** Rank mitigations by:
1. **Coverage** = # techniques mitigated × actor prevalence
2. **Effort** = implementation complexity
3. **ROI** = coverage / effort

### Top 10 Mitigations by Impact

| Rank | Mitigation | Coverage | Effort | ROI | Status |
|------|-----------|----------|--------|-----|--------|
| 1 | **M1017 — User Training** | 34 tech (48%) | Low | ⭐⭐⭐⭐⭐ | Done |
| 2 | **M1026 — Privileged Account Mgmt** | 28 tech (39%) | Medium | ⭐⭐⭐⭐ | In Progress |
| 3 | **M1020 — Automated Exfiltration** | 22 tech (31%) | High | ⭐⭐⭐ | Planned |
| 4 | **M1040 — Behavior Prevention** | 19 tech (27%) | Very High | ⭐⭐ | Future |
| 5 | **M1037 — Filter Network Traffic** | 15 tech (21%) | Low | ⭐⭐⭐⭐ | In Progress |
| 6 | **M1028 — Operating System Hardening** | 18 tech (25%) | Medium | ⭐⭐⭐ | In Progress |
| 7 | **M1054 — Software Configuration** | 12 tech (17%) | Low | ⭐⭐⭐⭐⭐ | Done |
| 8 | **M1018 — User Account Management** | 10 tech (14%) | Low | ⭐⭐⭐⭐ | Done |
| 9 | **M1049 — Antivirus/Antimalware** | 8 tech (11%) | Low | ⭐⭐⭐ | Done |
| 10 | **M1015 — Active Directory Config** | 7 tech (10%) | Medium | ⭐⭐ | Planned |

### ROI Winners

#### 🥇 **M1017 — User Training** (ALREADY IMPLEMENTED)
- **Coverage:** 34 techniques (48% of threat profile)
- **Cost:** ~$50K/year (phishing simulation platform)
- **Effort:** Low (annually updated training)
- **ROI:** Highest; continued investment = mandatory

#### 🥈 **M1026 — Privileged Account Management** (RECOMMENDED)
- **Coverage:** 28 techniques (39% of threat profile)
- **Impact:** Blocks most lateral movement + credential theft
- **Implementation:**
  - PAM solution (e.g., BeyondTrust, CyberArk): $150K-300K first year
  - MFA enforcement: Already deployed
  - Just-In-Time (JIT) access: In progress
- **ROI:** High; reduces blast radius of any compromise

#### 🥉 **M1020 — Automated Exfiltration** (FUTURE)
- **Coverage:** 22 techniques (31%)
- **Impact:** Blocks data theft via alternate channels
- **Implementation:** DLP solution (Forcepoint, Symantec): $200K+
- **ROI:** Medium (depends on data sensitivity)

---

## Technology Investments

### Current Stack

```
✅ Endpoint:
   - Windows Defender (built-in)
   - Sysmon (free, open-source)
   
✅ Network:
   - Palo Alto Networks firewall
   - Proxy with URL filtering
   - DNS sinkhole (Infoblox)
   
✅ Email:
   - Microsoft Defender for Office 365
   - Proofpoint (advanced threat detection)
   
⚠️ Missing:
   - EDR/XDR (CrowdStrike, Defender for Endpoint)
   - PAM (Privileged Access Management)
   - SIEM correlation (currently basic)
```

### Recommended Next Investments (Q3-Q4)

#### Phase 1: EDR/XDR (Highest Priority)

**Problem Solved:** 18 blind techniques would become visible

**Options:**
1. **CrowdStrike Falcon** — $15-20 per endpoint/month
   - Pros: Excellent detection, fast, lightweight
   - Cons: High cost, vendor lock-in
   - Estimated: 500 endpoints × $18 × 12 = $108K/year

2. **Microsoft Defender for Endpoint** — $4-10 per user/month
   - Pros: Integrated with Windows, cheaper, included in some licenses
   - Cons: Less advanced than CrowdStrike
   - Estimated: 500 endpoints × $7 × 12 = $42K/year

3. **Carbon Black** — $8-15 per endpoint/month
   - Pros: Balanced price/performance
   - Cons: Older platform
   - Estimated: 500 endpoints × $12 × 12 = $72K/year

**Recommendation:** Start with **Microsoft Defender for Endpoint** (if M365 tenant exists), upgrade to **CrowdStrike** if budget allows.

**Impact:** Coverage would increase from 56% to ~78% (+22%)

---

#### Phase 2: PAM Solution (Medium Priority)

**Problem Solved:** Credential Access techniques reduced from 11 → 3 detectable

**Options:**
1. **BeyondTrust Privilege Management** — $100-200K (first year)
2. **CyberArk** — $150-300K (first year)
3. **Open-source:** hashicorp/vault + audit scripts — $20K implementation

**Recommendation:** Open-source for Phase 1 (proof of concept), CyberArk for Phase 2 (production).

**Impact:** Lateral movement = 0% success (all accounts are ephemeral JIT access)

---

## Quarterly Roadmap

### Q3 2025 (July-September)

```
Month 1: Complete 10 detection rules (targeting T1059, T1003, T1087)
Month 2: Evaluate EDR solutions (PoC with CrowdStrike + Defender)
Month 3: Expand telemetry (add Linux, cloud logs)

Target Coverage: 65%
```

### Q4 2025 (October-December)

```
Month 1: Deploy EDR/XDR across enterprise
Month 2: PAM pilot (100 privileged accounts)
Month 3: Advanced hunting playbooks

Target Coverage: 78%
```

### Q1 2026 (January-March)

```
Month 1: Full PAM rollout
Month 2: Cloud security posture (AWS/Azure audit logs)
Month 3: Threat hunting program launch

Target Coverage: 85%
```

---

## Budget Request Summary

| Item | Cost | Priority | Timeline |
|------|------|----------|----------|
| EDR/XDR (500 endpoints) | $42K-108K/year | 🔴 Critical | Q3 2025 |
| PAM Solution | $20K-300K/year | 🟠 High | Q4 2025 |
| Detection Engineer (1 FTE) | $120K/year | 🔴 Critical | Q3 2025 |
| Threat Hunting Tools | $50K/year | 🟡 Medium | Q4 2025 |
| **TOTAL (Year 1)** | **$232K-578K** | — | — |

**ROI Calculation:**
- Cost avoided if breach prevented: $1-10M (data + legal + PR)
- Probability of breach without improvements: 30%
- Expected value of prevention: $300K-3M
- **ROI: 5:1 to 13:1**

---

## Blind Spots by Technology

### Windows-Specific Gaps

```
Coverage: 56% (31 of 65 Windows-relevant techniques detected)

Blind Techniques (Detection-Only):
❌ T1559.001 — COM/OLE Automation
❌ T1218.009 — Regsvcs/Regasm  
❌ T1197 — BITS Jobs
❌ T1574.008 — DLL Search Order Hijacking

Solution: EDR/XDR monitors these via behavior analysis
```

### Linux Gaps

```
Coverage: 12% (2 of 18 Linux-relevant techniques detected)

Blind Techniques:
❌ T1548.001 — Sudo/Sudo Caching
❌ T1053.006 — At (Linux Cron)
❌ T1562 — Indicator Removal (Log Deletion)

Solution: Deploy auditd, osquery, cloud logging
```

### Cloud Gaps

```
Coverage: 8% (1 of 12 cloud-relevant techniques detected)

Blind Techniques:
❌ T1538 — Cloud Service Dashboard
❌ T1526 — Cloud Infrastructure Discovery
❌ T1526.004 — AWS S3 Bucket Enumeration

Solution: Enable CloudTrail + Azure Activity Log + AWS Config
```

---

## KPIs to Track

### Monthly Metrics

```
1. Coverage % (target: +10% per month)
2. False Positive Rate (target: < 2%)
3. Mean Time to Detect (MTTD) — target: < 5 min
4. Blind Spots Reduction (target: -5 techniques)
5. Rule Tuning Requests (target: < 20)
```

### Dashboard (For Executives)

```
Coverage: 56% ▓▓▓▓▓░░░░░░░░░░░░░░░░░░ (Target: 75%)

Top Risk:
🔴 Defense Evasion: 44% coverage → Need EDR/XDR
🔴 Blind Spots: 18 techniques → EDR solves 12

Investment ROI: $300K-1M prevented breach cost per $100K invested
```

---

## Action Items (Next 30 Days)

### 👤 Security Lead
- [ ] Approve $40-50K for EDR/XDR pilot
- [ ] Allocate 1 FTE detection engineer
- [ ] Schedule board meeting: "Threat Landscape Briefing"

### 👥 Detection Engineering
- [ ] Complete 5 high-priority detection rules
- [ ] Evaluate CrowdStrike PoC
- [ ] Document 3 false positive sources

### 🔐 Infrastructure
- [ ] Expand Windows Security Event logging
- [ ] Deploy sysmon across all endpoints
- [ ] Enable cloud audit logs (AWS/Azure)

### 📊 Leadership Communication
- [ ] Weekly: Detection rule progress
- [ ] Monthly: Coverage trend (this report)
- [ ] Quarterly: Executive briefing + budget review

---

## Appendix: Technical Reference

### Data Model

```json
{
  "coverage_report": {
    "period": "2025-07",
    "threat_profile": ["G0016", "G0032"],
    "techniques_total": 72,
    "techniques_detected": 40,
    "coverage_percent": 56,
    "blind_spots": 18,
    "by_tactic": {
      "execution": {
        "total": 14,
        "detected": 11,
        "coverage": 78,
        "blind": 3
      }
    }
  }
}
```

---

**Last Updated:** 2025-07-08  
**Next Review:** 2025-08-08  
**Questions?** Contact: security-ops@company.com  
**Tool:** Attack Analysis Workbench v2.0
