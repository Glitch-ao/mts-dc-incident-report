# mts-dc-incident-report

## Incident: Unauthorized RDP Logon and Malicious PowerShell Execution on Domain Controller

**Report Date:** 2025-11-05  
**Reported By:** Abe O  
**Severity Level:** Critical

---

### Executive Summary

On November 4, 2025, between 08:02 and 08:15 UTC, an unauthorized RDP login to the domain controller (mts-dc.mts.local) was detected from a Tor exit node (IP 185.220.101.160) using compromised Administrator credentials. The attacker executed hidden PowerShell commands, dropped malicious binaries (MicrosoftEdgeUpdate.exe), and established persistence via a scheduled task named "Java" running a Java-based payload (svchost.exe). 

Microsoft Defender's automated investigation isolated and remediated the host at 08:32 UTC. **No evidence of lateral movement, data access, or exfiltration was identified.**

---

### Incident Timeline

See [timeline/timeline.md](timeline/timeline.md) for detailed event-by-event breakdown.

**Key Events:**
- **08:02:02 UTC** - RDP login from Tor exit node (185.220.101.160) using Administrator account
- **08:02:38 UTC** - Hidden PowerShell executed fake MicrosoftEdgeUpdate.exe
- **08:04:07 UTC** - PowerShell execution bypass script (1.ps1) executed
- **08:04:11 UTC** - Scheduled Task "Java" created for persistence
- **08:05:22-08:05:43 UTC** - Malicious file writes detected
- **08:15-08:32 UTC** - Java payload (javaw.exe) initiated C2 connections
- **08:32:41 UTC** - Microsoft Defender automated investigation triggered
- **08:42:48 UTC** - Remediation completed, host isolated

---

### Root Cause Analysis

**Credential Compromise:** Administrator account credentials were likely obtained via brute-force attack. Investigation identified 40 failed login attempts against the Administrator account the day before the incident (consistent with automated brute-force behavior). The attacker successfully logged in the next morning on the first attempt from a Tor node, strongly suggesting prior credential compromise.

**Attack Vector:** Remote Desktop Protocol (RDP) from Tor exit node

**Attacker Actions:**
1. RDP access with valid Administrator credentials
2. Hidden PowerShell execution running fake updater binary
3. Scheduled Task ("Java") creation for persistence
4. Java-based payload executed as svchost.exe
5. Outbound C2 beaconing to multiple IPs

---

### MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Valid Accounts | T1078 |
| Initial Access | Remote Services: RDP | T1021.001 |
| Execution | PowerShell | T1059.001 |
| Persistence | Scheduled Task/Job | T1053.005 |
| Defense Evasion | Impair Defenses | T1562 |
| Command & Control | Application Layer Protocol | T1071 |

---

### Impact Assessment

- **Affected System:** Domain Controller mts-dc.mts.local
- **Compromised Account:** Administrator (domain admin privileges)
- **Scope:** Isolated to domain controller; no lateral movement detected
- **Data Exposure:** No evidence of client data, tax records, or financial information accessed
- **Exfiltration:** No large outbound traffic patterns or exfiltration detected
- **Business Impact:** Host contained and remediated; credentials rotated; IOCs blocked

---

### Current Status

✅ **CONTAINED** - Host isolated, persistence removed, credentials rotated, IOCs blocked

---

### Documentation

- **Full PDF Report:** [incident-report/MTS-DC-Incident-Report.pdf](incident-report/MTS-DC-Incident-Report.pdf)
- **Screenshots:** [screenshots/](screenshots/)
- **Detailed Timeline:** [timeline/timeline.md](timeline/timeline.md)
- **Indicators of Compromise:** [ioc-list/iocs.md](ioc-list/iocs.md)
- **Recommendations:** [recommendations.md](recommendations.md)

---

### Key Questions Addressed

#### 1. How did the attacker obtain Administrator credentials?

A burst of 40 failed login attempts was identified against the Administrator account the day before the incident, consistent with automated brute-force activity. While not definitively proven, the attacker's successful first-attempt login the next morning from a Tor exit node strongly suggests the brute-force was successful in obtaining the password.

#### 2. Why didn't automated response trigger for 30 minutes?

The initial RDP login appeared to use valid credentials and did not generate an automatic response. Microsoft Defender only escalated the incident once the attacker began disabling security controls and executing suspicious scripts—these behavioral signals triggered the automated investigation at 08:32 UTC.

#### 3. Was any data accessed or exfiltrated?

**No.** Comprehensive analysis of endpoint, identity, and network telemetry confirmed:
- No lateral movement to other systems
- No access to file servers or client data repositories
- No large outbound traffic or exfiltration patterns
- Only short C2 beacons detected from the malware

---



---

### Repository Structure

```
mts-dc-incident-report/
│
├── README.md (this file)
├── incident-report/
│   └── MTS-DC-Incident-Report.pdf
├── screenshots/
│   ├── screenshot-1.png
│   ├── screenshot-2.png
│   └── ...
├── timeline/
│   └── timeline.md
├── ioc-list/
│   └── iocs.md
└── recommendations.md
```
