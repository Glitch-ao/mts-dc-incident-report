# Detailed Incident Timeline

## MTS Domain Controller - Unauthorized RDP Access (2025-11-04)

---

### Timeline of Events (All times in UTC)

#### **08:02:02** - Initial Unauthorized Access
- **Event:** RDP login from Tor exit node
- **Source IP:** 185.220.101.160 (Tor exit node)
- **Target System:** mts-dc.mts.local (Domain Controller)
- **Account Used:** Administrator
- **Authentication:** Successful (compromised credentials)
- **Logon Type:** RemoteInteractive (RDP)
- **Significance:** Attacker gains domain admin access to DC

---

#### **08:02:38** - Hidden PowerShell Execution
- **Event:** Hidden PowerShell process executed
- **Process:** powershell.exe
- **Command Line:** `powershell.exe -NoP -W Hidden -c Start-Process C.exe`
- **Parent Process:** Likely explorer.exe or cmd.exe
- **File Executed:** Fake MicrosoftEdgeUpdate.exe (renamed to C.exe)
- **Purpose:** Execute malicious payload with hidden window
- **MITRE ATT&CK:** T1059.001 (PowerShell)

---

#### **08:04:07** - Execution Policy Bypass
- **Event:** PowerShell script execution with bypass
- **Process:** powershell.exe
- **Command Line:** `powershell.exe -ExecutionPolicy Bypass -File 1.ps1`
- **Script:** 1.ps1 (malicious PowerShell script)
- **Purpose:** Bypass execution policy restrictions
- **MITRE ATT&CK:** T1059.001 (PowerShell), T1562 (Impair Defenses)

---

#### **08:04:11** - Persistence Establishment
- **Event:** Scheduled Task creation
- **Process:** schtasks.exe
- **Command Line:** `schtasks.exe /Create /XML 1.xml /TN Java`
- **Task Name:** "Java"
- **Task File:** 1.xml (imported XML configuration)
- **Purpose:** Establish persistence mechanism
- **Action:** Execute malicious payload on system events/schedule
- **MITRE ATT&CK:** T1053.005 (Scheduled Task/Job)

---

#### **08:05:22** - Malicious File Write (First Binary)
- **Event:** File creation on disk
- **File Path:** C:\...\[redacted].exe
- **SHA256:** `66e7676535db505fbb876840e677631ca0b8b5d81b79c08de6b3ed3da2e14589`
- **File Size:** Unknown
- **Purpose:** Stage malicious executable
- **VirusTotal Detection:** Likely flagged as malware

---

#### **08:05:43** - Malicious File Write (Second Binary)
- **Event:** File creation on disk
- **File Path:** C:\...\[redacted].exe  
- **SHA256:** `b22035c16dfbb8cd2590aa5fb8b84f2da0adbe9032ed235a424f191b9dab1837`
- **File Size:** Unknown
- **Purpose:** Additional malicious component or payload
- **VirusTotal Detection:** Likely flagged as malware

---

#### **08:15:00 - 08:32:00** - Command & Control Activity
- **Event:** Java-based payload execution and C2 beaconing
- **Process:** javaw.exe
- **Command Line:** `javaw.exe -jar C Files.exe`
- **Network Activity:** Multiple outbound connections
- **Destination:** Various external IPs (C2 infrastructure)
- **Behavior:** Short periodic beacons (heartbeat/keep-alive)
- **Data Transfer:** Minimal outbound traffic (beacons only)
- **MITRE ATT&CK:** T1071 (Application Layer Protocol)

---

#### **08:32:41** - Automated Investigation Triggered
- **Event:** Microsoft Defender automated investigation initiated
- **Process:** SenseIR.exe (Microsoft Defender for Endpoint)
- **Trigger:** Behavioral detection of suspicious activity
  - PowerShell execution with hidden window
  - Scheduled task creation
  - Unknown binary execution
  - Outbound C2 connections
- **Action:** Begin automated threat analysis and containment
- **Response:** Host isolation preparation

---

#### **08:32:41+** - Data Collection for Forensics
- **Event:** PowerShell DataCollection script execution
- **Process:** powershell.exe (automated by Defender)
- **Purpose:** Collect forensic artifacts for investigation
- **Data Collected:**
  - Process listings
  - Network connections
  - File system artifacts
  - Registry keys
  - Event logs
  - Memory dumps (if configured)

---

#### **08:42:48** - Remediation Completed
- **Event:** Automated remediation finalized
- **Process:** wermgr.exe (Windows Error Reporting Manager)
- **Actions Taken:**
  - Host isolated from network
  - Malicious processes terminated
  - Scheduled task "Java" removed
  - Malicious files quarantined
  - C2 connections blocked
- **Status:** Threat contained
- **Next Steps:** Manual investigation and credential rotation required

---

## Post-Incident Actions Taken

### Immediate Response (Day 0)
- ✅ Host isolated and contained
- ✅ Malicious persistence removed
- ✅ Administrator credentials rotated
- ✅ IOCs (IPs, hashes, domains) blocked
- ✅ Forensic data collected

### Follow-Up Actions (Day 1+)
- ✅ Full investigation report completed
- ⚠️ Domain controller rebuild recommended
- ⚠️ MFA enforcement on all admin accounts
- ⚠️ RDP access restriction via VPN/JIT
- ⚠️ Network segmentation review

---

## Key Observations

### Attack Duration
- **Initial Access to Detection:** ~30 minutes
- **Detection to Containment:** ~10 minutes
- **Total Compromise Window:** ~40 minutes

### Why Detection Took 30 Minutes
The initial RDP login appeared legitimate (valid credentials) and did not trigger immediate alerts. Defender only escalated once:
- Hidden PowerShell execution detected
- Unauthorized scheduled tasks created
- Unknown binaries executed
- C2 network beaconing observed

### Positive Indicators
- ✅ No lateral movement detected
- ✅ No data exfiltration observed
- ✅ No access to file servers or client data
- ✅ Fast automated containment once detected
- ✅ Complete forensic telemetry available

### Risk Factors
- ⚠️ Domain admin access achieved
- ⚠️ 30-minute window before detection
- ⚠️ Persistence mechanism established
- ⚠️ Multiple malicious binaries deployed

---

## Forensic Evidence Sources

### Telemetry Used for Timeline
- Microsoft Defender for Endpoint alerts
- DeviceLogonEvents (RDP authentication)
- DeviceProcessEvents (PowerShell, schtasks, java execution)
- DeviceFileEvents (malicious file writes)
- DeviceNetworkEvents (C2 beaconing)
- Windows Security Event Logs (Event ID 4624, 4625)
- Scheduled Task logs

---

**Report Generated:** 2025-11-05  
**Analyst:** Abe O  
**Review Status:** Complete
