# Indicators of Compromise (IOCs)

## MTS Domain Controller Incident - 2025-11-04

---

## Network Indicators

### IP Addresses

#### Attacker Source IP
- **185.220.101.160** (Tor exit node)
  - **First Seen:** 2025-11-04 08:02:02 UTC
  - **Activity:** RDP logon to mts-dc.mts.local
  - **Threat Intel:** Known Tor exit node, multiple abuse reports
  - **Action:** Block at firewall, add to threat intelligence feed
  - **VirusTotal:** [Check IP](https://www.virustotal.com/gui/ip-address/185.220.101.160)

---

### Domains

#### Suspicious Domains
- **filebin.net**
  - **Activity:** Likely used for malware staging or data exfiltration
  - **Action:** Block at DNS/web proxy level

---

## File Indicators

### Malicious Files

#### File 1: MicrosoftEdgeUpdate.exe (renamed to C.exe)
- **SHA256:** `66e7676535db505fbb876840e677631ca0b8b5d81b79c08de6b3ed3da2e14589`
- **File Path:** C:\...\[redacted].exe
- **File Size:** Unknown
- **First Seen:** 2025-11-04 08:05:22 UTC
- **Behavior:** Fake browser updater, executes via hidden PowerShell
- **YARA Rule:** Custom detection recommended
- **Action:** Quarantine, submit to VirusTotal
- **VirusTotal:** [Check Hash](https://www.virustotal.com/gui/file/66e7676535db505fbb876840e677631ca0b8b5d81b79c08de6b3ed3da2e14589)

#### File 2: Secondary Malicious Binary
- **SHA256:** `b22035c16dfbb8cd2590aa5fb8b84f2da0adbe9032ed235a424f191b9dab1837`
- **File Path:** C:\...\[redacted].exe
- **File Size:** Unknown
- **First Seen:** 2025-11-04 08:05:43 UTC
- **Behavior:** Secondary payload or persistence component
- **Action:** Quarantine, submit to VirusTotal
- **VirusTotal:** [Check Hash](https://www.virustotal.com/gui/file/b22035c16dfbb8cd2590aa5fb8b84f2da0adbe9032ed235a424f191b9dab1837)

#### File 3: Java-based Payload
- **File Name:** svchost.exe (masquerading as Windows process)
- **Original Name:** C Files.exe (JAR-based)
- **SHA256:** Not available in logs
- **Behavior:** Executed via javaw.exe, C2 beaconing
- **Action:** Hunt for Java processes executing suspicious files

---

## Process Indicators

### Malicious Process Patterns

#### Hidden PowerShell Execution
```
powershell.exe -NoP -W Hidden -c Start-Process C.exe
```
- **Detection:** PowerShell with "-W Hidden" and "-NoP" flags
- **MITRE ATT&CK:** T1059.001 (PowerShell)

#### Execution Policy Bypass
```
powershell.exe -ExecutionPolicy Bypass -File 1.ps1
```
- **Detection:** "-ExecutionPolicy Bypass" flag
- **MITRE ATT&CK:** T1059.001, T1562

#### Scheduled Task Creation
```
schtasks.exe /Create /XML 1.xml /TN Java
```
- **Task Name:** "Java"
- **Detection:** Scheduled task creation with suspicious XML import
- **MITRE ATT&CK:** T1053.005

#### Java-based C2
```
javaw.exe -jar C Files.exe
```
- **Detection:** javaw.exe executing non-standard JAR files
- **MITRE ATT&CK:** T1071

---

## Account Indicators

### Compromised Accounts
- **Administrator@[Redacted]**
  - **First Compromise:** Suspected 2025-11-03 (brute-force activity)
  - **Confirmed Use:** 2025-11-04 08:02:02 UTC (RDP from Tor)
  - **Action:** Password rotated, enforce MFA

---

## Behavioral Indicators

### Authentication Anomalies
- RDP login from Tor exit node (185.220.101.160)
- Administrator account used outside business hours
- No multi-factor authentication

### Process Anomalies
- PowerShell with hidden window execution
- Execution policy bypass
- Suspicious scheduled task creation
- Java process executing from non-standard location

### Network Anomalies
- Outbound connections from javaw.exe to unknown external IPs
- Short periodic beacons (C2 heartbeat pattern)
- Connections to filebin.net

---

## KQL Hunting Queries (Microsoft Defender)

### Query 1: Hunt for RDP Logins from Tor Exit Nodes
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-03) .. now())
| where LogonType == "RemoteInteractive"
| where RemoteIP in ("185.220.101.160") 
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType, ActionType
| order by TimeGenerated desc
```

### Query 2: Hunt for Hidden PowerShell Execution
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-03) .. now())
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-W Hidden", "-WindowStyle Hidden", "-NoP")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### Query 3: Hunt for Execution Policy Bypass
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-03) .. now())
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-ExecutionPolicy Bypass"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc
```

### Query 4: Hunt for Suspicious Scheduled Task Creation
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-03) .. now())
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("/Create", "/XML")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc
```

### Query 5: Hunt for Java-based C2 Activity
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-03) .. now())
| where FileName in~ ("java.exe", "javaw.exe")
| where ProcessCommandLine has "-jar"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### Query 6: Hunt for Malicious File Hashes
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-03) .. now())
| where SHA256 in (
    "66e7676535db505fbb876840e677631ca0b8b5d81b79c08de6b3ed3da2e14589",
    "b22035c16dfbb8cd2590aa5fb8b84f2da0adbe9032ed235a424f191b9dab1837"
)
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, ActionType
| order by TimeGenerated desc
```

### Query 7: Hunt for Outbound Connections from Java Processes
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-03) .. now())
| where InitiatingProcessFileName in~ ("java.exe", "javaw.exe")
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated desc
```

### Query 8: Comprehensive Incident Timeline
```kql
let StartTime = datetime(2025-11-04 07:00);
let EndTime = datetime(2025-11-04 09:00);
let TargetDevice = "mts-dc.mts.local";
union
    (DeviceLogonEvents
    | where TimeGenerated between (StartTime .. EndTime)
    | where DeviceName == TargetDevice
    | project TimeGenerated, EventType = "Logon", Details = strcat("User: ", AccountName, " | IP: ", RemoteIP)),
    (DeviceProcessEvents
    | where TimeGenerated between (StartTime .. EndTime)
    | where DeviceName == TargetDevice
    | where FileName in~ ("powershell.exe", "schtasks.exe", "java.exe", "javaw.exe")
    | project TimeGenerated, EventType = "Process", Details = ProcessCommandLine),
    (DeviceFileEvents
    | where TimeGenerated between (StartTime .. EndTime)
    | where DeviceName == TargetDevice
    | where ActionType == "FileCreated"
    | project TimeGenerated, EventType = "FileCreated", Details = strcat("File: ", FileName, " | Path: ", FolderPath)),
    (DeviceNetworkEvents
    | where TimeGenerated between (StartTime .. EndTime)
    | where DeviceName == TargetDevice
    | where RemoteIPType == "Public"
    | project TimeGenerated, EventType = "NetworkConnection", Details = strcat("Process: ", InitiatingProcessFileName, " | Remote IP: ", RemoteIP))
| order by TimeGenerated asc
```

---

## Detection Rules (Sigma Format)

### Rule 1: Hidden PowerShell Execution
```yaml
title: Hidden PowerShell Execution Detected
id: dc5b8ed1-2b3a-4c9f-9d2e-3f4a5b6c7d8e
status: stable
description: Detects PowerShell execution with hidden window parameters
author: SOC Team
date: 2025-11-05
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-W Hidden'
      - '-WindowStyle Hidden'
  condition: selection
falsepositives:
  - Legitimate administrative scripts
level: high
```

### Rule 2: Execution Policy Bypass
```yaml
title: PowerShell Execution Policy Bypass
id: e6c7d8f9-3a4b-5c6d-7e8f-9a0b1c2d3e4f
status: stable
description: Detects attempts to bypass PowerShell execution policy
author: SOC Team
date: 2025-11-05
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-ExecutionPolicy Bypass'
  condition: selection
falsepositives:
  - Legitimate administrative tasks
level: medium
```

---

## Threat Intelligence Context

### Threat Actor Profile
- **Sophistication:** Medium
- **TTPs:** Credential compromise, RDP abuse, PowerShell, scheduled tasks, Java-based malware
- **Anonymization:** Tor exit nodes
- **Objective:** Likely persistence and potential data exfiltration (contained before objective achieved)

### Similar Campaigns
- RDP brute-force campaigns targeting exposed admin accounts
- Tor-based intrusions for anonymization
- PowerShell-based malware deployment

---

## Response Actions

### Immediate
- Block IP 185.220.101.160 at firewall
- Quarantine malicious file hashes
- Remove scheduled task "Java"
- Rotate Administrator credentials
- Isolate mts-dc.mts.local

### Short-Term
- Deploy IOC hunting queries across environment
- Review all RDP logins from public IPs
- Implement MFA on all admin accounts
- Restrict RDP to VPN-only access

### Long-Term
- Rebuild domain controller from trusted backup
- Implement JIT (Just-in-Time) privileged access
- Deploy network segmentation
- Enhance endpoint detection coverage

---

**Report Updated:** 2025-11-05  
**Analyst:** Abe O  
**Classification:** TLP:AMBER
