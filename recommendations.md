# Security Recommendations

## Post-Incident Remediation and Hardening  
**MTS Domain Controller Incident - 2025-11-04**

---

## Executive Summary

Following the unauthorized RDP access to the domain controller (mts-dc.mts.local) on November 4, 2025, the following recommendations are provided to prevent similar incidents and strengthen the organization's security posture. These recommendations are categorized by priority and timeframe.

---

## Immediate Actions (Complete Within 24-48 Hours)

### 1. Confirm Automated Containment
- ✅ **Status:** COMPLETED
- **Action:** Verify Microsoft Defender isolated mts-dc.mts.local and removed all malicious artifacts
- **Validation:**
  - Confirm scheduled task "Java" has been deleted
  - Verify malicious binaries (SHA256: 66e7676535db..., b22035c16dfbb...) are quarantined
  - Confirm C2 network connections are blocked

### 2. Credential Rotation
- ✅ **Status:** COMPLETED
- **Action:** Rotate Administrator and all domain admin credentials
- **Additional Steps:**
  - Reset passwords for all service accounts
  - Invalidate all existing Kerberos tickets (TGTs)
  - Force password reset for any accounts accessed during compromise window

### 3. Block Indicators of Compromise
- ✅ **Status:** COMPLETED
- **IOCs Blocked:**
  - IP Address: 185.220.101.160 (Tor exit node)
  - Domain: filebin.net
  - File Hashes: 66e7676535db..., b22035c16dfbb...
- **Action:** Ensure IOCs are blocked at:
  - Firewall
  - Web proxy
  - DNS filtering
  - EDR/XDR platforms

### 4. Deploy IOC Hunting Queries
- ⚠️ **Status:** IN PROGRESS
- **Action:** Run KQL hunting queries (from ioc-list/iocs.md) across all endpoints
- **Focus Areas:**
  - Additional RDP logins from Tor exit nodes
  - Hidden PowerShell execution
  - Suspicious scheduled tasks
  - Java-based C2 activity
- **Timeline:** Complete within 24 hours

---

## Short-Term Actions (Complete Within 1 Week)

### 5. Rebuild Domain Controller
- ⚠️ **Status:** RECOMMENDED
- **Rationale:** Domain admin access was achieved; rebuilding ensures no persistent backdoors
- **Steps:**
  1. Take forensic snapshot for long-term retention
  2. Promote a clean domain controller
  3. Transfer FSMO roles to clean DC
  4. Demote and wipe compromised mts-dc.mts.local
  5. Rebuild from trusted backup or fresh install
  6. Re-promote as domain controller
- **Timeline:** Within 3-5 days

### 6. Implement Multi-Factor Authentication (MFA)
- ⚠️ **Status:** CRITICAL
- **Scope:** Enforce MFA for:
  - All domain administrator accounts
  - All privileged accounts (server admins, security team)
  - Remote access (RDP, VPN)
- **Solution Options:**
  - Azure AD Conditional Access
  - Hardware tokens (YubiKey, etc.)
  - Authenticator apps (Microsoft Authenticator, Duo)
- **Timeline:** Within 1 week

### 7. Restrict RDP Access
- ⚠️ **Status:** CRITICAL
- **Actions:**
  - **Remove direct internet RDP exposure:** Disable port 3389 from public internet
  - **Implement VPN-only access:** Require VPN connection before RDP
  - **Deploy Jump Box/Bastion Host:** Central RDP gateway with logging
  - **Enable Network Level Authentication (NLA)**
  - **Implement IP allow-listing** for known admin IPs
- **Timeline:** Within 3-5 days

### 8. Implement Just-in-Time (JIT) Privileged Access
- ⚠️ **Status:** RECOMMENDED
- **Solution:** Azure AD Privileged Identity Management (PIM) or similar
- **Benefits:**
  - Admin rights granted only when needed
  - Automatic expiration of privileges
  - Approval workflows for sensitive access
  - Full audit trail
- **Timeline:** Within 1 week

---

## Medium-Term Actions (Complete Within 1 Month)

### 9. Network Segmentation
- ⚠️ **Status:** RECOMMENDED
- **Actions:**
  - Isolate domain controllers in dedicated VLAN
  - Implement firewall rules restricting DC access to:
    - Domain-joined servers (for authentication)
    - Admin jump boxes only
    - No direct workstation access
  - Deploy micro-segmentation for critical assets
- **Timeline:** Within 2-4 weeks

### 10. Enhanced Logging and Monitoring
- ⚠️ **Status:** RECOMMENDED
- **Actions:**
  - **Increase Windows Event Log retention:** Minimum 90 days
  - **Forward logs to SIEM:** Centralize DC logs in SIEM/Log Analytics
  - **Enable PowerShell Script Block Logging:** Capture all PowerShell commands
  - **Enable Process Creation Auditing (Event ID 4688):** Track process execution
  - **Deploy Sysmon** on domain controllers for enhanced telemetry
- **Timeline:** Within 2-3 weeks

### 11. Deploy Detection Rules
- ⚠️ **Status:** RECOMMENDED
- **Actions:**
  - Implement Sigma rules (from ioc-list/iocs.md) in SIEM
  - Create alerts for:
    - RDP logins from public IPs
    - Hidden PowerShell execution
    - Scheduled task creation by non-admin processes
    - Java processes executing JAR files from non-standard locations
  - Tune alert thresholds to minimize false positives
- **Timeline:** Within 2 weeks

### 12. Account Password Policy Review
- ⚠️ **Status:** RECOMMENDED
- **Actions:**
  - Increase minimum password length to 16+ characters
  - Implement password complexity requirements
  - Enable Azure AD Password Protection (ban common/compromised passwords)
  - Consider passphrase policy vs. complexity
  - Enforce password history (prevent reuse)
- **Timeline:** Within 2 weeks

### 13. Account Lockout Policy
- ⚠️ **Status:** RECOMMENDED
- **Current Issue:** 40 failed login attempts before lockout (too high)
- **Recommended:** Lockout after 5-10 failed attempts
- **Balance:** Security vs. user experience
- **Implement:** Gradual lockout (increasing delay after failures)
- **Timeline:** Within 1 week

---

## Long-Term Actions (Complete Within 3 Months)

### 14. Implement Privileged Access Workstation (PAW)
- ⚠️ **Status:** RECOMMENDED
- **Description:** Dedicated, hardened workstations for administrative tasks
- **Benefits:**
  - Isolate admin activities from regular browsing/email
  - Reduce credential theft risk
  - Enforce clean source principle
- **Timeline:** Within 2-3 months

### 15. Deploy Endpoint Detection and Response (EDR) Enhancements
- ⚠️ **Status:** IN PROGRESS
- **Actions:**
  - Validate EDR coverage on all endpoints (100% deployment)
  - Enable tamper protection
  - Configure automatic threat remediation
  - Tune behavioral detections
  - Deploy EDR on servers (not just workstations)
- **Timeline:** Within 1-2 months

### 16. Red Team / Penetration Testing
- ⚠️ **Status:** RECOMMENDED
- **Purpose:** Validate security improvements
- **Focus Areas:**
  - RDP brute-force resistance
  - MFA effectiveness
  - Network segmentation
  - Detection and response capabilities
- **Timeline:** Within 3 months (after remediation complete)

### 17. Security Awareness Training
- ⚠️ **Status:** RECOMMENDED
- **Topics:**
  - Password security best practices
  - Phishing awareness
  - Social engineering tactics
  - Reporting suspicious activity
- **Target Audience:** All employees, especially IT staff
- **Timeline:** Within 2 months

### 18. Incident Response Plan Update
- ⚠️ **Status:** RECOMMENDED
- **Actions:**
  - Document lessons learned from this incident
  - Update IR playbooks for RDP compromise scenarios
  - Conduct tabletop exercises
  - Review and update escalation procedures
- **Timeline:** Within 1 month

---

## Technology Recommendations

### Identity and Access Management
- **Azure AD Conditional Access:** Enforce MFA, device compliance, location-based policies
- **Azure AD Identity Protection:** Risk-based authentication, leaked credential detection
- **Privileged Identity Management (PIM):** JIT admin access

### Network Security
- **Next-Generation Firewall:** Deep packet inspection, IPS
- **VPN with MFA:** Secure remote access
- **DNS Filtering:** Block malicious domains

### Endpoint Protection
- **Microsoft Defender for Endpoint:** Current solution; ensure full deployment
- **Sysmon:** Enhanced endpoint telemetry
- **AppLocker/WDAC:** Application whitelisting

### SIEM and Monitoring
- **Azure Sentinel / Log Analytics:** Centralized logging and threat detection
- **Splunk / ELK Stack:** Alternative SIEM options
- **Microsoft Sentinel Threat Intelligence:** IOC correlation

---

## Risk Assessment

### Remaining Risks
- ⚠️ **Medium:** Until DC is rebuilt, residual compromise risk remains
- ⚠️ **Medium:** Without MFA, admin accounts remain vulnerable to credential theft
- ⚠️ **Low:** With IOCs blocked and credentials rotated, immediate re-compromise risk is low

### Risk Mitigation Priority
1. **CRITICAL:** Implement MFA (eliminates 99% of credential attacks)
2. **CRITICAL:** Restrict RDP access (eliminates direct exposure)
3. **HIGH:** Rebuild DC (eliminates persistence risk)
4. **HIGH:** Implement JIT access (reduces standing admin privileges)
5. **MEDIUM:** Network segmentation (limits lateral movement)

---

## Budget and Resource Considerations

### Low-Cost / No-Cost Improvements
- Credential rotation (already completed)
- Block IOCs at firewall/DNS
- Enable PowerShell logging
- Implement account lockout policies
- Restrict RDP via VPN

### Medium-Cost Improvements ($5K-$20K)
- MFA solution (hardware tokens, licensing)
- Jump box / bastion host deployment
- SIEM licensing (if not already deployed)
- Red team / penetration testing

### High-Cost Improvements ($20K+)
- Privileged Access Workstations (PAWs)
- Network segmentation infrastructure
- Comprehensive EDR deployment
- Azure AD P2 licensing (for PIM, Identity Protection)

---

## Implementation Timeline Summary

| Priority | Action | Timeline | Owner |
|----------|--------|----------|-------|
| P0 | Confirm automated containment | 24 hours | Security Team |
| P0 | Rotate all admin credentials | 24 hours | IT/Security |
| P0 | Block IOCs | 24 hours | Network Team |
| P1 | Deploy IOC hunting queries | 48 hours | Security Team |
| P1 | Implement MFA | 1 week | IT/Security |
| P1 | Restrict RDP access | 1 week | Network/IT |
| P1 | Rebuild domain controller | 1 week | IT Team |
| P2 | Network segmentation | 1 month | Network Team |
| P2 | Enhanced logging | 1 month | IT/Security |
| P2 | Deploy detection rules | 1 month | Security Team |
| P3 | Implement PAW | 3 months | IT Team |
| P3 | Red team testing | 3 months | Security Team |

---

## Compliance and Regulatory Considerations

### Potential Reporting Requirements
- **Data Breach Notification:** If client data was accessed (not applicable in this case)
- **Cyber Insurance:** Notify insurer of incident
- **Industry Regulations:** Check compliance obligations (HIPAA, PCI-DSS, etc.)

### Documentation Requirements
- Maintain forensic evidence for 1 year minimum
- Document all remediation actions
- Update security policies and procedures
- Conduct post-incident review with leadership

---

## Success Metrics

### Key Performance Indicators (KPIs)
- **Time to Detect:** Reduce from 30 minutes to <5 minutes
- **Time to Respond:** Maintain <10 minute automated response
- **MFA Adoption:** 100% for privileged accounts within 1 week
- **Failed Login Attempts:** Reduce baseline from 40+ to <10 before lockout
- **RDP Exposure:** Zero direct internet exposure
- **EDR Coverage:** 100% of endpoints

### Validation Testing
- Conduct simulated RDP brute-force (should be blocked)
- Test MFA enforcement (should prevent password-only login)
- Validate detection rules (should alert on hidden PowerShell)
- Verify network segmentation (should block unauthorized DC access)

---

**Report Prepared:** 2025-11-05  
**Author:** Abe O (SOC Lead)  
**Review Status:** Approved  
**Next Review:** 2025-12-05 (30-day follow-up)
