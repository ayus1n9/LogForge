# Incident Investigation Report: Suspected Password Guessing

**Incident Case ID**: INC-20261010-001  
**Severity**: High (Level 12)  
**Assigned Analyst**: Tier 1 SOC Analyst  
**Date/Time of Investigation**: 2026-10-10 10:45:00 UTC  
**Status**: Closed - Confirmed Malicious Simulation  

---

## 1. Executive Summary
At 10:42:15 UTC, the Wazuh SIEM engine generated Critical Alert `100103` (*Successful authentication following repeated failed attempts*). An external/untrusted workstation generated 6 consecutive failed logons against local administrator account `target_admin` across a 28-second interval, followed immediately by a successful logon. Analysis indicates a successful brute-force/password-guessing attack.

---

## 2. Five Ws (Triage Checklist)

| Question | Investigation Finding | Supporting Evidence |
| :--- | :--- | :--- |
| **What was detected?** | Rapid authentication failures followed immediately by successful logon | Wazuh Rule `100101` and Rule `100103` |
| **Which endpoint was involved?** | Hostname: `WIN-LAB-EP01` (IP: `192.168.56.101`) | Wazuh Agent ID `001` |
| **Which user was involved?** | Target Account: `target_admin` / Caller Domain: `WIN-LAB-EP01` | Event Field: `win.eventdata.targetUserName` |
| **When did it occur?** | 2026-10-10 10:41:40 UTC to 10:42:15 UTC | Windows Event Timestamp log stream |
| **Source of activity?** | Remote Source IP: `192.168.56.50` (Workstation Name: `ATTACKER-BOX`) | Event ID 4625 `IpAddress` & `WorkstationName` |

---

## 3. Log Evidence & Timeline

```
+-- 10:41:42 UTC: Event ID 4625 (Logon Failure) - SubStatus 0xC000006A (Bad Password) - Source: 192.168.56.50
+-- 10:41:48 UTC: Event ID 4625 (Logon Failure) - SubStatus 0xC000006A (Bad Password) - Source: 192.168.56.50
+-- 10:41:52 UTC: Event ID 4625 (Logon Failure) - SubStatus 0xC000006A (Bad Password) - Source: 192.168.56.50
+-- 10:41:57 UTC: Event ID 4625 (Logon Failure) - SubStatus 0xC000006A (Bad Password) - Source: 192.168.56.50
+-- 10:42:04 UTC: Event ID 4625 (Logon Failure) - SubStatus 0xC000006A (Bad Password) - Source: 192.168.56.50
|   ==> Wazuh Alert 100101 FIRED (5 failures within 60 seconds)
+-- 10:42:14 UTC: Event ID 4624 (Logon Success) - LogonType 3 (Network) - Target: target_admin - Source: 192.168.56.50
    ==> Wazuh Alert 100103 FIRED (Level 12 - Account Compromise Alert)
```

---

## 4. Assessment: Benign vs. Malicious
- **Benign Probability**: < 5%. A user mistyping a password does not generate 6 failures with sequential dictionary timestamps within seconds over a Network Logon (Type 3).
- **Classification**: **Confirmed Malicious** (Simulated adversary brute-force activity mapped to MITRE ATT&CK T1110.001).

---

## 5. Analyst Recommendations & Containment Actions
1. **Immediate Containment**:
   - Temporarily disable the compromised account `target_admin` via PowerShell: `Disable-LocalUser -Name "target_admin"`.
   - Terminate any active network sessions from source `192.168.56.50`.
   - Block `192.168.56.50` at the local firewall / network perimeter.
2. **Eradication & Remediation**:
   - Reset the credentials for `target_admin` to a 20+ character randomized passphrase.
   - Implement account lockout thresholds via Local Security Policy (e.g., lock after 5 failed attempts for 15 minutes).
3. **Follow-up Monitoring**:
   - Pivot on `target_admin` to audit all processes spawned on `WIN-LAB-EP01` post-10:42:14 UTC (Sysmon Event ID 1) for signs of persistence or lateral movement.
