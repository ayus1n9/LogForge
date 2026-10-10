# Incident Investigation Report: Suspected Password Guessing

**Incident Case ID**: INC-20261010-001  
**Severity**: High (Level 12)  
**Assigned Analyst**: Tier 1 SOC Analyst  
**Date/Time of Investigation**: 2026-10-10 10:45:00 UTC  
**Status**: Closed - Confirmed Malicious Simulation (Synthetic Dataset Investigation)  
**Dataset Reference**: [`evidence/evidence-auth-guessing.json`](../../evidence/evidence-auth-guessing.json)

---

## 1. Executive Summary
At 10:42:15 UTC, the Wazuh SIEM engine generated Critical Alert `100103` (*Successful authentication following repeated failed attempts*). A simulated lab host (`192.168.56.50`) generated 5 consecutive failed logons against local administrator account `target_admin` across a 22-second interval, followed immediately (10 seconds later) by a successful network logon. Analysis confirms a successful brute-force/password-guessing attack simulation.

> **Note on Lab Methodology**: This investigation evaluates a synthetic test dataset representing telemetry collected from an isolated host-only lab subnet (`192.168.56.0/24`).

---

## 2. Five Ws (Triage Checklist)

| Question | Investigation Finding | Supporting Evidence |
| :--- | :--- | :--- |
| **What was detected?** | 5 rapid authentication failures followed immediately by successful logon | Wazuh Rule `100101` and Rule `100103` |
| **Which endpoint was involved?** | Hostname: `WIN-LAB-EP01` (IP: `192.168.56.101`) | Wazuh Agent ID `001` |
| **Which user was involved?** | Target Account: `target_admin` / Caller Domain: `WIN-LAB-EP01` | Event Field: `win.eventdata.targetUserName` |
| **When did it occur?** | 2026-10-10 10:41:42 UTC to 10:42:14 UTC (32 seconds total span) | Windows Security Event Timestamps |
| **Source of activity?** | Untrusted Lab Host IP: `192.168.56.50` (Internal Host-Only Lab Subnet) | Event ID 4625 / 4624 `IpAddress` |

---

## 3. Log Evidence & Timeline

```
+-- 10:41:42 UTC: Event ID 4625 (Logon Failure #1) - SubStatus 0xC000006A (Bad Password) - Source: 192.168.56.50
+-- 10:41:48 UTC: Event ID 4625 (Logon Failure #2) - SubStatus 0xC000006A (Bad Password) - Source: 192.168.56.50
+-- 10:41:52 UTC: Event ID 4625 (Logon Failure #3) - SubStatus 0xC000006A (Bad Password) - Source: 192.168.56.50
+-- 10:41:57 UTC: Event ID 4625 (Logon Failure #4) - SubStatus 0xC000006A (Bad Password) - Source: 192.168.56.50
+-- 10:42:04 UTC: Event ID 4625 (Logon Failure #5) - SubStatus 0xC000006A (Bad Password) - Source: 192.168.56.50
|   ==> Wazuh Alert 100101 FIRED (5 failures within 60 seconds; Rule Level 10)
+-- 10:42:14 UTC: Event ID 4624 (Logon Success)    - LogonType 3 (Network) - Target: target_admin - Source: 192.168.56.50
    ==> Wazuh Alert 100103 FIRED (Successful logon following repeated failures; Rule Level 12)
```

---

## 4. Assessment: Benign vs. Malicious
- **Benign Baseline Comparison**: A user mistyping a password generates isolated failures spaced over longer intervals on interactive logon (Type 2). The rapid 5-failure burst over Network Logon (Type 3) followed by immediate success confirms automated dictionary guessing.
- **Classification**: **Confirmed Malicious (Simulated)** — Mapped to MITRE ATT&CK T1110.001 (Brute Force: Password Guessing) and T1078 (Valid Accounts).

---

## 5. Analyst Recommendations & Containment Actions
1. **Immediate Containment**:
   - Temporarily disable the compromised account `target_admin`: `Disable-LocalUser -Name "target_admin"`.
   - Sever active SMB/network sessions from source `192.168.56.50`.
   - Block `192.168.56.50` at the endpoint host firewall (`New-NetFirewallRule`).
2. **Eradication & Remediation**:
   - Reset the credentials for `target_admin` to an enterprise-grade randomized passphrase.
   - Enforce Account Lockout Policy (threshold: 5 failed attempts within 15 minutes).
3. **Follow-up Monitoring**:
   - Audit Sysmon Event ID 1 (Process Create) for any commands executed under `target_admin` post-10:42:14 UTC.
