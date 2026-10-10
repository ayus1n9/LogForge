# LogForge: Windows Security Monitoring & Threat Detection Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![SIEM: Wazuh](https://img.shields.io/badge/SIEM-Wazuh%20v4.9-blue)](https://wazuh.com)
[![Telemetry: Sysmon](https://img.shields.io/badge/Telemetry-Sysmon%20v15-green)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Framework: MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)](https://attack.mitre.org)

A hands-on Security Information and Event Management (SIEM) and detection engineering lab designed for **SOC Analyst Tier 1 / Junior Detection Analyst** roles. **LogForge** collects Windows security and Sysmon telemetry, applies custom detection rules to detect attacker behavior, validates detections using controlled adversarial and benign scenarios, and provides detailed incident triage playbooks.

---

## 🎯 Lab Objectives

Rather than simply setting up Wazuh and capturing dashboard views, this project implements a rigorous detection engineering lifecycle:
- **Telemetry Instrumentation**: Fine-tune Windows Event Logs and Sysmon filtering to capture high-value signals (Events 4625, 4720, Sysmon 1, 3, 7, 11, 22) while minimizing log volume.
- **Custom Detection Engineering**: Author custom Wazuh XML rulesets for brute force, privilege escalation, obfuscated PowerShell, and LOLBIN outbound connections.
- **Adversary Simulation & Benign Baselines**: Execute controlled PowerShell attack techniques alongside benign admin actions to assess false positives.
- **SOC Triage & Incident Reporting**: Complete thorough incident investigation reports using the 5 Ws framework, evidence timelines, and remediation playbooks.

---

## 🏛️ Lab Architecture

```
                Windows Monitoring Endpoint
              ┌─────────────────────────────┐
              │ Windows 10/11 Workstation   │
              │ Sysmon Telemetry Filter     │
              │ Windows Security Auditing   │
              │ Wazuh Agent (Encrypted TLS) │
              └──────────────┬──────────────┘
                             │
                  TCP Port 1514 (Encrypted)
                             │
                             ▼
              ┌─────────────────────────────┐
              │ Wazuh Manager (SIEM Engine) │
              │                             │
              │ - Custom Decoders & Rules   │
              │ - Event Correlation Engine  │
              │ - MITRE ATT&CK Tagging      │
              └──────────────┬──────────────┘
                             │
                             ▼
              ┌─────────────────────────────┐
              │ Wazuh Dashboard & Indexer   │
              │                             │
              │ - Alert Triage Workflows    │
              │ - Investigation Drilldowns  │
              │ - Threat Hunting Dashboards │
              └─────────────────────────────┘
```

---

## 🛡️ Detection Pack Overview

| Rule ID | Severity | Detection Objective | Data Source | MITRE ATT&CK |
| :--- | :--- | :--- | :--- | :--- |
| **`100100`** | Level 3 | Windows Failed Logon Attempt (Event 4625) | Security Log | [T1110](https://attack.mitre.org/techniques/T1110/) |
| **`100101`** | Level 10 | Password Guessing / Brute Force (5+ failures in 60s) | Security Log | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| **`100103`** | Level 12 | Successful Logon Following Repeated Failures | Security Log | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078](https://attack.mitre.org/techniques/T1078/) |
| **`100200`** | Level 8 | New Local User Account Created (Event 4720) | Security Log | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) |
| **`100202`** | Level 11 | User Added to Privileged Group (Administrators) | Security Log | [T1098](https://attack.mitre.org/techniques/T1098/), [T1078.003](https://attack.mitre.org/techniques/T1078/003/) |
| **`100301`** | Level 8 | Suspicious PowerShell Execution (Bypass / IEX) | Sysmon Event 1 | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| **`100302`** | Level 9 | Obfuscated PowerShell with Encoded Commands | Sysmon Event 1 | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027](https://attack.mitre.org/techniques/T1027/) |
| **`100303`** | Level 8 | Binary Execution from User-Writable Paths (AppData/Temp) | Sysmon Event 1 | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) |
| **`100305`** | Level 10 | LOLBIN Outbound Connection on Non-Standard Port | Sysmon Event 3 | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |

---

## 🔍 Incident Investigation Exercises

The lab includes two full SOC Tier 1 incident investigation reports detailing initial detection, timeline reconstruction, payload deobfuscation, and remediation:

1. **[Investigation 1: Suspected Password Guessing & Compromise](investigations/password-guessing/incident-report.md)**:
   - Analysis of rapid Windows Event 4625 bursts followed by Event 4624 (Logon Type 3).
   - Root cause analysis, attacker IP attribution, and host isolation procedure.
2. **[Investigation 2: Suspicious Process Execution & Reverse Shell](investigations/suspicious-process/incident-report.md)**:
   - Triage of obfuscated PowerShell execution (`-EncodedCommand`) spawned via `cmd.exe`.
   - Payload deobfuscation revealing a .NET socket reverse shell targeting outbound TCP port 4444.

---

## 🔬 Testing & False-Positive Analysis

Detection engineering requires proving both what a rule detects and understanding when it will produce noise.

- **[Detection Test Matrix](tests/detection-test-matrix.md)**: Covers trigger scripts, expected firing alerts, and negative tests.
- **[Validation & False-Positive Analysis](tests/validation-results.md)**: Documents legitimate software behaviors (Teams, Zoom, SCCM deployment scripts) and tuning strategies applied to eliminate false positives.

---

## 🚀 Quickstart & Reproduction

### 1. Deploy Wazuh SIEM
Follow the [Installation Guide](docs/installation.md) to launch Wazuh via Docker:
```bash
git clone https://github.com/wazuh/wazuh-docker.git --depth=1 -b v4.9.0
cd wazuh-docker/single-node
docker compose up -d
```

### 2. Configure Windows Telemetry & Sysmon
1. Deploy the tailored Sysmon configuration located at [`sysmon/sysmonconfig-tailored.xml`](sysmon/sysmonconfig-tailored.xml).
2. Install the Wazuh agent on the Windows target and configure `ossec.conf` to monitor `Security`, `System`, and `Microsoft-Windows-Sysmon/Operational`.

### 3. Deploy Custom Rules
Copy rules from `detections/` to `/var/ossec/etc/rules/` on the Wazuh Server and restart the manager.

### 4. Execute Test Scenarios
Run the simulation script in PowerShell:
```powershell
.\scripts\simulate_attacks.ps1 -Scenario BruteForce
.\scripts\simulate_attacks.ps1 -Scenario EncodedPS
.\scripts\simulate_attacks.ps1 -Scenario Benign
```

---

## 📂 Repository Structure

```
LogForge/
├── README.md                               # Project overview and portfolio documentation
├── LICENSE                                 # MIT Open Source License
├── .gitignore                              # Excludes sensitive data and large VM artifacts
├── docs/
│   ├── architecture.md                     # Topology, network flow, and resource profile
│   ├── installation.md                     # Step-by-step Wazuh and agent deployment
│   ├── detection-engineering.md            # Rationale, life cycle, and blind spots
│   └── troubleshooting.md                  # Diagnostics for connectivity and telemetry issues
├── detections/
│   ├── authentication-rules.xml            # Brute-force & compromise rules
│   ├── account-management-rules.xml        # User creation & privilege escalation rules
│   └── process-detection-rules.xml         # Sysmon process, PowerShell & LOLBIN rules
├── sysmon/
│   └── sysmonconfig-tailored.xml           # Tailored Sysmon configuration
├── tests/
│   ├── detection-test-matrix.md            # Test matrix for adversary & benign scenarios
│   └── validation-results.md               # False-positive analysis and tuning notes
├── investigations/
│   ├── password-guessing/
│   │   └── incident-report.md              # Incident Report 1: Brute force & account compromise
│   └── suspicious-process/
│       └── incident-report.md              # Incident Report 2: Encoded PowerShell & reverse shell
├── evidence/
│   ├── README.md                           # Evidence catalog and methodology
│   ├── evidence-auth-guessing.json         # 5 failed logons & compromise trace
│   ├── evidence-privilege-escalation.json  # User creation & Administrators group addition trace
│   └── evidence-sysmon-encoded-ps.json     # Encoded reverse shell & socket trace
└── scripts/
    ├── simulate_attacks.ps1                # Hardened PowerShell adversary simulation tool
    └── log_generator.py                    # Automated detection test harness & log replayer
```

---

## 👤 Author
**Ayush Singh**  
- Portfolio / GitHub: [@ayus1n9](https://github.com/ayus1n9)
- Repository: [LogForge](https://github.com/ayus1n9/LogForge)
