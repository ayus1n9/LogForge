# LogForge 7-Day Implementation Roadmap & Milestone Tracker

This document outlines the structured 7-day development roadmap and operational milestones for the **LogForge** SOC Lab.

---

## 📅 Roadmap Overview

```
[Day 1: Foundation] ──> [Day 2: Telemetry] ──> [Day 3: Auth Rules] ──> [Day 4: Process Rules]
        │
        ▼
[Day 5: Triage & Reports] ──> [Day 6: Testing & Tuning] ──> [Day 7: Release & Portfolio]
```

---

## 📋 Phased Milestones & Deliverables

### Milestone 1: Lab Foundation & Scaffolding
- [x] Initialize Git repository (`ayus1n9/LogForge`) with MIT license, `.gitignore`, and directory hierarchy.
- [x] Design and document the lab network architecture, communication ports, and resource profile ([`docs/architecture.md`](architecture.md)).
- [x] Step-by-step deployment guide for Docker single-node Wazuh and Windows agent ([`docs/installation.md`](installation.md)).

### Milestone 2: Endpoint Telemetry Collection & Sysmon
- [x] Author tailored Sysmon XML configuration with targeted rule groups and discrete logic ([`sysmon/sysmonconfig-tailored.xml`](../sysmon/sysmonconfig-tailored.xml)):
  - Event ID 1: Process Creation (CLI patterns & user paths).
  - Event ID 3: Network Connection (LOLBINs on non-standard ports).
  - Event ID 7: Image Loaded (sensitive security DLLs).
  - Event ID 11: File Creation (executable dropping in user profiles).
  - Event ID 13: Registry Events (Run keys & persistence).
  - Event ID 22: DNS Queries (tunneling & anomalous TLDs).
- [x] Configure `ossec.conf` EventChannel collection and document verification steps ([`docs/telemetry-collection.md`](telemetry-collection.md)).

### Milestone 3: Authentication & Account Management Detections
- [x] Implement custom Wazuh XML rules mapped to correct default parent rules ([`detections/authentication-rules.xml`](../detections/authentication-rules.xml)):
  - Rule `100100`: Base Event 4625 failed logon (parent `60105`).
  - Rule `100101`: Correlated 5+ failed logons in 60s (MITRE T1110.001).
  - Rule `100103`: Successful logon following repeated failures (MITRE T1110 / T1078).
- [x] Implement account management and local privilege escalation rules ([`detections/account-management-rules.xml`](../detections/account-management-rules.xml)):
  - Rule `100200`: Local user creation (parent `60109` / MITRE T1136.001).
  - Rule `100201` & `100202`: Member added to local `Administrators` (parent `60144` / MITRE T1098).

### Milestone 4: Process & LOLBIN Network Detections
- [x] Implement Sysmon process and network rules using dedicated Sysmon parent IDs ([`detections/process-detection-rules.xml`](../detections/process-detection-rules.xml)):
  - Rule `100300`: Sysmon Process Creation base (parent `61603`).
  - Rule `100301`: Suspicious PowerShell bypass / download cradle (MITRE T1059.001).
  - Rule `100302`: Base64 encoded arguments `-EncodedCommand` (MITRE T1027).
  - Rule `100303`: Executable launched from user-writable directories (MITRE T1204.002).
  - Rule `100304` & `100305`: LOLBIN outbound socket connection on non-standard ports (parent `61605` / MITRE T1071.001).
- [x] Document threat modeling, telemetry requirements, and blind spots ([`docs/detection-engineering.md`](detection-engineering.md)).

### Milestone 5: SOC Triage & Incident Investigation
- [x] Standardized 8-point SOC Tier 1 Alert Triage SOP ([`docs/triage-playbook.md`](triage-playbook.md)).
- [x] Investigation Case 1: Password Guessing & Account Compromise report ([`investigations/password-guessing/incident-report.md`](../investigations/password-guessing/incident-report.md)).
- [x] Investigation Case 2: Suspicious Process Execution & Reverse Shell report ([`investigations/suspicious-process/incident-report.md`](../investigations/suspicious-process/incident-report.md)).

### Milestone 6: Detection Testing & False-Positive Analysis
- [x] Comprehensive Detection Test Matrix ([`tests/detection-test-matrix.md`](../tests/detection-test-matrix.md)).
- [x] In-depth qualitative False-Positive Analysis and tuning recommendations ([`tests/validation-results.md`](../tests/validation-results.md)).
- [x] Automated Python detection test harness with assertion logic ([`scripts/log_generator.py`](../scripts/log_generator.py)).
- [x] Safe, parameterized PowerShell adversary simulation script with elevation checks and try/finally cleanup ([`scripts/simulate_attacks.ps1`](../scripts/simulate_attacks.ps1)).

### Milestone 7: Release & Portfolio Polish
- [x] Professional portfolio README with architecture diagrams, MITRE ATT&CK tables, and quickstart commands ([`README.md`](../README.md)).
- [x] Complete synthetic evidence catalog ([`evidence/`](../evidence/)).
- [x] Troubleshooting manual for common lab failures ([`docs/troubleshooting.md`](troubleshooting.md)).
