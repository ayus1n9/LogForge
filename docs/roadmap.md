# LogForge 7-Day Implementation Roadmap & Milestone Tracker

This document tracks the phased day-by-day implementation of the **LogForge** SOC Lab, adhering strictly to the structured 7-day plan from the project specification.

---

## 📅 Roadmap Overview

```
[Day 1: Foundation] ──> [Day 2: Telemetry] ──> [Day 3: Auth Rules] ──> [Day 4: Process Rules]
        │
        ▼
[Day 5: Triage & Reports] ──> [Day 6: Testing & Tuning] ──> [Day 7: Release & Portfolio]
```

---

## 📋 Daily Deliverables & Status

### ✅ Day 1: Working Lab Foundation (v0.1.0)
- [x] Initialize Git repository (`ayus1n9/LogForge`) with MIT license, `.gitignore`, and directory hierarchy.
- [x] Design and document the lab network architecture, communication ports, and resource consumption profile (`docs/architecture.md`).
- [x] Create step-by-step installation instructions for Wazuh single-node Docker and Windows agent (`docs/installation.md`).
- [x] Tag and publish release: `v0.1.0`.

---

### ✅ Day 2: Endpoint Telemetry Collection (v0.2.0)
- [x] Tailor Sysmon XML configuration focusing strictly on high-fidelity signals:
  - Event ID 1: Process Creation (command lines, parent PIDs, hashes).
  - Event ID 3: Network Connection (outbound socket connections from LOLBINs).
  - Event ID 7: Image Loaded (DLL monitoring).
  - Event ID 11: File Creation (user-writable directories and persistence paths).
  - Event ID 22: DNS Query (suspicious TLDs and anomalies).
- [x] Configure `ossec.conf` event channels (`Security`, `System`, `Microsoft-Windows-Sysmon/Operational`).
- [x] Document telemetry verification commands and agent ingestion checks (`docs/telemetry-collection.md`).
- [x] Commit and tag: `v0.2.0`.

---

### ✅ Day 3: Initial Detection Pack — Authentication & Account Management (v0.3.0)
- [x] Implement custom Wazuh XML rules:
  - Repeated failed logons (Windows Event 4625 threshold correlation).
  - Successful logon following repeated failures (Account compromise indicator).
  - Local user creation (Event ID 4720).
  - Privileged group addition (Event ID 4732 / `Administrators`).
- [x] Test and validate rule syntax with `wazuh-logtest`.
- [x] Commit and tag: `v0.3.0`.

---

### ✅ Day 4: Process & LOLBIN Detections (v0.4.0)
- [x] Implement custom Wazuh XML rules:
  - Suspicious PowerShell cradle patterns (`-nop`, `-exec bypass`, `IEX`, `DownloadString`).
  - Base64 encoded PowerShell arguments (`-EncodedCommand`, `-enc`).
  - Binaries executing from user-writable directories (`AppData`, `Temp`).
  - LOLBIN outbound network connections to non-standard ports (`4444`, `8080`, `1337`).
- [x] Document telemetry dependencies and blind spots (`docs/detection-engineering.md`).
- [x] Commit and tag: `v0.4.0`.

---

### ✅ Day 5: Triage Playbooks & Incident Investigations (v0.5.0)
- [x] Create standardized SOC Tier 1 Alert Triage Guide (`docs/triage-playbook.md`).
- [x] Conduct Investigation Exercise 1: Suspected Password Guessing & Compromise report.
- [x] Conduct Investigation Exercise 2: Suspicious Process Execution & Reverse Shell report.
- [x] Commit and tag: `v0.5.0`.

---

### ✅ Day 6: Testing, Benign Validation & False-Positive Tuning (v0.6.0)
- [x] Comprehensive Detection Test Matrix (`tests/detection-test-matrix.md`).
- [x] False-positive tuning documentation covering legitimate administrative noise and third-party software (`tests/validation-results.md`).
- [x] Build automated synthetic log replayer script (`scripts/log_generator.py`) and PowerShell attack simulation script (`scripts/simulate_attacks.ps1`).
- [x] Commit and tag: `v0.6.0`.

---

### ✅ Day 7: Portfolio Release & Final Polish (v1.0.0)
- [x] Professional portfolio README polish with MITRE ATT&CK coverage badges and architecture diagrams.
- [x] Sample log evidence captures in `evidence/`.
- [x] Complete walkthrough and final verification.
- [x] Commit and tag: `v1.0.0`.
