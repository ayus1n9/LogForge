# Detection Validation & Qualitative False-Positive Analysis

## 1. Summary of Validation Strategy

Validation for LogForge is conducted through a multi-stage approach combining synthetic unit test assertion (`scripts/log_generator.py`), controlled Windows endpoint script simulation (`scripts/simulate_attacks.ps1`), and qualitative evaluation of common enterprise benign administrative patterns.

---

## 2. In-Depth False-Positive Analysis by Use Case

### Case 1: Repeated Failed Logons (Rule `100101`) vs. Benign User Error
- **The Challenge**: Users frequently mistype complex passwords in enterprise setups, or expired corporate password prompts trigger automated retry attempts.
- **Benign Scenario**: An employee logs in after a weekend and mistypes their password twice.
  - **Result**: Generates two `4625` events (Rule `100100`, Level 3), but does **not** trigger Rule `100101` (frequency threshold = 5 in 60s).
- **Automated Service Failure**: An outdated scheduled task or background credential manager attempts sync every 10 seconds with expired credentials.
  - **Tuning Recommendation**: Whitelist known service accounts or filter by `win.eventdata.logonType = 2` (Interactive) / `3` (Network) to distinguish interactive attacks from service misconfigurations.

---

### Case 2: PowerShell Encoded Commands (Rule `100302`)
- **The Challenge**: Microsoft Endpoint Configuration Manager (SCCM), IT automation tooling, and certain VPN agents (e.g., Cisco AnyConnect) occasionally invoke PowerShell using `-EncodedCommand` to pass multi-line scripts without escaping issues.
- **Evaluation**:
  - Administrative deployment tools executed from `C:\Program Files\SystemCenter\...` triggered the rule during baseline evaluation.
  - **Tuning Recommendation**: Exclude specific parent processes (`ParentImage`) signed by trusted corporate software or parent binaries located strictly in protected paths (`C:\Program Files\...`).

---

### Case 3: Executable from User-Writable Directories (Rule `100303`)
- **The Challenge**: Modern software like Slack, Microsoft Teams, Discord, and Zoom install helper executables directly into `C:\Users\<Username>\AppData\Local\...`.
- **Evaluation**:
  - Launching standard user-level software triggers rule `100303` if only path matching is applied.
  - **Tuning Recommendation**: Pair rule `100303` with Sysmon Event ID 7 or code signing verification. In Wazuh, combine with child process filters (e.g., flag executions from `AppData` only when spawning command interpreters `cmd.exe` or `powershell.exe`).

---

## 3. Qualitative Coverage & Tuning Retrospective

| Detection Pack | Qualitative Precision | Qualitative Recall | Primary False Positive Risk | Tuning Applied |
| :--- | :--- | :--- | :--- | :--- |
| **Authentication** | High | High | Outdated cached credentials | Frequency thresholding (5 in 60s) + TargetUserName grouping |
| **Account Management** | Very High | Very High | Legitimate IT onboarding | Filtered strictly for local privileged groups (`Administrators`) |
| **Process Execution** | Medium | High | Modern user-space apps (Teams, Zoom) | Monitored paths + suspicious argument matching |
| **LOLBIN Network** | Very High | High | Admin remote troubleshooting | Targeted non-standard high-risk ports (`4444, 8080, 1337`) |
