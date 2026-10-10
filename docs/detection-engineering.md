# Detection Engineering Methodology & Rationale

## 1. Detection Engineering Lifecycle in LogForge

LogForge implements a structured detection lifecycle modeled after industry security operations frameworks (Palantir Alerting & Detection Strategy, MITRE ATT&CK):

```
[ Threat Modeling ] ──> [ Telemetry Requirements ] ──> [ Rule Logic Formulation ]
         │                                                      │
         ▼                                                      ▼
[ Gaps & Blind Spots ] <── [ False-Positive Analysis ] <── [ Benign & Adversary Testing ]
```

---

## 2. Telemetry Requirements & Field Mappings

To avoid brittle string-matching, our detection rules target structured fields parsed from Windows Security Channels and Sysmon:

| Use Case | Data Source | Key Event Fields | Required Decoding / Pre-parsing |
| :--- | :--- | :--- | :--- |
| **Password Guessing (T1110)** | Security.evtx (4625) | `win.system.eventID`, `win.eventdata.targetUserName`, `win.eventdata.status`, `win.eventdata.ipAddress` | Windows EventChannel Decoder |
| **Privilege Escalation (T1098)** | Security.evtx (4720, 4732) | `win.system.eventID`, `win.eventdata.targetUserName`, `win.eventdata.subjectUserName` | Windows EventChannel Decoder |
| **Suspicious PowerShell (T1059.001)** | Sysmon (ID 1) | `win.eventdata.image`, `win.eventdata.commandLine`, `win.eventdata.parentImage` | Sysmon EventChannel Decoder |
| **User Directory Execution (T1204.002)**| Sysmon (ID 1) | `win.eventdata.image`, `win.eventdata.currentDirectory`, `win.eventdata.user` | Regex matching user profile paths |
| **Suspicious Network Outbound (T1071)** | Sysmon (ID 3) | `win.eventdata.image`, `win.eventdata.destinationPort`, `win.eventdata.destinationIp` | Port and binary correlation |

---

## 3. Severity & Priority Scoring Matrix

LogForge rules avoid alert fatigue by categorizing rules into progressive levels:

- **Level 3 (Informational/Base)**: Individual atomic events (single 4625 failed login, normal process creation, normal network connection). These do not page an analyst directly but serve as building blocks.
- **Level 6 - 8 (Suspicious / Medium)**: Deviations from administrative baselines (e.g., local user creation 4720, PowerShell download cradles, execution from AppData). Requires triage within standard SLA.
- **Level 10 - 12 (Critical / High)**: Direct correlation of attack phases (e.g., 5+ failed logons within 60s followed immediately by a successful logon, or LOLBIN outbound beacon on port 4444). Immediate SOC analyst intervention required.

---

## 4. Known Blind Spots & Evasion Techniques

1. **PowerShell Obfuscation & Shorthand**:
   - Adversaries can use environment variable expansion (`cmd /c "set a=-enc&& powershell %a% ..."`) or partial abbreviations (`powershell -e ...`). LogForge rules account for `-e `, `-enc `, and `-encodedcommand `, but AST (Abstract Syntax Tree) level analysis or Script Block Logging (Event ID 4104) is recommended for production environments.
2. **Path Spoofing & Living-off-the-Land (LOLBINs)**:
   - Malicious binaries can be renamed to benign system names (e.g., naming malware `svchost.exe` inside `C:\Users\John\AppData\Local\Temp\`). LogForge detects the *path* rather than relying solely on the process name.
3. **Slow Password Spraying**:
   - Attackers spacing login attempts beyond the 60-second correlation window will not trigger rule `100101`. Mitigating this requires wider time-window aggregation (e.g., hourly SIEM thresholding).
