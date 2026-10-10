# Detection Test Matrix & Validation Framework

This matrix documents the testing suite for the LogForge detection rules pack. Each detection includes both expected malicious triggers and benign baseline evaluations to measure false-positive tendencies.

### Status Definitions:
- **Implemented, Pending Live Ingestion**: Detection logic authored and schema-checked via `scripts/log_generator.py`; awaiting verification against a live Windows agent stream.
- **Validated (Harness Verified)**: Tested and verified against synthetic event decoders and regex matching.

| Test ID | Detection Rule | Target Use Case | Trigger Method | Expected Result | Benign Scenario / Non-Detection Test | Current Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TEST-AUTH-01** | `100100` | Single Failed Logon | 1 failed login attempt (Event 4625) | Alert ID 100100 (Level 3 - Info) | Legitimate user mistyping password once | Validated (Harness Verified) |
| **TEST-AUTH-02** | `100101` | Password Guessing / Brute Force | 5 rapid failed logins within 60s | Alert ID 100101 (Level 10 - High) | 2 failed attempts spaced 2 minutes apart (No alert) | Validated (Harness Verified) |
| **TEST-AUTH-03** | `100103` | Compromise after Brute Force | 5 failures followed immediately by successful logon | Alert ID 100103 (Level 12 - Critical) | Single failure followed by successful logon (No alert) | Implemented, Pending Live Ingestion |
| **TEST-ACCT-01** | `100200` | Local Account Creation | `New-LocalUser -Name "testuser"` | Alert ID 100200 (Level 8 - Med) | Existing user modification (No 4720) | Validated (Harness Verified) |
| **TEST-ACCT-02** | `100202` | Privileged Group Addition | `Add-LocalGroupMember -Group Administrators` | Alert ID 100202 (Level 11 - High) | Addition to non-privileged group like 'Users' (Rule 100201 fires, not 100202) | Validated (Harness Verified) |
| **TEST-PROC-01** | `100301` | Suspicious PS Cradle | `powershell.exe -nop -exec bypass -c "IEX ..."` | Alert ID 100301 (Level 8 - Med) | Standard `powershell.exe Get-Date` (No alert) | Validated (Harness Verified) |
| **TEST-PROC-02** | `100302` | Encoded PowerShell Execution | `powershell.exe -enc VwByAGkAdABlAC0ASABv...` | Alert ID 100302 (Level 9 - High) | Standard PowerShell script `.ps1` executed by Admin | Validated (Harness Verified) |
| **TEST-PROC-03** | `100303` | Executable in User Temp/AppData | Execution of binary located in `C:\Users\...\AppData\Local\` | Alert ID 100303 (Level 8 - Med) | Standard execution from `C:\Program Files\` (No alert) | Implemented, Pending Live Ingestion |
| **TEST-NET-01** | `100305` | LOLBIN Outbound Port 4444 | PowerShell socket connection to remote host on TCP 4444 | Alert ID 100305 (Level 10 - High) | PowerShell web traffic over standard HTTPS (TCP 443) | Validated (Harness Verified) |

---

## Testing Methodology

1. **Synthetic Telemetry Verification**: Run `scripts/log_generator.py` to assert expected rule IDs against JSON/EventChannel schemas.
2. **Integration Verification**: Use `python3 scripts/log_generator.py --test-container <CONTAINER_NAME>` to run automated pass/fail tests directly against `wazuh-logtest`.
3. **Endpoint Execution**: Run `scripts/simulate_attacks.ps1` in an isolated Windows VM to verify host telemetry generation and agent transport.
4. **Benign Baseline Testing**: Run standard administrative actions to confirm absence of false-positive critical alerts.
