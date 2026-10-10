# Detection Test Matrix & Validation Framework

This matrix documents the testing suite for the LogForge detection rules pack. Each detection includes both expected malicious triggers and benign baseline evaluations to measure false-positive tendencies.

| Test ID | Detection Rule | Target Use Case | Trigger Method | Expected Result | Benign Scenario / Non-Detection Test | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TEST-AUTH-01** | `100100` | Single Failed Logon | 1 failed login attempt (Event 4625) | Alert ID 100100 (Level 3 - Info) | Legitimate user mistyping password once | Verified |
| **TEST-AUTH-02** | `100101` | Password Guessing / Brute Force | 6 rapid failed logins within 30s | Alert ID 100101 (Level 10 - High) | 2 failed attempts spaced 2 minutes apart (No alert) | Verified |
| **TEST-AUTH-03** | `100103` | Compromise after Brute Force | 5 failures followed immediately by successful logon | Alert ID 100103 (Level 12 - Critical) | Single failure followed by successful logon (No alert) | Verified |
| **TEST-ACCT-01** | `100200` | Local Account Creation | `net user testattacker Password123! /add` | Alert ID 100200 (Level 8 - Med) | Existing user modification (No 4720) | Verified |
| **TEST-ACCT-02** | `100202` | Privileged Group Addition | `net localgroup Administrators testattacker /add` | Alert ID 100202 (Level 11 - High) | Addition to non-privileged group like 'Users' (Rule 100201 fires, not 100202) | Verified |
| **TEST-PROC-01** | `100301` | Suspicious PS Cradle | `powershell.exe -nop -exec bypass -c "IEX ..."` | Alert ID 100301 (Level 8 - Med) | Standard `powershell.exe Get-Date` (No alert) | Verified |
| **TEST-PROC-02** | `100302` | Encoded PowerShell Execution | `powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAg...` | Alert ID 100302 (Level 9 - High) | Standard PowerShell script `.ps1` executed by Admin | Verified |
| **TEST-PROC-03** | `100303` | Executable in User Temp/AppData | Execution of binary located in `C:\Users\...\AppData\Local\` | Alert ID 100303 (Level 8 - Med) | Standard execution from `C:\Program Files\` (No alert) | Verified |
| **TEST-NET-01** | `100305` | LOLBIN Outbound Port 4444 | PowerShell socket connection to remote host on TCP 4444 | Alert ID 100305 (Level 10 - High) | PowerShell web traffic over standard HTTPS (TCP 443) | Verified |

---

## Testing Methodology

1. **Synthetic Telemetry Verification**: Run `scripts/log_generator.py` to replay Windows EventChannel XML blocks into `wazuh-logtest` to verify regex matching, decoders, and rule firing triggers.
2. **Endpoint Execution**: Run `scripts/simulate_attacks.ps1` in an isolated Windows VM to confirm actual event generation from the OS through the agent pipeline.
3. **Negative / Benign Testing**: Run benign administrative commands to guarantee no noisy alert storms occur.
