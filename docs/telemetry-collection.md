# Endpoint Telemetry Collection & Verification Guide

This guide details the instrumentation, configuration, and verification of Windows endpoint telemetry for the LogForge SOC lab.

---

## 1. Selected Telemetry Sources & Rationale

In high-throughput enterprise environments, collecting unthrottled endpoint telemetry creates storage bloat and alert noise. LogForge adopts an intentional, threat-focused collection strategy combining Windows Event Logs and Microsoft Sysmon.

### Windows Event Log Channels
| Channel | Target Event IDs | Purpose |
| :--- | :--- | :--- |
| **Security** | `4624` (Logon Success), `4625` (Logon Failure) | Authentication auditing, brute-force correlation, user logon types (Type 2 Interactive, Type 3 Network) |
| **Security** | `4720` (User Created), `4724` (Password Reset), `4732` (Member Added to Group) | Persistence and local privilege escalation auditing |
| **System** | `7045` (Service Installed) | Persistence via Windows Service installation |

### Selective Sysmon Configuration (Tailored Schema 4.90)
Located at: [`sysmon/sysmonconfig-tailored.xml`](../sysmon/sysmonconfig-tailored.xml)

| Sysmon Event ID | Category | Filter Rationale | Monitored Attributes |
| :--- | :--- | :--- | :--- |
| **Event ID 1** | Process Creation | Intercept command-line execution, LOLBINs, and scripts running from user-writable paths | `CommandLine`, `Image`, `ParentImage`, `User`, `Hashes` (SHA256) |
| **Event ID 3** | Network Connection | Capture outbound socket connections initiated by living-off-the-land binaries (PowerShell, CMD, CertUtil) | `Image`, `DestinationPort`, `DestinationIp`, `Protocol` |
| **Event ID 7** | Image Loaded | Track sensitive DLL loading into processes (e.g. `amsi.dll`, `samlib.dll`) | `ImageLoaded`, `Signed`, `Signature` |
| **Event ID 11** | File Creation | Monitor binary creation in user profiles (`AppData`, `Temp`, `Desktop`) and Startup persistence folders | `TargetFilename`, `Image` |
| **Event ID 22** | DNS Query | Catch lookups to suspicious top-level domains (`.xyz`, `.top`, `.tk`) and tunneling domains (e.g. `ngrok`) | `QueryName`, `QueryStatus`, `Image` |

---

## 2. Wazuh Agent EventChannel Configuration

To forward these channels to the Wazuh Manager, configure `C:\Program Files (x86)\ossec-agent\ossec.conf` using the modern Windows EventChannel API:

```xml
<ossec_config>
  <!-- Windows Security Event Channel -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>
      *[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4724 or EventID=4732)]]
    </query>
  </localfile>

  <!-- Windows System Event Channel -->
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
    <query>
      *[System[(EventID=7045)]]
    </query>
  </localfile>

  <!-- Microsoft Sysmon Operational Channel -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

---

## 3. Telemetry Verification & Validation Steps

### Step 1: Verify Sysmon Operational Logging on Windows
Run in an elevated PowerShell session:
```powershell
# Verify Sysmon service is Active
Get-Service -Name Sysmon64

# Query latest 5 Sysmon Process Creation events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Where-Object { $_.Id -eq 1 } | Format-List TimeCreated, Id, Message
```

### Step 2: Trigger Controlled Test Events on Endpoint
```powershell
# Test Event 1: Trigger benign Event ID 4625
net use \\127.0.0.1\IPC$ "InvalidPass" /USER:test_telemetry_user 2>&1 | Out-Null

# Test Event 2: Trigger benign Sysmon Event ID 1 with flag
powershell.exe -nop -c "Write-Host 'LogForge Telemetry Verification'"
```

### Step 3: Verify Ingestion on Wazuh Server
On the Wazuh server or via `docker exec`:
```bash
# Verify raw event ingestion in archives log (if <logall_json> is enabled)
grep -E "4625|Sysmon" /var/ossec/logs/archives/archives.json | tail -n 5

# Check active agent list and status
/var/ossec/bin/agent_control -l
```

### Step 4: Missing Telemetry & Blind Spot Audit
- If Event ID 1 is received without the full command line: Ensure Windows Group Policy `Administrative Templates > System > Audit Process Creation > Include command line in process creation events` is enabled.
- If Sysmon events do not arrive: Confirm the EventChannel name is typed exactly as `Microsoft-Windows-Sysmon/Operational` in `ossec.conf`.
