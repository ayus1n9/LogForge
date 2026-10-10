# Common Troubleshooting & Diagnostic Procedures

This guide provides operational troubleshooting steps for common issues encountered when running the LogForge lab.

---

## 1. Wazuh Agent Not Connecting to Manager

### Symptoms
- Agent status remains `Never connected` or `Disconnected` in Wazuh Dashboard.
- Manager log displays no registration activity.

### Diagnostics & Resolution
1. **Network Connectivity**:
   - Check if port 1514 (TCP/UDP) and 1515 (TCP) are reachable from Windows:
     ```powershell
     Test-NetConnection -ComputerName "<WAZUH_SERVER_IP>" -Port 1514
     Test-NetConnection -ComputerName "<WAZUH_SERVER_IP>" -Port 1515
     ```
2. **Firewall Rules**:
   - On the Linux host running Wazuh, ensure UFW or iptables is not blocking port 1514:
     ```bash
     sudo ufw allow 1514/tcp
     sudo ufw allow 1515/tcp
     ```
3. **Agent Logs**:
   - Inspect local agent log file: `C:\Program Files (x86)\ossec-agent\ossec.log`. Look for `ERROR: (4112): Invalid key for server...` or handshake timeouts.

---

## 2. Sysmon Telemetry Missing in Wazuh

### Symptoms
- Standard Windows Event logs appear in Wazuh, but Sysmon Event ID 1 or 3 events never show up.

### Diagnostics & Resolution
1. **Check Sysmon Service**:
   ```powershell
   Get-Service -Name Sysmon64
   ```
   If stopped, start it: `Start-Service Sysmon64`.
2. **Verify Sysmon Event Channel in `ossec.conf`**:
   Ensure `ossec.conf` contains the exact channel name:
   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```
3. **Check Sysmon Configuration Schema**:
   Ensure the Sysmon XML schema matches the installed Sysmon version. Run `sysmon -c` to inspect the active configuration.

---

## 3. Wazuh Manager / Indexer Low Memory Crashes

### Symptoms
- Docker container `wazuh.indexer` repeatedly exits with code `137` (Out Of Memory killer).

### Diagnostics & Resolution
1. **Verify Linux `vm.max_map_count`**:
   ```bash
   sysctl vm.max_map_count
   ```
   Must be at least `262144`.
2. **Restrict Indexer JVM Heap**:
   In `docker-compose.yml` or container environment, explicitly pass:
   ```yaml
   OPENSEARCH_JAVA_OPTS: "-Xms1024m -Xmx1024m"
   ```
3. **Prune Old Indices**:
   If disk space fills up, indexer locks writes (read-only watermark at 95% disk usage). Clear disk space or expand storage.
