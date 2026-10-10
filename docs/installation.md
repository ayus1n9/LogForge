# Lab Installation & Configuration Guide

This document covers step-by-step instructions to deploy the LogForge SOC environment from scratch.

---

## Part 1: Wazuh Server Deployment (Docker Single-Node)

The Docker deployment provides a clean, isolated SIEM instance with minimal resource overhead.

### 1. Host Preparation (Linux Host / WSL2)
Ensure kernel virtual memory supports Elasticsearch/Wazuh Indexer:
```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### 2. Deploy Wazuh with Docker Compose
Clone the official Wazuh docker repository or use the optimized LogForge compose config:
```bash
git clone https://github.com/wazuh/wazuh-docker.git --depth=1 -b v4.9.0
cd wazuh-docker/single-node
docker compose up -d
```
Verify all containers are healthy:
```bash
docker compose ps
```

Default credentials:
- **URL**: `https://<WAZUH_SERVER_IP>:443`
- **Username**: `admin`
- **Password**: Provided in `config/wazuh_indexer/internal_users.yml` or generated passwords file.

---

## Part 2: Windows Endpoint Preparation

### 1. Download & Install Sysmon
1. Download Sysmon from Microsoft Sysinternals:
   [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Extract to `C:\Tools\Sysmon\`.
3. Apply the tailored LogForge Sysmon configuration (`sysmon/sysmonconfig-tailored.xml`):
   ```powershell
   cd C:\Tools\Sysmon
   .\Sysmon64.exe -accepteula -i C:\Path\To\sysmonconfig-tailored.xml
   ```
4. Verify Sysmon is running:
   ```powershell
   Get-Service -Name Sysmon64
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
   ```

### 2. Install & Configure the Wazuh Agent
1. Download the Windows MSI installer from Wazuh:
   ```powershell
   Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi -OutFile wazuh-agent.msi
   ```
2. Install silently and specify the Wazuh Server IP:
   ```powershell
   .\wazuh-agent.msi /q WAZUH_MANAGER="<WAZUH_SERVER_IP>" WAZUH_REGISTRATION_SERVER="<WAZUH_SERVER_IP>"
   ```
3. Update `C:\Program Files (x86)\ossec-agent\ossec.conf` to ingest Sysmon and Windows Security channels:
   ```xml
   <ossec_config>
     <!-- Windows Security Event Log -->
     <localfile>
       <location>Security</location>
       <log_format>eventchannel</log_format>
     </localfile>

     <!-- Windows System Event Log -->
     <localfile>
       <location>System</location>
       <log_format>eventchannel</log_format>
     </localfile>

     <!-- Microsoft Sysmon Operational Channel -->
     <localfile>
       <location>Microsoft-Windows-Sysmon/Operational</location>
       <log_format>eventchannel</log_format>
     </localfile>
   </ossec_config>
   ```
4. Restart the Wazuh agent service:
   ```powershell
   Restart-Service -Name Wazuh
   ```

---

## Part 3: Deploying Custom Rules to Wazuh

1. Copy custom rules from `detections/` to the Wazuh Manager custom rules directory (`/var/ossec/etc/rules/` on the server or container mount):
   ```bash
   docker cp detections/authentication-rules.xml wazuh-manager:/var/ossec/etc/rules/
   docker cp detections/account-management-rules.xml wazuh-manager:/var/ossec/etc/rules/
   docker cp detections/process-detection-rules.xml wazuh-manager:/var/ossec/etc/rules/
   ```
2. Test rule syntax on the Wazuh server:
   ```bash
   docker exec -it wazuh-manager /var/ossec/bin/wazuh-logtest
   ```
3. Restart the Wazuh Manager daemon to apply changes:
   ```bash
   docker exec -it wazuh-manager /var/ossec/bin/wazuh-control restart
   ```
