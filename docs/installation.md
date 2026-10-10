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
Clone the official Wazuh docker repository (pinned to verified v4.9.0 release):
```bash
git clone https://github.com/wazuh/wazuh-docker.git --depth=1 -b v4.9.0
cd wazuh-docker/single-node
```

Generate self-signed SSL certificates for cluster components:
```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

Start the single-node stack:
```bash
docker compose up -d
```

Verify all containers are running and healthy:
```bash
docker compose ps
```
The active container names deployed are typically:
- `single-node-wazuh.manager-1`
- `single-node-wazuh.indexer-1`
- `single-node-wazuh.dashboard-1`

### 3. Accessing the Dashboard & Credentials
- **URL**: `https://<WAZUH_SERVER_IP>:443`
- **Default Username**: `admin`
- **Password**: Provided in the official repository `config/wazuh_indexer/internal_users.yml` or generated via the password configuration script. Note: Browser will present a self-signed certificate warning which you must accept for lab testing.

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
2. Install and specify the Wazuh Server IP:
   ```powershell
   .\wazuh-agent.msi /q WAZUH_MANAGER="<WAZUH_SERVER_IP>" WAZUH_REGISTRATION_SERVER="<WAZUH_SERVER_IP>"
   ```
3. **Important Configuration Note**:
   Do **not** replace your entire `ossec.conf` file. Open `C:\Program Files (x86)\ossec-agent\ossec.conf` and append or merge the following `<localfile>` blocks inside the existing `<ossec_config>` section:
   ```xml
   <!-- Append inside existing <ossec_config> -->
   <localfile>
     <location>Security</location>
     <log_format>eventchannel</log_format>
     <query>*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4724 or EventID=4732)]]</query>
   </localfile>

   <localfile>
     <location>System</location>
     <log_format>eventchannel</log_format>
     <query>*[System[(EventID=7045)]]</query>
   </localfile>

   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```
4. Restart the Wazuh agent service:
   ```powershell
   Restart-Service -Name Wazuh
   ```

---

## Part 3: Deploying Custom Rules to Wazuh

1. Identify your exact manager container name:
   ```bash
   docker ps --format 'table {{.Names}}\t{{.Status}}'
   # Example: single-node-wazuh.manager-1
   ```
2. Copy custom rules from `detections/` to the Wazuh Manager custom rules directory (`/var/ossec/etc/rules/`):
   ```bash
   docker cp detections/authentication-rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/
   docker cp detections/account-management-rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/
   docker cp detections/process-detection-rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/
   ```
3. Test rule syntax and verify no XML parsing or parent-child errors occur:
   ```bash
   docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest
   ```
4. Restart the Wazuh Manager daemon to apply changes:
   ```bash
   docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
   ```
