# Architecture & Deployment Guide: LogForge SOC Lab

## 1. Overview & High-Level Topology

**LogForge** is designed as a focused, resource-conscious detection engineering and SIEM lab. The architecture captures endpoint telemetry from a Windows workstation, forwards logs over a secure channel to a centralized Wazuh SIEM stack, and correlates alerts mapped to the MITRE ATT&CK framework.

```
       [ Windows 10/11 Monitored Endpoint ]
       ├── Windows Event Logs (Security 4625, 4720, etc.)
       ├── Sysmon Telemetry (Process, Network, ImageLoad, DNS)
       └── Wazuh Agent (TLS 1514/TCP)
                        │
                        │ Encrypted Event Ingestion
                        ▼
       [ Wazuh Server / SIEM Core Engine ]
       ├── Analysis Engine (wazuh-analysisd)
       ├── Custom Rules Pack (LogForge XML Rulesets)
       ├── MITRE ATT&CK Mapping Engine
       └── wazuh-indexer (Elasticsearch/OpenSearch Engine)
                        │
                        │ Visual Query & Triage
                        ▼
       [ Wazuh Dashboard (Port 443/8443 HTTPS) ]
       └── SOC Tier 1 Alert Queue & Deep-Dive Investigation
```

---

## 2. Component Breakdown

| Component | Role | Resource Profile | Telemetry / Protocol |
| :--- | :--- | :--- | :--- |
| **Windows Endpoint** | Monitored victim/simulation host | 2 vCPU / 2-4 GB RAM | Event IDs: 4625, 4624, 4720, 4728, Sysmon IDs 1, 3, 7, 11, 22 |
| **Sysmon** | Granular host instrumentation | Minimal overhead | Process command lines, hashes, parent processes, DNS, network sockets |
| **Wazuh Agent** | Local log collector & transport | < 50 MB RAM | Encrypted transport to Wazuh Server via TCP/1514 |
| **Wazuh Manager / Server** | Log decoding, correlation & alerting | 2 vCPU / 2-3 GB RAM | Custom XML rules, threshold rules, alert decoders |
| **Wazuh Indexer & Dashboard**| Search & visualization UI | 2 vCPU / 2-4 GB RAM | REST API (55000), HTTPS Dashboard (443 / 8443) |

---

## 3. Network & Security Isolation

> [!CAUTION]
> **Lab Isolation Warning**:
> - Never expose Wazuh agent communication ports (`1514/TCP`, `1515/TCP`) or the Wazuh Dashboard (`443/TCP` or `8443/TCP`) to the public internet.
> - Utilize a dedicated host-only network (e.g., `192.168.56.0/24` or an internal Docker bridge) to isolate test adversary behavior from personal/home network devices.

### Port Requirements

| Port | Protocol | Source | Destination | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **1514** | TCP/UDP | Windows Endpoint | Wazuh Server | Agent event communication & telemetry transport |
| **1515** | TCP | Windows Endpoint | Wazuh Server | Agent registration / enrollment service |
| **55000** | TCP | Wazuh Dashboard | Wazuh Server | Wazuh REST API management |
| **9200** | TCP | Wazuh Server | Wazuh Indexer | Indexing event logs and alerts |
| **443/8443** | TCP | SOC Analyst Browser | Wazuh Dashboard | Web interface for alert triage |

---

## 4. Resource Allocation & Hardware Optimization

For single-machine environments (e.g., laptops with 8 GB to 16 GB of RAM), running a full multi-node Kubernetes or heavy OVA stack alongside a Windows VM will exhaust memory. LogForge uses an optimized **Docker single-node Wazuh stack** paired with memory controls:

1. **Indexer JVM Heap tuning**: Set `-Xms1g -Xmx1g` in `jvm.options` to restrict Elasticsearch/Indexer memory spikes.
2. **Windows VM Tuning**:
   - Disable unnecessary background services (Cortana, Windows Widgets, telemetry reporting).
   - Allocate 2 CPU cores and 3 GB memory (or 2.5 GB minimum).
3. **Alternative Simulation**: Telemetry replay scripts (`scripts/log_generator.py`) allow validating detection logic directly against Wazuh if running a full VM concurrently is constrained by host RAM.
