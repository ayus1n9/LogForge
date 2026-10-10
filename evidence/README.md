# Evidence & Artifact Repository

This directory contains synthetic and simulated event traces, test fixtures, and raw log payloads used to develop, test, and document the LogForge detection rules.

## Evidence Catalog

| Evidence File | Scenario / Use Case | Associated Detection Rules | Type |
| :--- | :--- | :--- | :--- |
| [`evidence-auth-guessing.json`](evidence-auth-guessing.json) | 5 failed logons within 22s followed by successful network logon | Rules `100100`, `100101`, `100103` | Synthetic Test Dataset |
| [`evidence-sysmon-encoded-ps.json`](evidence-sysmon-encoded-ps.json) | Obfuscated PowerShell reverse shell execution and outbound port 4444 socket | Rules `100302`, `100305` | Synthetic Test Dataset |
| [`evidence-privilege-escalation.json`](evidence-privilege-escalation.json) | Account creation (`4720`) and addition of member to `Administrators` (`4732`) | Rules `100200`, `100202` | Synthetic Test Dataset |

> **Ethical & Safety Notice**: All evidence payloads are strictly synthetic fixtures or benign simulations. No real customer credentials, hostnames, private keys, or sensitive IP addresses are present.
