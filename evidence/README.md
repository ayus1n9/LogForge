# Evidence & Artifact Repository

This directory contains log snippets, simulation output traces, and evidence captures from testing the LogForge detection rules.

## Evidence Catalog

| Evidence File | Description | Associated Detection |
| :--- | :--- | :--- |
| `evidence-auth-guessing.json` | Captured event traces for 6 failed logons and subsequent success | Rules `100100`, `100101`, `100103` |
| `evidence-sysmon-encoded-ps.json`| Raw Sysmon Process Creation event with Base64 payload | Rule `100302` |
| `evidence-privilege-escalation.json`| Security event log showing membership change to `Administrators` | Rules `100200`, `100202` |

> Note: All evidence captures represent synthetic or benign test simulation data. No real customer credentials, hostnames, private keys, or sensitive IP addresses are committed.
