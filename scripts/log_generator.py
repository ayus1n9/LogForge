#!/usr/bin/env python3
"""
LogForge Synthetic Log Replay & Verification Tool
Generates structured JSON / XML logs to test Wazuh decoders and rules via wazuh-logtest.
"""

import sys
import json

TEST_EVENTS = [
    {
        "name": "TEST_AUTH_4625_SINGLE",
        "raw": (
            '{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4625"},'
            '"eventdata":{"targetUserName":"victim_admin","ipAddress":"192.168.56.50","logonType":"3",'
            '"subStatus":"0xc000006a"}}}'
        ),
        "expected_rule": "100100"
    },
    {
        "name": "TEST_ACCT_4720_NEWUSER",
        "raw": (
            '{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4720"},'
            '"eventdata":{"targetUserName":"backdoor_user","subjectUserName":"Administrator"}}}'
        ),
        "expected_rule": "100200"
    },
    {
        "name": "TEST_ACCT_4732_PRIV_ADMIN",
        "raw": (
            '{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4732"},'
            '"eventdata":{"targetUserName":"Administrators","subjectUserName":"Administrator",'
            '"memberSid":"S-1-5-21-..."}}}'
        ),
        "expected_rule": "100202"
    },
    {
        "name": "TEST_SYSMON_1_ENCODED_PS",
        "raw": (
            '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"1"},'
            '"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",'
            '"commandLine":"powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAA...","user":"WIN-LAB\\\\jdoe"}}}'
        ),
        "expected_rule": "100302"
    },
    {
        "name": "TEST_SYSMON_3_LOLBIN_NET",
        "raw": (
            '{"win":{"system":{"providerName":"Microsoft-Windows-Sysmon","eventID":"3"},'
            '"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",'
            '"destinationPort":"4444","destinationIp":"192.168.56.50","protocol":"tcp"}}}'
        ),
        "expected_rule": "100305"
    }
]

def main():
    print("=" * 65)
    print(" LogForge Synthetic Telemetry Test Generator")
    print("=" * 65)
    print(f"Total defined test cases: {len(TEST_EVENTS)}\n")

    for idx, test in enumerate(TEST_EVENTS, 1):
        print(f"[{idx}/{len(TEST_EVENTS)}] Scenario: {test['name']}")
        print(f"    Expected Wazuh Rule ID: {test['expected_rule']}")
        print(f"    Log Payload Snippet:    {test['raw'][:80]}...\n")

    print("[+] Test definition complete. To pipe into Wazuh wazuh-logtest:")
    print("    python3 scripts/log_generator.py --export | docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest")

if __name__ == "__main__":
    if "--export" in sys.argv:
        for t in TEST_EVENTS:
            print(t["raw"])
    else:
        main()
