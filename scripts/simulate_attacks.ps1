<#
.SYNOPSIS
    Simulates controlled adversary and benign test actions for the LogForge SOC Detection Lab.
.DESCRIPTION
    Runs safe, controlled test scenarios to validate detection rules and produce telemetry.
.PARAMETER Scenario
    The specific scenario to execute: 'BruteForce', 'NewUser', 'PrivEsc', 'SuspiciousPS', 'EncodedPS', 'Benign'
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("BruteForce", "NewUser", "PrivEsc", "SuspiciousPS", "EncodedPS", "Benign")]
    [string]$Scenario
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " LogForge Test Scenario: $Scenario" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

switch ($Scenario) {
    "BruteForce" {
        Write-Host "[*] Simulating repeated failed logons (Windows Security Event 4625)..." -ForegroundColor Yellow
        $targetUser = "victim_admin"
        for ($i = 1; $i -le 6; $i++) {
            Write-Host "    -> Attempt $i/6: Attempting logon for $targetUser with invalid password..."
            # Invoking logon attempt via net use against localhost (generates 4625)
            net use \\127.0.0.1\IPC$ "WrongPassword$i!" /USER:$targetUser 2>&1 | Out-Null
            Start-Sleep -Milliseconds 800
        }
        Write-Host "[+] Brute force simulation sequence finished. Check Wazuh Rule 100101." -ForegroundColor Green
    }

    "NewUser" {
        Write-Host "[*] Simulating unauthorized local user creation (Event ID 4720)..." -ForegroundColor Yellow
        $tempUser = "logforge_test_user"
        net user $tempUser "TempP@ssw0rd123!" /add
        Write-Host "[+] User created. Cleaning up in 5 seconds..."
        Start-Sleep -Seconds 5
        net user $tempUser /delete
        Write-Host "[+] Cleanup complete. Check Wazuh Rule 100200." -ForegroundColor Green
    }

    "PrivEsc" {
        Write-Host "[*] Simulating addition to local Administrators group (Event ID 4732 / Rule 100202)..." -ForegroundColor Yellow
        $tempAdmin = "logforge_admin_test"
        net user $tempAdmin "TempP@ssw0rd123!" /add
        net localgroup Administrators $tempAdmin /add
        Start-Sleep -Seconds 5
        net localgroup Administrators $tempAdmin /delete
        net user $tempAdmin /delete
        Write-Host "[+] Privileged group addition test complete. Check Wazuh Rule 100202." -ForegroundColor Green
    }

    "SuspiciousPS" {
        Write-Host "[*] Executing benign simulated PowerShell download cradle (Sysmon Event ID 1)..." -ForegroundColor Yellow
        powershell.exe -nop -exec bypass -c "Write-Host 'Simulated download cradle test executed' -ForegroundColor Magenta"
        Write-Host "[+] Check Wazuh Rule 100301." -ForegroundColor Green
    }

    "EncodedPS" {
        Write-Host "[*] Executing Base64 encoded PowerShell command (Sysmon Event ID 1)..." -ForegroundColor Yellow
        # Command: Write-Host 'LogForge Encoded Command Validation'
        $encodedCmd = "VwByAGkAdABlAC0ASABvAHMAdAAgACcATABvAGcARgBvAHIAZwBlACAARQBuAGMAbwBkAGUAZAAgAEMAbwBtAG0AYQBuAGQAIABWAGEAbABpAGQAYQB0AGkAbwBuACcA"
        powershell.exe -enc $encodedCmd
        Write-Host "[+] Check Wazuh Rule 100302." -ForegroundColor Green
    }

    "Benign" {
        Write-Host "[*] Executing standard administrative baseline operations (Should NOT fire critical alerts)..." -ForegroundColor Yellow
        Get-Process | Select-Object -First 5
        Get-Service -Name LanmanServer
        powershell.exe -Command "Get-Date"
        Write-Host "[+] Benign baseline test finished. Verify no false-positive critical alerts were triggered." -ForegroundColor Green
    }
}
