<#
.SYNOPSIS
    Simulates controlled adversary and benign test actions for the LogForge SOC Detection Lab.
.DESCRIPTION
    Runs safe, controlled test scenarios to validate detection rules and produce telemetry.
    Includes privilege checking, dynamic unique account naming, and safe try/finally cleanup.
.PARAMETER Scenario
    The specific scenario to execute: 'BruteForce', 'NewUser', 'PrivEsc', 'SuspiciousPS', 'EncodedPS', 'Benign'
.PARAMETER TargetIP
    Target IP for authentication testing. Defaults to '127.0.0.1'.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("BruteForce", "NewUser", "PrivEsc", "SuspiciousPS", "EncodedPS", "Benign")]
    [string]$Scenario,

    [Parameter(Mandatory = $false)]
    [string]$TargetIP = "127.0.0.1"
)

function Test-IsElevated {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " LogForge Test Scenario: $Scenario" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

switch ($Scenario) {
    "BruteForce" {
        Write-Host "[*] Simulating repeated failed logons against $TargetIP (Windows Security Event 4625)..." -ForegroundColor Yellow
        $targetUser = "logforge_test_target"
        
        # Verify if running against local or remote lab IP
        if ($TargetIP -eq "127.0.0.1") {
            Write-Host "    [!] Note: Testing against loopback (127.0.0.1). In a multi-node lab, pass -TargetIP <Victim_IP> to test remote Type 3 logons." -ForegroundColor Yellow
        }

        # Clear existing SMB sessions to ensure clean failed logon attempts
        net use * /delete /y 2>&1 | Out-Null

        $successAttempts = 0
        for ($i = 1; $i -le 6; $i++) {
            Write-Host "    -> Attempt $i/6: Submitting authentication failure for $targetUser..."
            $res = net use "\\$TargetIP\IPC`$" "InvalidPass_$i!" /USER:$targetUser 2>&1
            Start-Sleep -Milliseconds 700
        }
        Write-Host "[+] Brute force attempts completed. Verify Event ID 4625 in Event Viewer and Wazuh Rule 100101." -ForegroundColor Green
    }

    "NewUser" {
        if (-not (Test-IsElevated)) {
            Write-Error "[!] Scenario 'NewUser' requires Administrator privileges. Run script as Administrator."
            return
        }

        # Generate unique test account name to prevent collisions with existing accounts
        $uniqueSuffix = Get-Random -Minimum 1000 -Maximum 9999
        $tempUser = "lf_test_$uniqueSuffix"

        # Pre-check: Ensure account does not already exist
        $existing = Get-LocalUser -Name $tempUser -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Error "[!] Collision detected: User $tempUser already exists. Aborting."
            return
        }

        Write-Host "[*] Creating unique temporary user: $tempUser (Event ID 4720)..." -ForegroundColor Yellow
        $created = $false
        try {
            $securePass = ConvertTo-SecureString "TempP@ss_LogForge$uniqueSuffix!" -AsPlainText -Force
            New-LocalUser -Name $tempUser -Password $securePass -Description "LogForge Test User" -ErrorAction Stop
            $created = $true
            Write-Host "[+] Local user $tempUser created successfully. Verifying event generation..." -ForegroundColor Green
            Start-Sleep -Seconds 5
        }
        catch {
            Write-Error "[!] Failed to create local user: $_"
        }
        finally {
            if ($created) {
                Write-Host "[*] Safe cleanup: Removing test user $tempUser..." -ForegroundColor Yellow
                Remove-LocalUser -Name $tempUser -ErrorAction SilentlyContinue
                Write-Host "[+] Safe cleanup completed. Check Wazuh Rule 100200." -ForegroundColor Green
            }
        }
    }

    "PrivEsc" {
        if (-not (Test-IsElevated)) {
            Write-Error "[!] Scenario 'PrivEsc' requires Administrator privileges. Run script as Administrator."
            return
        }

        $uniqueSuffix = Get-Random -Minimum 1000 -Maximum 9999
        $tempUser = "lf_admin_$uniqueSuffix"

        # Pre-check
        if (Get-LocalUser -Name $tempUser -ErrorAction SilentlyContinue) {
            Write-Error "[!] Collision: $tempUser already exists. Aborting."
            return
        }

        Write-Host "[*] Simulating privilege escalation with unique user: $tempUser..." -ForegroundColor Yellow
        $userCreated = $false
        try {
            $securePass = ConvertTo-SecureString "TempAdminPass$uniqueSuffix!" -AsPlainText -Force
            New-LocalUser -Name $tempUser -Password $securePass -Description "LogForge PrivEsc Test" -ErrorAction Stop
            $userCreated = $true

            Write-Host "[*] Adding $tempUser to local Administrators group (Event ID 4732 / Rule 100202)..." -ForegroundColor Yellow
            Add-LocalGroupMember -Group "Administrators" -Member $tempUser -ErrorAction Stop
            Write-Host "[+] User added to Administrators group." -ForegroundColor Green
            Start-Sleep -Seconds 5
        }
        catch {
            Write-Error "[!] Error during PrivEsc scenario: $_"
        }
        finally {
            if ($userCreated) {
                Write-Host "[*] Safe cleanup: Removing $tempUser from Administrators group and deleting account..." -ForegroundColor Yellow
                Remove-LocalGroupMember -Group "Administrators" -Member $tempUser -ErrorAction SilentlyContinue
                Remove-LocalUser -Name $tempUser -ErrorAction SilentlyContinue
                Write-Host "[+] Cleanup completed. Check Wazuh Rule 100202." -ForegroundColor Green
            }
        }
    }

    "SuspiciousPS" {
        Write-Host "[*] Executing benign simulated PowerShell download cradle (Sysmon Event ID 1)..." -ForegroundColor Yellow
        powershell.exe -nop -exec bypass -c "Write-Host 'LogForge Benign Cradle Test' -ForegroundColor Magenta"
        Write-Host "[+] Execution complete. Check Wazuh Rule 100301." -ForegroundColor Green
    }

    "EncodedPS" {
        Write-Host "[*] Executing Base64 encoded PowerShell test command (Sysmon Event ID 1)..." -ForegroundColor Yellow
        # Benign test command: Write-Host 'LogForge Encoded Command Validation'
        # Base64 encoded in UTF-16LE:
        $encodedCmd = "VwByAGkAdABlAC0ASABvAHMAdAAgACcATABvAGcARgBvAHIAZwBlACAARQBuAGMAbwBkAGUAZAAgAEMAbwBtAG0AYQBuAGQAIABWAGEAbABpAGQAYQB0AGkAbwBuACcA"
        powershell.exe -enc $encodedCmd
        Write-Host "[+] Benign encoded command executed. Check Wazuh Rule 100302." -ForegroundColor Green
    }

    "Benign" {
        Write-Host "[*] Executing standard administrative baseline operations (Should NOT fire critical alerts)..." -ForegroundColor Yellow
        Get-Process | Select-Object -First 5
        Get-Service -Name LanmanServer
        powershell.exe -Command "Get-Date"
        Write-Host "[+] Benign baseline test finished. Verify no false-positive critical alerts were triggered." -ForegroundColor Green
    }
}
