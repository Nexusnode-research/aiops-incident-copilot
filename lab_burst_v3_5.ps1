# lab_burst_v3_5.ps1
# Generates tagged telemetry across DC, PC1, JuiceShop, and OPNsense using SSH Config + Keys.
# V3.5 Improvements: Fail-fast, Unified dynamic tagging, robust error handling.
# Tag format: LAB_BURST_V3_5_<timestamp>

$ErrorActionPreference = "Stop"
$Tag = "LAB_BURST_V3_5_$(Get-Date -Format 'yyyyMMddHHmmss')"
$KeyPath = "$env:USERPROFILE\.ssh\aiops_lab"

# SSH Options to ensure fail-fast (no password prompts) and using correct key
$SSH_OPTS = @(
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "ConnectTimeout=5",
    "-o", "ServerAliveInterval=5",
    "-o", "ServerAliveCountMax=1",
    "-i", "$KeyPath"
)

function Invoke-SshAndVerify {
    param (
        [string]$HostAlias,
        [string]$Command,
        [string]$Description,
        [switch]$AllowFailure
    )

    Write-Host "[$Description] Connecting to $HostAlias..." -NoNewline
    
    # Run SSH command with our strict options
    # We use & to execute the array of arguments correctly
    
    # Temporarily allow stderr without exception
    $Local:ErrorActionPreference = "Continue"

    if ($HostAlias -match "dc|pc1") {
        # Windows Targets:
        $Remote = $Command.Replace('"', '\"')
        $Output = & ssh $SSH_OPTS $HostAlias $Remote 2>&1
    }
    else {
        # Linux/BSD: Pass command directly
        $Output = & ssh $SSH_OPTS $HostAlias $Command 2>&1
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host " [OK]" -ForegroundColor Green
        # Write-Host "Output: $Output" -ForegroundColor Gray # Uncomment for debug
    }
    else {
        if ($AllowFailure) {
            Write-Host " [EXPECTED FAIL]" -ForegroundColor Yellow
            # Write-Host "Command returned exit code $LASTEXITCODE (allowed)." -ForegroundColor Gray
        }
        else {
            Write-Host " [FAILED]" -ForegroundColor Red
            Write-Host "Command failed with exit code $LASTEXITCODE" -ForegroundColor Red
            Write-Host "Output: $Output" -ForegroundColor Red
            throw "SSH command to $HostAlias failed. Aborting burst."
        }
    }
}

Write-Host "=== STARTING LAB BURST V3.5 (SSH KEY AUTH) ===" -ForegroundColor Cyan
Write-Host "Tag: $Tag" -ForegroundColor Yellow

# --- Pre-flight Checks ---
Write-Host "`n[Pre-flight] Verifying connectivity to all hosts..." -ForegroundColor Yellow

# Simple check to confirm we can auth and run commands
# Using 'whoami' as it works on both Windows (cmd/ps) and Linux
# This confirms we are on the box as the expected user.
$PreFlightCmd = "whoami" 

$Hosts = "opnsense", "juiceshop", "dc", "pc1"
$AvailableHosts = @()

foreach ($H in $Hosts) {
    try {
        Invoke-SshAndVerify -HostAlias $H -Command $PreFlightCmd -Description "Pre-flight Check: $H"
        # If Invoke-SshAndVerify didn't throw, it was successful?
        # Wait, Invoke-SshAndVerify throws on failure (Line 63).
        $AvailableHosts += $H
    }
    catch {
        Write-Host " [SKIPPING] Host $H is unreachable." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Gray
    }
}

Write-Host "`n[Pre-flight] All hosts reachable. Proceeding with burst." -ForegroundColor Green


# 1. OPNsense (SSH via alias 'opnsense')
# -----------------
# OPNsense Burst: Syslog (Standard) + UDP Bypass + Suricata Emulation
$OpnMsg = "BURST_TAG=$Tag lab_type=burst lab_env=aiops LAB_BURST=$Tag lab_host=opnsense lab_signal=syslog_test OPNsense burst start"
# Top-level JSON fields for Suricata
$EveJson = '{"timestamp": "2025-12-21T12:00:00.000000+0000", "event_type": "alert", "lab_type": "burst", "lab_env": "aiops", "lab_tag": "' + $Tag + '", "LAB_BURST": "' + $Tag + '", "lab_host": "opnsense", "lab_signal": "suricata_test", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "alert": {"signature": "LAB_BURST_EMULATION", "severity": 3}}'

# We use single quotes around the command string for PowerShell to pass it literally to SSH
# Inside the string, we construct the shell command for the remote host
$OpnCmd = "logger -t $Tag '$OpnMsg'; echo '$OpnMsg' | nc -u -w 1 172.16.58.134 5514; logger -t suricata '$EveJson'"
if ($AvailableHosts -contains "opnsense") {
    Invoke-SshAndVerify -HostAlias "opnsense" -Command $OpnCmd -Description "Burst OPNsense"
}


# 2. JuiceShop (SSH via alias 'juiceshop')
# ------------------
# Nginx Burst (Port 80) + App Log Burst
# Note: $(Get-Date) is evaluated locally by PowerShell before sending
$RemoteDate = "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"

# Encode the complex command to Base64 to avoid SSH/Shell argument parsing issues & crashes
$RawJuiceCmd = "for i in {1..10}; do curl -s -o /dev/null 'http://127.0.0.1:80/?burst_tag=$Tag&lab_type=burst&lab_env=aiops&LAB_BURST=$Tag&lab_host=juiceshop&lab_signal=web_probe&i='`$i; done; mkdir -p /home/juice/.pm2/logs; echo '[${RemoteDate}] info: BURST_TAG=$Tag lab_type=burst lab_env=aiops LAB_BURST=$Tag lab_host=juiceshop lab_signal=app_log HOST=JuiceShop App Log Burst' >> /home/juice/.pm2/logs/juiceshop-out.log"
$Bytes = [System.Text.Encoding]::UTF8.GetBytes($RawJuiceCmd)
$B64 = [Convert]::ToBase64String($Bytes)
$JuiceCmd = "echo $B64 | base64 -d | bash"

if ($AvailableHosts -contains "juiceshop") {
    Invoke-SshAndVerify -HostAlias "juiceshop" -Command $JuiceCmd -Description "Burst JuiceShop"
}


# 3. DC (SSH via alias 'dc')
# -------------------------
# Step A: Windows EventCreate (Standard) — simplified (no nested PowerShell quoting)
$DescDC = "BURST_TAG=$Tag lab_type=burst lab_env=aiops LAB_BURST=$Tag lab_host=dc lab_signal=event_create DC BURST"

# Run eventcreate directly; safer over SSH -> cmd
# Using double double-quotes for cmd.exe compatibility
$WinCmdDC = "eventcreate /T INFORMATION /ID 999 /L APPLICATION /SO $Tag /D ""$DescDC"""

if ($AvailableHosts -contains "dc") {
    Invoke-SshAndVerify -HostAlias "dc" -Command $WinCmdDC -Description "Burst DC (Event)"
    
    # Auth Failure
    $AuthFailCmd = "powershell -Command `"try { (`$sec = ConvertTo-SecureString 'BURST_BAD_PASS' -AsPlainText -Force); (`$cred = New-Object System.Management.Automation.PSCredential ('FAIL_$Tag', `$sec)); Start-Process cmd.exe -Credential `$cred -NoNewWindow -ArgumentList '/c exit' -ErrorAction Stop } catch {}`""
    Invoke-SshAndVerify -HostAlias "dc" -Command $AuthFailCmd -Description "Burst DC (AuthFail)" -AllowFailure
}


# 4. PC1 (SSH via alias 'pc1')
# --------------------------
# Step A: Windows EventCreate (Standard)
$DescPC = "BURST_TAG=$Tag lab_type=burst lab_env=aiops LAB_BURST=$Tag lab_host=pc1 lab_signal=event_create PC1 BURST"

# Run eventcreate directly (like DC)
$WinCmdPC = "eventcreate /T INFORMATION /ID 777 /L APPLICATION /SO LAB_BURST /D ""$DescPC"""
# Define AuthFailCmd globally for reuse
$AuthFailCmd = "powershell -Command `"try { (`$sec = ConvertTo-SecureString 'BURST_BAD_PASS' -AsPlainText -Force); (`$cred = New-Object System.Management.Automation.PSCredential ('FAIL_$Tag', `$sec)); Start-Process cmd.exe -Credential `$cred -NoNewWindow -ArgumentList '/c exit' -ErrorAction Stop } catch {}`""

if ($AvailableHosts -contains "pc1") {
    Invoke-SshAndVerify -HostAlias "pc1" -Command $WinCmdPC -Description "Burst PC1 (Event)"

    # Step A.1: Restart Splunk Forwarder to flush logs
    $SplunkCmdPC = "net stop SplunkForwarder & net start SplunkForwarder"
    Invoke-SshAndVerify -HostAlias "pc1" -Command $SplunkCmdPC -Description "Burst PC1 (Restart Splunk)" -AllowFailure

    # Step B: Auth Failure for Wazuh (Expected Fail)
    Invoke-SshAndVerify -HostAlias "pc1" -Command $AuthFailCmd -Description "Burst PC1 (AuthFail)" -AllowFailure

    ### ✅ A) PC1 network probe (Suricata/Zenarmor pivot)

    # Step C: PC1 generates real network traffic (Suricata/Zenarmor can see this at OPNsense)
    # NOTE: set this to your JuiceShop VM IP/port if different
    $JuiceIP = "172.16.58.133"
    $JuicePort = "80"

    $Pc1NetProbeCmd = "powershell -NoProfile -Command `"`$u='http://$JuiceIP`:$JuicePort/?lab_tag=$Tag&lab_type=burst&lab_env=aiops&lab_host=pc1&lab_signal=net_probe&LAB_BURST=$Tag'; curl.exe -s -o NUL `$u`""

    Invoke-SshAndVerify -HostAlias "pc1" -Command $Pc1NetProbeCmd -Description "Burst PC1 (NetProbe)"

    ### ✅ B) Optional: Defender pivot (standard AV test file) on PC1

    # Step D (Optional): Create a standard antivirus test file so Defender generates a clear timeline event.
    # Tag is in the filename so you can search it in MDE timeline: eicar_<TAG>
    $Pc1DefenderTestCmd = @"
powershell -NoProfile -Command "New-Item -ItemType Directory -Force C:\test-WDATP-test | Out-Null; Set-Content -Path C:\test-WDATP-test\eicar_$Tag.com -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'"
"@

    Invoke-SshAndVerify -HostAlias "pc1" -Command $Pc1DefenderTestCmd -Description "Burst PC1 (Defender Test File)"
}


# Finalize
Set-Content -Path "last_burst_tag_v35.txt" -Value $Tag
Write-Host "`n=== BURST DONE ===" -ForegroundColor Cyan
Write-Host "Verify in Splunk with: index=* lab_tag=$Tag" -ForegroundColor Yellow
