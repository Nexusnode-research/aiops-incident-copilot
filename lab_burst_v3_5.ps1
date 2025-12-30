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
    $Output = & ssh $SSH_OPTS $HostAlias $Command 2>&1
    
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

foreach ($H in $Hosts) {
    Invoke-SshAndVerify -HostAlias $H -Command $PreFlightCmd -Description "Pre-flight Check: $H"
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
Invoke-SshAndVerify -HostAlias "opnsense" -Command $OpnCmd -Description "Burst OPNsense"


# 2. JuiceShop (SSH via alias 'juiceshop')
# ------------------
# Nginx Burst (Port 80) + App Log Burst
# Note: $(Get-Date) is evaluated locally by PowerShell before sending
$RemoteDate = "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
$JuiceCmd = "for i in `$(seq 1 10); do curl -s -o /dev/null http://127.0.0.1:80/?burst_tag=$Tag&lab_type=burst&lab_env=aiops&LAB_BURST=$Tag&lab_host=juiceshop&lab_signal=web_probe&i=`$i ; done; mkdir -p /home/juice/.pm2/logs && echo `"[${RemoteDate}] info: BURST_TAG=$Tag lab_type=burst lab_env=aiops LAB_BURST=$Tag lab_host=juiceshop lab_signal=app_log HOST=JuiceShop App Log Burst`" >> /home/juice/.pm2/logs/juiceshop-out.log"

Invoke-SshAndVerify -HostAlias "juiceshop" -Command $JuiceCmd -Description "Burst JuiceShop"


# 3. DC (SSH via alias 'dc')
# -------------------------
# Step A: Windows EventCreate (Standard)
$DescDC = "BURST_TAG=$Tag lab_type=burst lab_env=aiops LAB_BURST=$Tag lab_host=dc lab_signal=event_create DC BURST"
$PsPayloadDC = "eventcreate /T INFORMATION /ID 999 /L APPLICATION /SO $Tag /D '$DescDC'"
$WinCmdDC = "powershell -NoProfile -Command `"$PsPayloadDC`"; whoami"
Invoke-SshAndVerify -HostAlias "dc" -Command $WinCmdDC -Description "Burst DC (Event)"

# Step B: Auth Failure for Wazuh (Expected# Force a failed 4625 logon for Wazuh to detect (Swallow error so we don't fail-fast)
# We embed the Tag in the username so we can verify the event exists even if Wazuh doesn't alert
$AuthFailCmd = 'cmd /c "net use \\127.0.0.1\IPC$ /user:FAIL_{0} BURST_BAD_PASS >nul 2>&1 & net use \\127.0.0.1\IPC$ /delete >nul 2>&1"' -f $Tag
Invoke-SshAndVerify -HostAlias "dc" -Command $AuthFailCmd -Description "Burst DC (AuthFail)" -AllowFailure


# 4. PC1 (SSH via alias 'pc1')
# --------------------------
# Step A: Windows EventCreate + Service Restart (Standard)
$DescPC = "BURST_TAG=$Tag lab_type=burst lab_env=aiops LAB_BURST=$Tag lab_host=pc1 lab_signal=event_create PC1 BURST"
# Use escaped double quotes for the inner command string
$WinCmdPC = "eventcreate /T INFORMATION /ID 777 /L APPLICATION /SO LAB_BURST /D \`"$DescPC\`" & net stop SplunkForwarder & net start SplunkForwarder"
Invoke-SshAndVerify -HostAlias "pc1" -Command $WinCmdPC -Description "Burst PC1 (Event)"

# Step B: Auth Failure for Wazuh (Expected Fail)
Invoke-SshAndVerify -HostAlias "pc1" -Command $AuthFailCmd -Description "Burst PC1 (AuthFail)" -AllowFailure


# Finalize
Set-Content -Path "last_burst_tag_v35.txt" -Value $Tag
Write-Host "`n=== BURST DONE ===" -ForegroundColor Cyan
Write-Host "Verify in Splunk with: index=* lab_tag=$Tag" -ForegroundColor Yellow
