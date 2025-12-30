# verify_v3_5.ps1
# V3.5 Verification: Checks Burst Coverage AND Dataset Freshness

param(
    [string]$Tag = ""
)

$tagFile = Join-Path (Get-Location) "last_burst_tag_v35.txt"
if (-not $Tag) {
    if (Test-Path $tagFile) { $Tag = (Get-Content $tagFile -Raw).Trim() }
}

Write-Host "=== FINAL LAB VALIDATION (V3.5) ===" -ForegroundColor Cyan
Write-Host "Tag: $Tag" -ForegroundColor Yellow

# Load .env file for credentials
$EnvPath = Join-Path (Get-Location) ".env"
$EnvVars = @{}

if (Test-Path $EnvPath) {
    Get-Content $EnvPath | ForEach-Object {
        $Line = $_.Trim()
        # Skip comments and empty lines
        if ($Line -and $Line -notmatch "^#") {
            $Parts = $Line -split "=", 2
            if ($Parts.Count -eq 2) {
                $Key = $Parts[0].Trim()
                $Value = $Parts[1].Trim()
                # Remove potential quotes
                $Value = $Value -replace '^"|"$', '' -replace "^'|'$", ''
                $EnvVars[$Key] = $Value
            }
        }
    }
}
else {
    Write-Warning ".env file not found at $EnvPath. Authentication may fail."
}

$SplunkHost = "172.16.58.134"
$SplunkPort = "8089"
$User = if ($EnvVars.ContainsKey("SPLUNK_USERNAME")) { $EnvVars["SPLUNK_USERNAME"] } else { "admin" }
$Pass = if ($EnvVars.ContainsKey("SPLUNK_PASSWORD")) { $EnvVars["SPLUNK_PASSWORD"] } else { "" }

if (-not $Pass) {
    Write-Error "SPLUNK_PASSWORD not found in .env file. Please check e:\Projects\aiops\.env"
    exit 1
}

$BaseUrl = "https://$SplunkHost`:$SplunkPort/services/search/jobs/export?output_mode=json"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

function Run-Search($SearchQuery) {
    try {
        $EncodedQuery = [System.Uri]::EscapeDataString("search $SearchQuery")
        $Body = "search=$EncodedQuery"
        $Auth = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$User`:$Pass"))
        $Headers = @{Authorization = $Auth }
        
        $Response = Invoke-WebRequest -Uri $BaseUrl -Method Post -Body $Body -Headers $Headers -UseBasicParsing
        $Lines = $Response.Content -split "`n"
        $Results = @()
        foreach ($Line in $Lines) {
            if ($Line.Trim().Length -gt 0) {
                try {
                    $Obj = $Line | ConvertFrom-Json
                    if ($Obj.result) { $Results += $Obj.result }
                }
                catch {}
            }
        }
        return $Results
    }
    catch {
        Write-Host "Error running search: $_" -ForegroundColor Red
        return $null
    }
}

# 1. Burst Coverage (All Hosts by Tag and Markers)
Write-Host "`n--- Burst Coverage ($Tag) ---" -ForegroundColor Yellow

# Extraction Regex for both KV and JSON with Coalescing
# Matches: lab_host=val OR "lab_host":"val"
$HostRex = '| rex field=_raw "(?i)\blab_host=(?<lab_host>\w+)" | rex field=_raw "\"lab_host\"\s*:\s*\"(?<lab_host_json>[^\"]+)\"" | eval lab_host=coalesce(lab_host, lab_host_json)'
$SignalRex = '| rex field=_raw "(?i)\blab_signal=(?<lab_signal>[A-Za-z0-9_:\-]+)" | rex field=_raw "\"lab_signal\"\s*:\s*\"(?<lab_signal_json>[^\"]+)\"" | eval lab_signal=coalesce(lab_signal, lab_signal_json)'

# 1. Host Coverage
# Search for Tag as STRING first, then extract
$BurstQuery = 'index=* earliest=-30m "' + $Tag + '" ' + $HostRex + ' | stats count by lab_host | table lab_host count'
$BurstResults = Run-Search $BurstQuery

$ExpectedHosts = @("opnsense", "juiceshop", "dc", "pc1")
foreach ($H in $BurstResults) {
    if ($ExpectedHosts -contains $H.lab_host) {
        Write-Host "HOST: $($H.lab_host) | COUNT: $($H.count) | STATUS: [PASS]" -ForegroundColor Green
    }
    else {
        Write-Host "HOST: $($H.lab_host) | COUNT: $($H.count) | STATUS: [UNKNOWN HOST] (Warning)" -ForegroundColor Yellow
    }
}

# 2. Detailed Signal Coverage
Write-Host "`n--- Detailed Signal Coverage ---" -ForegroundColor Yellow
$DetailQuery = 'index=* earliest=-30m "' + $Tag + '" ' + $HostRex + ' ' + $SignalRex + ' | stats count as events by lab_host, sourcetype, lab_signal | sort lab_host'
$DetailResults = Run-Search $DetailQuery

if ($DetailResults) {
    $DetailResults | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Cyan
}
else {
    Write-Host "No detailed results found." -ForegroundColor Red
}


# 3. Dataset Freshness (Last 15m)
Write-Host "`n--- Dataset Freshness (Last 15m) ---" -ForegroundColor Yellow
# Using _indextime to avoid timestamp parsing issues
$Datasets = @(
    @{ Name = "Wazuh Alerts"; Query = 'index=wazuh OR index=* sourcetype=wazuh-alerts' },
    @{ Name = "JuiceShop App"; Query = 'index=* sourcetype=juiceshop:app OR (host=juiceshop sourcetype=monitor)' },
    @{ Name = "Suricata"; Query = 'index=* sourcetype=suricata OR sourcetype=opnsense:syslog' },
    @{ Name = "Zenarmor"; Query = 'index=main host="172.16.58.2" ("zenarmor" OR "ipdr" OR "sensei")' }
)

foreach ($DS in $Datasets) {
    $FreshnessQuery = "$($DS.Query) earliest=-15m | stats count as c latest(_indextime) as last_index_time | eval age_sec=now()-last_index_time | eval status=if(c>0 AND age_sec<900,`"ALIVE`",`"DEAD`") | table c status age_sec"
    
    $Res = Run-Search $FreshnessQuery
    
    if ($Res) {
        # $Res might be an array if multiple rows returned (unlikely for stats) or single object
        if ($Res -is [array]) { $Res = $Res[0] }
        
        $StatusStr = "[$($Res.status)]"
        $Color = if ($Res.status -eq "ALIVE") { "Green" } else { "Red" }

        # Special handling for Wazuh: WARN instead of DEAD
        if ($DS.Name -eq "Wazuh Alerts" -and $Res.status -eq "DEAD") {
            $StatusStr = "[WARN]"
            $Color = "Yellow"
        }
        
        Write-Host "DATASET: $($DS.Name) | COUNT: $($Res.c) | AGE: $([math]::Round($Res.age_sec, 1))s | STATUS: $StatusStr" -ForegroundColor $Color
    }
}

# 4. Auth Failure Verification (Deterministic Proof)
Write-Host "`n--- Tagged Auth Verification (Event 4625: FAIL_$Tag) ---" -ForegroundColor Yellow
# Search for the explicit tagged username we injected
$AuthQuery = 'index=* earliest=-15m EventCode=4625 "FAIL_' + $Tag + '" | stats count by host'
$AuthResults = Run-Search $AuthQuery

if ($AuthResults) {
    # If single result, wrap in array
    if (-not ($AuthResults -is [array])) { $AuthResults = @($AuthResults) }
    
    foreach ($Result in $AuthResults) {
        Write-Host "HOST: $($Result.host) | COUNT: $($Result.count) | STATUS: [PASS] (Found Tagged Event)" -ForegroundColor Green
    }
}
else {
    Write-Host "No tagged 4625 events found. (Windows Logs or Pipeline Issue)" -ForegroundColor Red
}
