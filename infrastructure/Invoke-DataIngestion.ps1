<#
.SYNOPSIS
    Ingest emulated JSON log data into a Log Analytics workspace for CTFd lab scenarios.

.DESCRIPTION
    Reads JSON files from a module's emulated-data directory and sends them to the
    specified Log Analytics workspace using the Data Collector API.

.PARAMETER ModulePath
    Path to the emulated-data directory (e.g., modules/01-phishing/emulated-data)

.PARAMETER WorkspaceId
    Log Analytics workspace ID

.PARAMETER WorkspaceKey
    Log Analytics workspace primary or secondary key

.PARAMETER LogType
    Custom log type name (defaults to module name derived from path)

.EXAMPLE
    .\Invoke-DataIngestion.ps1 -ModulePath "modules/01-phishing/emulated-data" -WorkspaceId "abc-123" -WorkspaceKey "key=="
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ModulePath,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceId,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceKey,

    [Parameter(Mandatory = $false)]
    [string]$LogType
)

function Build-Signature {
    param(
        [string]$WorkspaceId,
        [string]$WorkspaceKey,
        [string]$Date,
        [int]$ContentLength,
        [string]$Method,
        [string]$ContentType,
        [string]$Resource
    )

    $xHeaders = "x-ms-date:" + $Date
    $stringToHash = $Method + "`n" + $ContentLength + "`n" + $ContentType + "`n" + $xHeaders + "`n" + $Resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($WorkspaceKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $WorkspaceId, $encodedHash
    return $authorization
}

function Send-LogAnalyticsData {
    param(
        [string]$WorkspaceId,
        [string]$WorkspaceKey,
        [string]$Body,
        [string]$LogType
    )

    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $Body.Length

    $signature = Build-Signature `
        -WorkspaceId $WorkspaceId `
        -WorkspaceKey $WorkspaceKey `
        -Date $rfc1123date `
        -ContentLength $contentLength `
        -Method $method `
        -ContentType $contentType `
        -Resource $resource

    $uri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization"        = $signature
        "Log-Type"             = $LogType
        "x-ms-date"           = $rfc1123date
        "time-generated-field" = "TimeGenerated"
    }

    try {
        $response = Invoke-RestMethod -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $Body
        Write-Host "  [OK] Sent $contentLength bytes to '$LogType'" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "  [FAIL] Error sending to '$LogType': $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# --- Main ---

if (-not (Test-Path $ModulePath)) {
    Write-Error "Module path not found: $ModulePath"
    exit 1
}

# Derive LogType from module path if not specified
if (-not $LogType) {
    $moduleName = (Split-Path (Split-Path $ModulePath -Parent) -Leaf) -replace '[^a-zA-Z0-9]', '_'
    $LogType = "CTH_$moduleName"
}

Write-Host "`n=== Cloud Threat Hunting — Data Ingestion ===" -ForegroundColor Cyan
Write-Host "Module Path : $ModulePath"
Write-Host "Workspace   : $WorkspaceId"
Write-Host "Log Type    : $LogType"
Write-Host ""

$jsonFiles = Get-ChildItem -Path $ModulePath -Filter "*.json" -File

if ($jsonFiles.Count -eq 0) {
    Write-Warning "No JSON files found in $ModulePath"
    exit 0
}

$successCount = 0
$failCount = 0

foreach ($file in $jsonFiles) {
    Write-Host "Processing: $($file.Name)" -ForegroundColor Yellow
    
    $content = Get-Content -Path $file.FullName -Raw
    $records = $content | ConvertFrom-Json

    # Remove _comment fields before sending
    $cleanRecords = $records | ForEach-Object {
        $record = $_
        $props = $record.PSObject.Properties | Where-Object { $_.Name -ne '_comment' }
        $clean = [PSCustomObject]@{}
        foreach ($prop in $props) {
            $clean | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $prop.Value
        }
        $clean
    }

    $body = $cleanRecords | ConvertTo-Json -Depth 10

    # Log Analytics Data Collector API has a 30 MB limit per request
    # Split into batches if needed
    $batchSize = 100
    $batches = [System.Collections.ArrayList]@()

    for ($i = 0; $i -lt $cleanRecords.Count; $i += $batchSize) {
        $end = [Math]::Min($i + $batchSize, $cleanRecords.Count)
        $batch = $cleanRecords[$i..($end - 1)]
        [void]$batches.Add($batch)
    }

    foreach ($batch in $batches) {
        $batchBody = $batch | ConvertTo-Json -Depth 10
        
        # Ensure it's always an array
        if ($batch.Count -eq 1) {
            $batchBody = "[$batchBody]"
        }

        $result = Send-LogAnalyticsData `
            -WorkspaceId $WorkspaceId `
            -WorkspaceKey $WorkspaceKey `
            -Body $batchBody `
            -LogType $LogType

        if ($result) { $successCount++ } else { $failCount++ }
    }
}

Write-Host "`n=== Ingestion Complete ===" -ForegroundColor Cyan
Write-Host "Successful batches: $successCount" -ForegroundColor Green
Write-Host "Failed batches    : $failCount" -ForegroundColor $(if ($failCount -gt 0) { 'Red' } else { 'Green' })
Write-Host ""
