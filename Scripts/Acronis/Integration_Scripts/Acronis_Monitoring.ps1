# Log new alerts for current machine

# Script input parameters
# $VendorName           - name of the vendor

$ErrorActionPreference = "Stop"

$acronisRegistryPath = "HKLM:\SOFTWARE\Acronis\BackupAndRecovery\Settings\MachineManager"
$acronisEventLogSource = "Acronis Agent"

function Get-LastScanTime {
    $LastScanTime = Get-ItemProperty -Path $acronisRegistryPath | Select-Object -ExpandProperty NableLastScanTime -ErrorAction SilentlyContinue
    return $LastScanTime
}

function Update-LastScanTime {
    $NewScanTime = [Int64](([datetime]::UtcNow) - (Get-Date "1/1/1970")).TotalSeconds
    if (Get-LastScanTime) { Set-ItemProperty -Path $acronisRegistryPath -Name NableLastScanTime -Value $NewScanTime }
    else { New-ItemProperty -Path $acronisRegistryPath -Name NableLastScanTime -Value $NewScanTime }
}

Get
$allLastWeekAlerts = Invoke-RestMethod -Uri "https://us-cloud.acronis.com/api/alert_manager/v1/alerts?query=GMF02MYROL00022.roberval.reg02.gmf.qc.ca" -Headers $headers

function Get-AakoreProxyLocation {
    $aakoreCmdOutput = &"${env:CommonProgramFiles}\Acronis\Agent\aakore.exe" "info" "--raw" | Out-String
    $aakoreCmdOutput = $aakoreCmdOutput.Replace([System.Environment]::NewLine, '').Replace("}{", "},{")
    $aakoreCmdOutput = "[${aakoreCmdOutput}]"
    $aakoreInfo = $aakoreCmdOutput | ConvertFrom-Json
    return $aakoreInfo[0].location
}

function Get-AccessToken {
    param ([string] $aakoreProxyLocation, [string] $clientId, [string] $clientSecret, $aakoreSession)
    
    $clientIdSecretBytes = [System.Text.Encoding]::ASCII.GetBytes("${clientId}:${clientSecret}")
    $clientIdSecretBase64 = [System.Convert]::ToBase64String($clientIdSecretBytes)
    $headers = @{
        "Authorization" = "Basic $clientIdSecretBase64"
        "Content-Type"  = "application/x-www-form-urlencoded"
    }
    $body = @{ grant_type = "client_credentials" }
    $response = Invoke-RestMethod -Uri "${aakoreProxyLocation}/idp/token" `
        -Method Post `
        -Headers $headers `
        -Body $body `
        -WebSession $aakoreSession

    return $response.access_token
}

function Get-ResourceName {
    param ([string] $aakoreProxyLocation, [string] $accessToken, [string] $resourceId, $aakoreSession)
    
    $resource = Invoke-RestMethod -Uri "${aakoreProxyLocation}/api/resource_management/v4/resources/${resourceId}" -Method Get -Headers @{ "Authorization" = "Bearer $accessToken" } -WebSession $aakoreSession

    return $resource.name
}

$ScriptName = "AcronisMonitoring"
$ScriptVersion = "1.0.0.0"
$ScriptLabel = "windows"
$VendorVersion = "1.0.0.0"

function Send-Statistics
{
    param (
        [string]$cloudUrl, 
        [string]$accessToken, 
        [string]$vendor = $VendorName,
        [string]$vendorVersion = $VendorVersion,
        [string]$scriptName = $ScriptName,
        [string]$scriptVersion = $ScriptVersion,
        [string]$eventCategory = $ScriptName,
        [string]$eventAction,
        [string]$eventLabel = $ScriptLabel,
        [int]$eventValue = 0
        )

    $acronisRegistryPath = "HKLM:\SOFTWARE\Acronis\BackupAndRecovery\Settings\MachineManager"
    $resourceId = Get-ItemProperty -Path $acronisRegistryPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InstanceID
    $agentId = Get-ItemProperty -Path $acronisRegistryPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MMSCurrentMachineID

    $applicationIds = @{
        "N-able N-central" = "702880c0-714f-4a95-aaf7-06e7f1da7d09" # N-able N-central
        "N-able RMM" = "4497f3ff-dc79-4189-9ad9-964b83f71b9b" # N-able RMM
        "Datto RMM" = "85f40c81-1c86-4fbd-8fea-a8d14cb548cc" # Datto RMM
    }

    $headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $accessToken"
    }

    $body = @{
        "application_id" = $applicationIds[$vendor]
        "workload" = @{
            "agent_id" = $agentId.ToLower()
            "resource_id" = $resourceId.ToLower()
            "hostname" = [Environment]::MachineName
        }
        "module" = @{
            "name" = $scriptName
            "version" = $scriptVersion
        }
        "vendor_system" = @{
            "name" = $vendor
            "version" = $vendorVersion
        }

        "events" = @(
                @{
                    "category" = $eventCategory
                    "action" = $eventAction
                    "label" = $eventLabel
                    "value" = $eventValue
                }
            )
    } | ConvertTo-Json
  
    try
    {
        $result = Invoke-WebRequest -Uri "${cloudUrl}/api/integration_management/v2/status" -UseBasicParsing `
            -Method Post `
            -Headers $headers `
            -Body $body
    }catch{
        $result = $_.Exception.Response
    }

    return $result
}

function Get-Alerts {
    param ([string] $aakoreProxyLocation, [string] $accessToken, [string] $resourceName, $aakoreSession)
    
    $getAlertsUri = "${aakoreProxyLocation}/api/alert_manager/v1/alerts?query=${resourceName}"
    $previousScanTime = Get-LastScanTime
    $previousScanTime = "1635262938"
    if ($previousScanTime) {
        $getAlertsUri += "&created_at=gt($previousScanTime)"
    }
    
    $headers = @{ "Authorization" = "Bearer $accessToken" }
    
    $response = Invoke-RestMethod -Uri $getAlertsUri -Method Get -Headers $headers -WebSession $aakoreSession
    $response.items
    
    $after = $response.paging.cursors.after
    while ($after) {
        $response = Invoke-RestMethod -Uri "${aakoreProxyLocation}/api/alert_manager/v1/alerts?after=${after}" `
            -Method Get `
            -Headers $headers `
            -WebSession $aakoreSession
        $response.items
        $after = $response.paging.cursors.after
    }
}

function Write-AlertsToEventLog {
    param ($alerts)

    foreach ($alert in $alerts) {
        $entryType = switch ($alert.severity) {
            "ok" { "Information" }
            "warning" { "Warning" }
            "error" { "Error" }
            "critical" { "Error" }
        }
    
        Write-EventLog -LogName "Application" `
            -Source $acronisEventLogSource `
            -EventID 1 `
            -EntryType $entryType `
            -Message "$($alert.type); $($alert.details.resourceName)"
    }
}

# Ensure Acronis Event Log is created
if (-not [System.Diagnostics.EventLog]::SourceExists($acronisEventLogSource)) {
    [System.Diagnostics.EventLog]::CreateEventSource($acronisEventLogSource, "Application")
}

$aakoreProxyLocation = Get-AakoreProxyLocation

# Get client ID and client secret using aakore
$aakoreClient = Invoke-RestMethod -Uri "${aakoreProxyLocation}/idp/clients" -Method Post -UseDefaultCredentials -SessionVariable aakoreSession
$clientId = $aakoreClient.client_id
$clientSecret = $aakoreClient.client_secret

# Get access token using aakore
$accessToken = Get-AccessToken $aakoreProxyLocation $clientId $clientSecret $aakoreSession

$headers = @{ "Authorization" = "Bearer $accessToken" }

# Get resource name for alert filtering
$resourceId = Get-ItemProperty -Path $acronisRegistryPath | Select-Object -ExpandProperty InstanceID
$resourceName = Get-ResourceName $aakoreProxyLocation $accessToken $resourceId $aakoreSession

# Get new alerts generated since last scan and write them to Windows Event Log
$alerts = Get-Alerts $aakoreProxyLocation $accessToken $resourceName $aakoreSession
Update-LastScanTime
Write-AlertsToEventLog $alerts

$stat = Send-Statistics -cloudUrl $aakoreProxyLocation -accessToken $accessToken -eventAction "SentToEventLog" -eventValue $alerts.Count