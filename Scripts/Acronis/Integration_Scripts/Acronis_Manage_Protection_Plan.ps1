# Apply/Revoke Protection Plan

# Script input parameters
# $RegistrationToken - Acronis registration token (required)
# $Revoke            - Revoke protection plan yes/no (required, 'no' by default)
# $VendorName           - name of the vendor

$ErrorActionPreference = "Stop"

$acronisRegistryPath = "HKLM:\SOFTWARE\Acronis\BackupAndRecovery\Settings\MachineManager"

function Get-CloudURL {
    $aakoreCmdOutput = &"${env:CommonProgramFiles}\Acronis\Agent\aakore.exe" "info" "--raw" | Out-String
    $aakoreCmdOutput = $aakoreCmdOutput.Replace([System.Environment]::NewLine, '').Replace("}{", "},{")
    $aakoreCmdOutput = "[${aakoreCmdOutput}]"
    $aakoreInfo = $aakoreCmdOutput | ConvertFrom-Json
    return $aakoreInfo[2].server
}

function Get-AccessToken {
    param ([string] $cloudUrl, [string] $registrationToken)
    
    $headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }
    $body = @{
        "grant_type" = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        "assertion"  = $registrationToken
    }
    $response = Invoke-RestMethod -Uri "${cloudUrl}/bc/idp/token" `
        -Method Post `
        -Headers $headers `
        -Body $body
    
    return $response.access_token
}

$ScriptName = "AcronisSetProtectionPlan"
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

function Invoke-Plan {
    param ([string] $cloudUrl, [string] $accessToken, [string] $resourceId)
    
    $headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $accessToken"
    }
    $body = @{
        "context" = @{
            "items" = @($resourceId)
        }
    } | ConvertTo-Json

    $response = Invoke-WebRequest -Uri "${cloudUrl}/api/policy_management/v4/applications" -UseBasicParsing `
        -Method Post `
        -Headers $headers `
        -Body $body

    if ($response.StatusCode -match "20*") {
        Write-Output "Protection Plan was successfully applied"
    }
    else {
        Write-Error "Failed to apply Protection Plan"
    }
}

function Revoke-Plan {
    param ([string] $cloudUrl, [string] $accessToken, [string] $resourceId)
    
    $response = Invoke-WebRequest -Uri "${cloudUrl}/api/policy_management/v4/applications?context_id=${resourceId}"  -UseBasicParsing `
        -Method Delete `
        -Headers @{ "Authorization" = "Bearer $accessToken" }
    
    if ($response.StatusCode -match "20*") {
        Write-Output "Protection Plan was successfully revoked"
    }
    else {
        Write-Error "Failed to revoke Protection Plan"
    }
}

$CloudUrl = Get-CloudURL

# Exchange registration token to access token
$accessToken = Get-AccessToken $CloudUrl $RegistrationToken

# Get resource ID (the one from aakore reg.yml is wrong)
$resourceId = Get-ItemProperty -Path $acronisRegistryPath | Select-Object -ExpandProperty InstanceID

$wasError = 0

try {

    # Apply or revoke protection plan depending on $Revoke parameter
    if ($Revoke -match "^y(es)?$") {
        Revoke-Plan $CloudUrl $accessToken $resourceId
    }
    else {
        Invoke-Plan $CloudUrl $accessToken $resourceId
    }

}
catch { 
    Write-Output "Failed to apply or revoke Protection Plan: $_"
    $wasError = 1
}

$stat = Send-Statistics -cloudUrl $CloudUrl -accessToken $accessToken -eventAction $Revoke -eventValue $wasError