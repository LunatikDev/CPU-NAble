# Run selected policy for current machine

# Script input parameters
# $TaskType - Policy type user wants to run (required)
# Available task types:
# * Backup
# * Antivirus Scan
# * Malware Scan
# * Vulnerability Assessment
# * Patch Management
# * Data Protection Map
# $VendorName           - name of the vendor

$ErrorActionPreference = "Stop"
$ErrorActionPreference

$acronisRegistryPath = "HKLM:\SOFTWARE\Acronis\BackupAndRecovery\Settings\MachineManager"

class AccessTokenRole {
    [string] $tid
    [string] $tuid
    [string] $rs
    [string] $rn
    [string] $rp
    [string] $role
}

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

function Get-AccessTokenPayload {
    param([string] $token)
    
    $payloadEncoded = $token.Split('.')[1] -replace '-', '+' -replace '_', '/'
    while ($payloadEncoded.Length % 4) {
        $payloadEncoded += '='
    }
    
    $payloadJson = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($payloadEncoded))
    $payload = $payloadJson | ConvertFrom-Json
    
    $scopeJson = ($payloadJson | Select-String "\[.*\]").Matches.Value
    $scope = $scopeJson | ConvertFrom-Json
    $payload.scope = $scope

    return $payload
}

function Get-PolicyType {
    param ([string] $taskType)
    
    $policyType = switch ($taskType) {
        "backup" { "policy.backup." }
        "av_scan" { @("policy.security.windows_defender", "policy.security.microsoft_security_essentials") }
        "malware_scan" { "policy.security.antimalware_protection" }
        "vulnerability_assessment" { "policy.security.vulnerability_assessment" }
        "patch_management" { "policy.security.patch_management" }
        "protection_map" { "policy.security.data_protection_map" }
    }

    return $policyType
}

function Get-PolicyId {
    param ($aakoreProxyLocation, $accessToken, $policyType, $planId, $aakoreSession)

    if ($policyType -is [array] )
    {
        $policyTypeName = "or(" + ($policyType -join ", ") + ")"
    }
    else
    {
        $policyTypeName = $policyType
    }

    $uri = "${aakoreProxyLocation}/api/policy_management/v4/policies?type=${policyTypeName}"

    if ($planId)
    {
        $uri += "&parent_id=${planId}"
    }
    
    $response = Invoke-RestMethod `
        -Uri "${uri}" `
        -Method Get `
        -Headers @{ "Authorization" = "Bearer $accessToken" } `
        -WebSession $aakoreSession

    $policy = @()

    if ($policyType -isnot [array] )
    {
        $policy += , ($response.items[0].policy | where -Property type -Match $policyType)
    }
    else
    {
        foreach ($policyName in $policyType)
        {
            $policy += , ($response.items[0].policy | where -Property type -Match $policyName)
        }
    }
  
    return $policy[0].id
}

function Invoke-Policy {
    param ($aakoreProxyLocation, $accessToken, $policyId, $resourceId, $aakoreSession)
    
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }
    $body = @{
        "state"       = "running"
        "policy_id"   = $policyId
        "context_ids" = @($resourceId)
    } | ConvertTo-Json

    try
    {
        $result = Invoke-WebRequest -Uri "${aakoreProxyLocation}/api/policy_management/v4/applications/run" -UseBasicParsing `
            -Method Put `
            -Headers $headers `
            -Body $body `
            -WebSession $aakoreSession -ErrorAction Ignore

    }catch{
        $result = $_.Exception.Response
    }

    return $result

}

$ScriptName = "AcronisScans"
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

$aakoreProxyLocation = Get-AakoreProxyLocation

# Get client ID and client secret from aakore
$aakoreClient = Invoke-RestMethod -Uri "${aakoreProxyLocation}/idp/clients" `
    -Method Post `
    -UseDefaultCredentials `
    -SessionVariable aakoreSession
$clientId = $aakoreClient.client_id
$clientSecret = $aakoreClient.client_secret

# Get access token using aakore
$accessToken = Get-AccessToken $aakoreProxyLocation $clientId $clientSecret $aakoreSession

# Get policy ID
$accessTokenPayload = Get-AccessTokenPayload $accessToken
$planId = $accessTokenPayload.scope | Where-Object role -eq "apply_revoke" | Select-Object -First 1 -ExpandProperty "rp"
if (-not $planId)
{
    $planId = $accessTokenPayload.scope | Where-Object role -eq "admin" | Select-Object -First 1 -ExpandProperty "rp" -ErrorAction SilentlyContinue
}

$policyType = Get-PolicyType $TaskType

$policyId = Get-PolicyId $aakoreProxyLocation $accessToken $policyType $planId $aakoreSession

# Get resource ID (the one from aakore reg.yml is wrong)
$resourceId = Get-ItemProperty -Path $acronisRegistryPath | Select-Object -ExpandProperty InstanceID

# Run selected policy
$result = Invoke-Policy $aakoreProxyLocation $accessToken $policyId $resourceId $aakoreSession

if ($result.StatusCode.ToString() -match "20*")
{
    Write-Output "Task $TaskType started"
# $result is internal N-Able variable: N-Central considers script execution is failed if it is not $null
    $result = $null
}
else
{
    Write-Output ([String]::Format("Task $TaskType failed to start: {0}", $result.StatusCode))
}

$stat = Send-Statistics -cloudUrl $aakoreProxyLocation -accessToken $accessToken -eventAction $TaskType -eventValue $result.StatusCode