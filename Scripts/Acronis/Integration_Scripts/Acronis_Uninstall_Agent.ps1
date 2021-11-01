# Uninstall Cyber Protect Agent

# Script input parameters
# $VendorName           - name of the vendor


$ErrorActionPreference = "Stop"

function Get-UpgradeCode {
    if ([System.Environment]::Is64BitOperatingSystem) {
        '{DAC56B69-1A5E-494D-92AE-A462FFB2A281}'
    }
    else {
        '{48557248-4EE3-49E4-9450-BAADC7CD1A88}'
    } 
}

function Get-ProductCode {
    param ([string] $upgradeCode)
    
    return Get-CimInstance -ClassName Win32_Property -Filter "Property='UpgradeCode' AND Value='$upgradeCode'" |
        Select-Object -First 1 -ExpandProperty ProductCode
}

function Get-Product {
    param ([string] $productCode)
    
    return Get-WmiObject -Class Win32_Product | Where-Object { $_.IdentifyingNumber -match $productCode }
}

function Get-CloudURL {
    $aakoreCmdOutput = &"${env:CommonProgramFiles}\Acronis\Agent\aakore.exe" "info" "--raw" | Out-String
    $aakoreCmdOutput = $aakoreCmdOutput.Replace([System.Environment]::NewLine, '').Replace("}{", "},{")
    $aakoreCmdOutput = "[${aakoreCmdOutput}]"
    $aakoreInfo = $aakoreCmdOutput | ConvertFrom-Json
    return $aakoreInfo[2].server
}

function Get-AakoreProxyLocation {
    $aakoreCmdOutput = &"${env:CommonProgramFiles}\Acronis\Agent\aakore.exe" "info" "--raw" | Out-String
    $aakoreCmdOutput = $aakoreCmdOutput.Replace([System.Environment]::NewLine, '').Replace("}{", "},{")
    $aakoreCmdOutput = "[${aakoreCmdOutput}]"
    $aakoreInfo = $aakoreCmdOutput | ConvertFrom-Json
    return $aakoreInfo[0].location
}

$aakoreProxyLocation = Get-AakoreProxyLocation
$aakoreClient = Invoke-RestMethod -Uri "${aakoreProxyLocation}/idp/clients" `
    -Method Post `
    -UseDefaultCredentials `
    -SessionVariable aakoreSession
$clientId = $aakoreClient.client_id
$clientSecret = $aakoreClient.client_secret


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

$ScriptName = "UninstallAgent"
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

$cloudURL = Get-CloudURL
$accessToken = Get-AccessToken $aakoreProxyLocation $clientId $clientSecret $aakoreSession

$upgradeCode = Get-UpgradeCode
$productCode = Get-ProductCode $upgradeCode
$product = Get-Product $productCode
if ($product) {
    try {
        Send-Statistics -cloudUrl $aakoreProxyLocation -accessToken $accessToken -aakoreSession $aakoreSession -vendor "N-Able RMM" -eventAction "started"
        $product.Uninstall()
    }
    catch {
        
    }
    if (Get-Product $productCode) {
        Write-Error "Failed to uninstall Cyber Protect Agent"
    }
    else {
        Write-Output "Cyber Protect Agent was uninstalled successfully"
    }
}
else
{
    Write-Output "Cyber Protect Agent is not installed"
}
