<#
.SYNOPSIS
    This script export Acronis Resource Data to n-able custom properties
.DESCRIPTION
    This script export Acronis Resource Data to n-able custom properties
.NOTES
    Fichier    : Export_Acronis_Resource_Data.ps1
    Author     : Jerome Couette - j.couette@cpu.ca
    Version    : 1.0
#>

$ErrorActionPreference = "SilentlyContinue"

#-----------------------------------------------------------[Functions]------------------------------------------------------------
function Get-AakoreProxyLocation {
    $aakoreCmdOutput = &"${env:CommonProgramFiles}\Acronis\Agent\aakore.exe" "info" "--raw" | Out-String
    $aakoreCmdOutput = $aakoreCmdOutput.Replace([System.Environment]::NewLine, '').Replace("}{", "},{")
    $aakoreCmdOutput = "[${aakoreCmdOutput}]"
    $aakoreInfo = $aakoreCmdOutput | ConvertFrom-Json
    return $aakoreInfo[0].location
}
function Get-AccessToken {
    [OutputType([System.Collections.IDictionary])]
    param (
        [Parameter(Mandatory=$true,Position = 0)]
        [string]$aakoreProxyLocation,
        [Parameter(Mandatory=$true,Position = 1)]
        [System.Collections.IDictionary]$restheaders,
        [Parameter(Mandatory=$true,Position = 2)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$aakoreSession
    )
    $restBody = @{ grant_type = "client_credentials" }
    $response = Invoke-RestMethod -Uri "${aakoreProxyLocation}/idp/token" -Method Post -Headers $restheaders -Body $restBody -WebSession $aakoreSession
    return $response.access_token
}
function Get-RestHeaders {
    [OutputType([System.Collections.IDictionary])]
    Param(
        [Parameter(Mandatory = $true,Position = 0)]
        [string]$clientID,
        [Parameter(Mandatory = $true,Position = 1)]
        [string]$clientSecret
    )
    $clientIDSecretBytes = [System.Text.Encoding]::ASCII.GetBytes("${clientID}:${clientSecret}")
    $clientIDSecretBase64 = [System.Convert]::ToBase64String($clientIDSecretBytes)
    $headers = @{
        "Authorization" = "Basic $clientIDSecretBase64"
        "Content-Type"  = "application/x-www-form-urlencoded"
    }
    return $headers
}
function Get-AcronisResource {
    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory=$true,Position = 0)]
        [string]$aakoreProxyLocation,
        [Parameter(Mandatory=$true,Position = 1)]
        [string]$accessToken,
        [Parameter(Mandatory=$true,Position = 2)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$aakoreSession,
        [Parameter(Mandatory=$false,Position = 3)]
        [string]$resourceId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Acronis\BackupAndRecovery\Settings\MachineManager" | Select-Object -ExpandProperty InstanceID)
    )
    $resource = Invoke-RestMethod -Uri "${aakoreProxyLocation}/api/resource_management/v4/resources/${resourceId}" -Method Get -Headers @{ "Authorization" = "Bearer $accessToken" } -WebSession $aakoreSession
    return $resource
}
#----------------------------------------------------------[Declarations]----------------------------------------------------------

$aakoreProxyLocation = Get-AakoreProxyLocation

#-----------------------------------------------------------[Execution]------------------------------------------------------------

$aakoreClient = Invoke-RestMethod -Uri "${aakoreProxyLocation}/idp/clients" -Method Post -UseDefaultCredentials -SessionVariable aakoreSession

$headers = Get-RestHeaders ($aakoreClient.client_id) ($aakoreClient.client_secret)

$token = Get-AccessToken $aakoreProxyLocation $headers $aakoreSession

$resource = Get-AcronisResource $aakoreProxyLocation $token $aakoreSession

#Output parameters 

$AcronisAgentID = $resource.agent_id

$AcronisTenantID = $resource.tenant_id

$AcronisDeviceName = $resource.name

