<#
.SYNOPSIS
    blablabla
.DESCRIPTION
    blablabla
.NOTES
    Fichier    : xyz.ps1
    Author     : Jerome Couette - j.couette@cpu.ca
    Version    : 1.0
#>

#-----------------------------------------------------------[Functions]------------------------------------------------------------
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
#----------------------------------------------------------[Declarations]----------------------------------------------------------
$aakoreProxyLocation = Get-AakoreProxyLocation
$aakoreClient = Invoke-RestMethod -Uri "${aakoreProxyLocation}/idp/clients" -Method Post -UseDefaultCredentials -SessionVariable aakoreSession
$clientId = $aakoreClient.client_id
$clientSecret = $aakoreClient.client_secret
$accessToken = Get-AccessToken $aakoreProxyLocation $clientId $clientSecret $aakoreSession
$headers = @{ "Authorization" = "Bearer $accessToken" }
#-----------------------------------------------------------[Execution]------------------------------------------------------------
$Tasks = Invoke-RestMethod  -Uri "${aakoreProxyLocation}/api/task_manager/v2/tasks" -Headers $headers
