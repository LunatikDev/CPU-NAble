# Apply/Revoke Protection Plan

# Script input parameters
# $RegistrationToken - Acronis registration token (required)
# $Revoke            - Revoke protection plan yes/no (required, 'no' by default)
# $VendorName           - name of the vendor

$ErrorActionPreference = "Stop"

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

$CloudUrl = Get-CloudURL

# Exchange registration token to access token
$accessToken = Get-AccessToken $CloudUrl $RegistrationToken
$accessToken | Out-File -FilePath "C:\temp\acronis_registration_token.txt" -Encoding utf8