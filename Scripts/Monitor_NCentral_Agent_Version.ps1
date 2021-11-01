<#
.SYNOPSIS
    This script is used to monitor the version of NC Agent
.DESCRIPTION
    This script is used to monitor the version of NC Agent
.NOTES
    Fichier    : Monitor_NCentral_Agent_Version.ps1
    Author     : Jerome Couette - j.couette@cpu.ca
    Version    : 1.0
#>

#-----------------------------------------------------------[Functions]------------------------------------------------------------
function Install-PSNcentralModule (){
    $PsModulePath1 = "$env:SystemDrive\Program Files\WindowsPowerShell\Modules"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Set-PSRepository -Name 'PSGallery' -SourceLocation "https://www.powershellgallery.com/api/v2" -InstallationPolicy Trusted
    Install-Module -Name 7Zip4PowerShell -Force
    if (!(Test-Path "$env:systemdrive\Temp")) {mkdir "$env:systemdrive\Temp"}
    Invoke-WebRequest -Uri "https://chocolatey.cpu.qc.ca/endpoints/CPU/content/DEVOPS/NAble/PS-NCentral.zip" -Headers @{"AUTHORIZATION"="Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("DefaultFeedUser:RC8QCsIKUe"))} -OutFile "$env:systemdrive\Temp\PS-NCentral.zip"
    $sourcefile = "$env:systemdrive\Temp\PS-NCentral.zip"
    Expand-7Zip -ArchiveFileName $sourcefile -TargetPath $PsModulePath1
}
function Test-NCentralConnection (){
    $IsConnected = NcConnected
    return $IsConnected
}
function Get-NCPlatformVersion (){
    $DeviceIDs     = @()
    $DeviceObjects = New-Object System.Collections.ArrayList
    try { $customers = (Get-NCCustomerList).customerid } catch { if (Test-NCentralConnection = $false) { New-NCentralConnection $Global:NCentral_FQDN $Global:NAble_Credentials } }
    for ($i = 0; $i -le 10; $i++ ){ $DeviceIDs += (Get-NCDeviceList ($customers[$i])).deviceid }
    for ($i = 0; $i -le 50; $i++ ){   
        try {
            $TargetDeviceID = $deviceIds[$i] 
            $DevicesVersionList = (((Get-NCDeviceObject -DeviceID $TargetDeviceID).application | where {$_.displayname -eq "Windows Agent"}) | Select-Object -Property version).version
            $DeviceObjects.Add($DevicesVersionList) > $null
        }
        catch {
            if (Test-NCentralConnection = $false) { New-NCentralConnection $Global:NCentral_FQDN $Global:NAble_Credentials }
        }
    } 
    $NC_PlatformCurrentVersion = ($DeviceObjects | Sort-Object -Descending)[0]
    return $NC_PlatformCurrentVersion
}
function Get-NCLocalAgentVersion (){
    try { 
        $Device = (Get-NCDeviceLocal | Get-NCDeviceObject) 
    } 
    catch { 
        if (Test-NCentralConnection = $false) { New-NCentralConnection $Global:NCentral_FQDN $Global:NAble_Credentials } 
    }
    $NC_LocalAgentVersion = ($Device.application | where {$_.displayname -eq "Windows Agent"}).version
    return $NC_LocalAgentVersion
}
#----------------------------------------------------------[Declarations]----------------------------------------------------------
$Global:NCentral_FQDN        = "ncod440.n-able.com"
$Global:NAble_SecureString   = ConvertTo-SecureString "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTb2xhcndpbmRzIE1TUCBOLWNlbnRyYWwiLCJ1c2VyaWQiOjY1Njk3NjQ5NiwiaWF0IjoxNjM0NjcxNzMxfQ.eNw624wqvBigKt8lXYFz_BRR50ETgmRVtH0cR8NrGHw" -AsPlainText -Force
$Global:NAble_Credentials    = New-Object PSCredential ("_JWT", $Global:NAble_SecureString)
#---------------------------------------------------------[Initialisation]---------------------------------------------------------
try {
    if (!(Test-path "$env:SystemDrive\Program Files\WindowsPowerShell\Modules\PS-NCentral")) { Install-PSNcentralModule }
    #Import PS-NCentral Module
    Import-Module PS-NCentral
    Start-Sleep -s 3
    Write-Host "Success: PS-NCentral Module has been installed!"
}
catch {
    Write-Host "Error: PS-NCentral Module has not been installed!"
}
New-NCentralConnection $Global:NCentral_FQDN $Global:NAble_Credentials
#-----------------------------------------------------------[Execution]------------------------------------------------------------
$NC_LocalAgentVersion = Get-NCLocalAgentVersion
$NC_PlatformCurrentVersion = Get-NCPlatformVersion

Write-Host "NCentral Console Version: $NC_PlatformCurrentVersion"
Write-Host "Local Agent Version: $NC_LocalAgentVersion"
if ($NC_PlatformCurrentVersion -eq $NC_LocalAgentVersion) { Write-Host "The Agent is up-to-date!" }else { Write-Host "The Agent is outdated!" }