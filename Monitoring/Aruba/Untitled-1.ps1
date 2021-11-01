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
function Install-PSSNMPTools (){
    $PsModulePath1 = "$env:SystemDrive\Program Files\WindowsPowerShell\Modules"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Set-PSRepository -Name 'PSGallery' -SourceLocation "https://www.powershellgallery.com/api/v2" -InstallationPolicy Trusted
    Install-Module -Name 7Zip4PowerShell -Force
    if (!(Test-Path "$env:systemdrive\Temp")) {mkdir "$env:systemdrive\Temp"}
    Invoke-WebRequest -Uri "http://chocolatey.cpu.qc.ca/endpoints/CPU/content/DEVOPS/Modules/PSSNMPTools.zip" -Headers @{"AUTHORIZATION"="Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("DefaultFeedUser:RC8QCsIKUe"))} -OutFile "$env:systemdrive\Temp\PSSNMPTools.zip"
    $sourcefile = "$env:systemdrive\Temp\PSSNMPTools.zip"
    Expand-7Zip -ArchiveFileName $sourcefile -TargetPath $PsModulePath1
}
#---------------------------------------------------------[Initialisation]---------------------------------------------------------
import-module PSSNMPTools
#----------------------------------------------------------[Declarations]----------------------------------------------------------
#-----------------------------------------------------------[Execution]------------------------------------------------------------
#get a list of instances
$instances = (Invoke-SnmpWalk "10.56.11.70" ".1.3.6.1.4.1.14823.2.3.3.1.2.4.1.1").OID
$instances = $instances -replace ("1.3.6.1.4.1.14823.2.3.3.1.2.4.1.1.","")

$Clients = @()
foreach ($instance in $instances) {
    $report = new-object -TypeName psobject
    $IPAddress = (Invoke-SnmpGet "10.56.11.70" ".1.3.6.1.4.1.14823.2.3.3.1.2.4.1.3.$instance").Data
    $report | Add-Member -NotePropertyName IPAddress -NotePropertyValue $IPAddress
    $ClientName = (Invoke-SnmpGet "10.56.11.70" ".1.3.6.1.4.1.14823.2.3.3.1.2.4.1.5.$instance").Data
    $report | Add-Member -NotePropertyName ClientName -NotePropertyValue $ClientName
    $ClientOS = (Invoke-SnmpGet "10.56.11.70" ".1.3.6.1.4.1.14823.2.3.3.1.2.4.1.6.$instance").Data
    $report | Add-Member -NotePropertyName ClientOS -NotePropertyValue $ClientOS
    $Clients += $report
}
$Clients
