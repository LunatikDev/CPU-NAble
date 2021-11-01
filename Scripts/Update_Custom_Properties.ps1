<#
.SYNOPSIS
    N-Able - Mise à jour des Custom Properties (device)
.DESCRIPTION
    Ce script met à jour les Custom Properties du device dans la console N-Able en utilisant l'API
.NOTES
    Fichier    : Update_Custom_Properties.ps1
    Author     : Jerome Couette - jerome.couette@cpu.ca
    Date       : March 25 2021
    Version    : 1.1
#>
#-----------------------------------------------------------[Functions]------------------------------------------------------------


function Send-DataToLogDNA {
    <#
    .SYNOPSIS
    Send log message to LogDNA service

    .DESCRIPTION
    Send log message to LogDNA service using the REST API and powershell

    .PARAMETER Message
    Log message to send to LogDNA.

    .PARAMETER Severity
    Log Severity [INFO,DEBUG,WARN,ERROR]

    .PARAMETER Application
    Application that send the log message.

    .PARAMETER ApiKey
    Organisation Ingestion Key.

    .EXAMPLE
    PS> Send-DataToLogDNA -Message "Message d'information" -Severity INFO -Application "Update_Medesync_Client.ps1" -ApiKey "1ec3f3f8a4b8617ec6c8904c9c928a6b"
    
    status batchID
    ------ -------
    ok     6e696142-aee2-4036-8df8-2f4fc77eafec:65219:ld70

    .EXAMPLE
    PS> Send-DataToLogDNA -Message "Message de debug" -Severity DEBUG -Application "Update_Medesync_Client.ps1" -ApiKey "1ec3f3f8a4b8617ec6c8904c9c928a6b"
    
    status batchID
    ------ -------
    ok     6e696142-aee2-4036-8df8-2f4fc77eafec:65219:ld70

    .EXAMPLE
    PS> Send-DataToLogDNA -Message "Message d'avertissement" -Severity WARN -Application "Update_Medesync_Client.ps1" -ApiKey "1ec3f3f8a4b8617ec6c8904c9c928a6b"
    
    status batchID
    ------ -------
    ok     6e696142-aee2-4036-8df8-2f4fc77eafec:65219:ld70

    .EXAMPLE
    PS> Send-DataToLogDNA -Message "Message d'erreur" -Severity ERROR -Application "Update_Medesync_Client.ps1" -ApiKey "1ec3f3f8a4b8617ec6c8904c9c928a6b"
    
    status batchID
    ------ -------
    ok     6e696142-aee2-4036-8df8-2f4fc77eafec:65219:ld70

    .NOTES
    Author: Jerome Couette (jerome.couette@cpu.ca)
    Version: 1.0.0
    Date: 2021-02-24
    #>
    [CmdletBinding()]
    param (
        # Log message to send to LogDNA
        [Parameter(Position=0,Mandatory=$true)]
        [String]$Message,
        # Log Severity
        [Parameter(Position=1,Mandatory=$true)]
        [ValidateSet("INFO", "DEBUG", "WARN", "ERROR")]
        [String]$Severity,
        # Application that send the log message
        [Parameter(Position=2,Mandatory=$true)]
        [String]$Application,
        # Organisation Ingestion Key
        [Parameter(Position=3,Mandatory=$true)]
        [String]$ApiKey
    )
    $time = [int64](get-date -uformat %s)
    $Uri = "https://logs.logdna.com/logs/ingest?hostname=$env:COMPUTERNAME&now=$time&apikey=$ApiKey"
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type","application/json; charset=UTF-8")
    $body = @"
    {
        "lines":[
          {
              "line": "$Message",
              "app": "$application",
              "level": "$Severity"
          }
        ]
      }
"@ 

$result = Invoke-RestMethod -Uri $uri -Method Post -Body $body -Headers $headers
return $result

}

function Get-ChocoVersion (){
    $Choco = "C:\ProgramData\chocolatey\bin\choco.exe"
    $Version = (&$Choco)[0] -replace "Chocolatey v",""
    return $Version
}

function Get-ChocoSources (){
    [XML]$Choco_Config = Get-Content "$env:systemdrive\ProgramData\chocolatey\config\chocolatey.config"
    $Sources = ($Choco_Config.chocolatey.sources.ChildNodes.id -join ";")
    return $Sources
}

function Get-ChocoInstalledPackages (){
    $Installed_Packages =  (Get-ChildItem -Path "$env:systemdrive\ProgramData\chocolatey\lib").Name -join ";"
    return $Installed_Packages
}

function Get-ChocoLastInstalledPackage(){
    function Get-PackageVersion {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [String]$Pkg_Name
        )
        [XML]$Pkg_Metadata = Get-Content "$env:systemdrive\ProgramData\chocolatey\lib\$Pkg_Name\$Pkg_Name.nuspec"
        return $Pkg_Metadata.package.metadata.version
    }
    function Get-PackageTitle {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [String]$Pkg_Name
        )
        [XML]$Pkg_Metadata = Get-Content "$env:systemdrive\ProgramData\chocolatey\lib\$Pkg_Name\$Pkg_Name.nuspec"
        return $Pkg_Metadata.package.metadata.title
    }
    $Last_Installed_Pkg = ((Get-ChildItem "$env:systemdrive\ProgramData\chocolatey\lib" | Sort-Object -Property LastWriteTime -Descending)[0])
    $Pkg_Name = "Package Name: " + $Last_Installed_Pkg.Name + " (" + (Get-PackageTitle -Pkg_Name $Last_Installed_Pkg.Name) + ")"
    $Pkg_Version = "Package Version: " + (Get-PackageVersion -Pkg_Name $Last_Installed_Pkg.Name)
    $Pkg_Install_Time = "Installation Timestamp: " + $Last_Installed_Pkg.LastWriteTime
    $Pkg_Data = @($Pkg_Name,$Pkg_Version,$Pkg_Install_Time)
    $Last_Installed_Pkg_Data = $Pkg_Data -join ";"
    return $Last_Installed_Pkg_Data
}

function Get-FSRMInstallState () {
    $FSRM_Install_State =  (Get-WindowsFeature | Where-Object {$_.Name -eq "FS-Resource-Manager"}).Installed
    return $FSRM_Install_State
}

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

function Wait-RandomPeriod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,Position=0)]
        [int]$StartNumber=0,
        [Parameter(Mandatory=$false,Position=1)]
        [int]$MaxNumber=900
    )
    $TimeToWait = Get-Random -Minimum $StartNumber -Maximum $MaxNumber
    start-sleep -s $TimeToWait
    Write-Host "Waited $TimeToWait seconds .."
}
#----------------------------------------------------------[Declarations]----------------------------------------------------------

$Global:Is_Choco_Installed   = Test-Path "$env:systemdrive\ProgramData\chocolatey\choco.exe"
$Global:Is_Device_Normalized = Test-Path "$env:systemdrive\ProgramData\Normalisation"

#N-Able API Auth
$Global:NCentral_FQDN        = "ncod440.n-able.com"
#$Global:NAble_SecureString   = ConvertTo-SecureString "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTb2xhcndpbmRzIE1TUCBOLWNlbnRyYWwiLCJ1c2VyaWQiOjY1Njk3NjQ5NiwiaWF0IjoxNjE0NjI3MzkwfQ.8yntfz1Rh5o245ylT9B-vJZZJ-1GWtRiDIB_qnacq3I" -AsPlainText -Force
$Global:NAble_SecureString   = ConvertTo-SecureString "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTb2xhcndpbmRzIE1TUCBOLWNlbnRyYWwiLCJ1c2VyaWQiOjY1Njk3NjQ5NiwiaWF0IjoxNjM0NjcxNzMxfQ.eNw624wqvBigKt8lXYFz_BRR50ETgmRVtH0cR8NrGHw" -AsPlainText -Force
$Global:NAble_Credentials    = New-Object PSCredential ("_JWT", $Global:NAble_SecureString)
#---------------------------------------------------------[Initialization]---------------------------------------------------------
try {
    #Install PS-NCentral Module
    Install-PSNcentralModule

    #Import PS-NCentral Module
    Import-Module PS-NCentral
}
catch {
    Send-DataToLogDNA -Message "Initialization Failed !" -Severity ERROR -Application "Update_Custom_Properties.ps1" -ApiKey "1ec3f3f8a4b8617ec6c8904c9c928a6b"
    $error[0].Exception.Message
}


#-----------------------------------------------------------[Execution]------------------------------------------------------------
#This command makes the script wait for X number of seconds to minimize the load on N-Central server (Default = 0-3600 seconds)
Wait-RandomPeriod
try {

    #Connect to N-Central
    New-NCentralConnection $Global:NCentral_FQDN $NAble_Credentials

    #Get Device Info (the computer where the script is running)
    $Device = Get-NCDeviceLocal | Get-NCDeviceObject
    $Device_Id = $Device.deviceid

    #Get information about FSRM (only on servers)
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    if ($osInfo.ProductType -eq 2) {
        $Global:Is_FSRM_Installed = Get-FSRMInstallState
    }else {
        $Global:Is_FSRM_Installed = "False"
    }


    
    #Get information about chocolatey package managerget-comm   
    if ($Is_Choco_Installed -eq $true) {
        $Global:Choco_Version = Get-ChocoVersion
        $Global:Choco_Sources = Get-ChocoSources 
        $Global:Choco_Installed_Packages = Get-ChocoInstalledPackages
        $Global:Choco_Last_Installed_Package = Get-ChocoLastInstalledPackage
    }else {
        $Global:Choco_Version = "N\A"
        $Global:Choco_Sources = "N\A"
        $Global:Choco_Installed_Packages = "N\A"
        $Global:Choco_Last_Installed_Package = "N\A"
    }

    $Device = Get-NCDeviceLocal | Get-NCDeviceObject
    Set-NCDeviceProperty -DeviceIDs $Device_Id -PropertyLabel "IsNormalized" -PropertyValue $Global:Is_Device_Normalized
    Set-NCDeviceProperty -DeviceIDs $Device_Id -PropertyLabel "IsChocolateyInstalled" -PropertyValue $Global:Is_Choco_Installed
    if ($osInfo.ProductType -eq 2) {
        Set-NCDeviceProperty -DeviceIDs $Device_Id -PropertyLabel "IsFSRMInstalled" -PropertyValue $Global:Is_FSRM_Installed
    }
    Set-NCDeviceProperty -DeviceIDs $Device_Id -PropertyLabel "ChocolateyInstalledPackages" -PropertyValue $Global:Choco_Installed_Packages
    Set-NCDeviceProperty -DeviceIDs $Device_Id -PropertyLabel "ChocolateySources" -PropertyValue $Global:Choco_Sources
    Set-NCDeviceProperty -DeviceIDs $Device_Id -PropertyLabel "ChocolateyVersion" -PropertyValue "$Global:Choco_Version"
    Set-NCDeviceProperty -DeviceIDs $Device_Id -PropertyLabel "ChocolateyLastInstalledPackage" -PropertyValue "$Global:Choco_Last_Installed_Package" 

    Send-DataToLogDNA -Message "The update of N-Able Custom Properties ran successfully !" -Severity INFO -Application "Update_Custom_Properties.ps1" -ApiKey "1ec3f3f8a4b8617ec6c8904c9c928a6b"
}
catch {
    Send-DataToLogDNA -Message $_ -Severity ERROR -Application "Update_Custom_Properties.ps1" -ApiKey "1ec3f3f8a4b8617ec6c8904c9c928a6b"
}

