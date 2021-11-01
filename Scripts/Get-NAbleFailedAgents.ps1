<#
.SYNOPSIS
    N-Able - Script de découverte des agents en problème
.DESCRIPTION
    N-Able - Script de découverte des agents en problème, Ce script valide que les ordinateurs qui sont en ligne au moment de l'exécution
    sont également en ligne dans la console N-Able. Si leur état est à disconnected il configure le flag IsAgentFailed à true

.NOTES
    Fichier    : Get-NAbleFailedAgents.ps1
    Author     : Jerome Couette - jerome.couette@cpu.ca
    Date       : March 31 2021
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
function Send-DataToLogDNA {
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
#N-Able API Auth
$Global:NCentral_FQDN        = "ncod440.n-able.com"
$Global:NAble_SecureString   = ConvertTo-SecureString "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTb2xhcndpbmRzIE1TUCBOLWNlbnRyYWwiLCJ1c2VyaWQiOjY1Njk3NjQ5NiwiaWF0IjoxNjE0NjI3MzkwfQ.8yntfz1Rh5o245ylT9B-vJZZJ-1GWtRiDIB_qnacq3I" -AsPlainText -Force
$Global:NAble_Credentials    = New-Object PSCredential ("_JWT", $Global:NAble_SecureString)
#---------------------------------------------------------[Initialization]---------------------------------------------------------
try {
    #Install PS-NCentral Module
    if (!(Test-Path -Path "$env:SystemDrive\Program Files\WindowsPowerShell\Modules\PS-NCentral")) { Install-PSNcentralModule }

    #Import PS-NCentral Module
    Import-Module PS-NCentral
}
catch {
    Send-DataToLogDNA -Message "Initialization Failed !" -Severity ERROR -Application "Get-NAbleFailedAgents.ps1" -ApiKey "1ec3f3f8a4b8617ec6c8904c9c928a6b"
    $error[0].Exception.Message
}
$ScanResults = Import-clixml -Path "$env:SystemDrive\ProgramData\NetScan\scanresults.xml"
#-----------------------------------------------------------[Execution]------------------------------------------------------------
Wait-RandomPeriod # A random delay is needed so not all agents communicate at the same time with the API
# Connect to N-Central
New-NCentralConnection $Global:NCentral_FQDN $NAble_Credentials

# Get customer ID
$CustomerID = (Get-NCDeviceLocal).customerid

# Get a list of devices for that customer ID
$CustomerDevices = Get-NCDeviceList -CustomerID $CustomerID | Select-Object -Property longname,agentversion,deviceid

# Create a correctly formated objects list of hostnames + Agent version + Agent Status
$DeviceHostnames = @()
$ScanResults | ForEach-Object {
    $PSObj = New-Object -TypeName PSCustomObject
    $HostName = ($_.HostName.ToString().split(".")[0])
    $PSObj  | Add-Member -NotePropertyName HostName -NotePropertyValue $HostName
    $Device = ($CustomerDevices | where {$_.longname -eq $HostName})
    $DeviceID = $Device.deviceid
    $PSObj  | Add-Member -NotePropertyName DeviceID -NotePropertyValue ($DeviceID)
    $AgentVersion = $Device.agentversion
    $PSObj  | Add-Member -NotePropertyName AgentVersion -NotePropertyValue ($AgentVersion)
    $PSObj  | Add-Member -NotePropertyName AgentStatus -NotePropertyValue ((Get-NCDeviceStatus -DeviceIDs $DeviceID | where {$_.modulename -eq 'Agent Status'}).statestatus)
    $DeviceHostnames += $PSObj
}

# List all failed agents
$FailedAgents = $DeviceHostnames | where {$_.AgentStatus -eq "Disconnected"}

# Set the flag for failed agents
$FailedAgents | ForEach-Object {
    Set-NCDeviceProperty -DeviceIDs ($_.DeviceID) -PropertyLabel "IsAgentFailed" -PropertyValue $true
}
