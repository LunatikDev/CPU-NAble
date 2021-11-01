<#
.SYNOPSIS
    N-Able - Ajout exclusion FSRM 
.DESCRIPTION
    Ce script ajoute une exception dans FSRM pour N-Able
.NOTES
    Fichier    : Add_FSRM_Exclusion_NAble.ps1
    Author     : Jerome Couette - jerome.couette@cpu.ca
    Date       : March 3 2021
    Version    : 1.0
#>
#-----------------------------------------------------------[Functions]------------------------------------------------------------

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
function Get-FSRMInstallState () {
    $FSRM_Install_State =  (Get-WindowsFeature | Where-Object {$_.Name -eq "FS-Resource-Manager"}).Installed
    return $FSRM_Install_State
}
#----------------------------------------------------------[Declarations]----------------------------------------------------------
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
#-----------------------------------------------------------[Execution]------------------------------------------------------------

try {
    if ($osInfo.ProductType -eq 2) {
        $Global:Is_FSRM_Installed = Get-FSRMInstallState
        if ($Global:Is_FSRM_Installed -eq "True") {
            filescrn exception add /path:"C:\ProgramData\N-Able Technologies" /add-filegroup:"Fichier système" /add-filegroup:"Fichiers audio et vidéo" /add-filegroup:"Fichiers compressés" /add-filegroup:"Fichiers de courrier électronique" /add-filegroup:"Fichiers de pages Web" /add-filegroup:"Fichiers de sauvegarde" /add-filegroup:"Fichiers exécutables" /add-filegroup:"Fichiers image" /add-filegroup:"Fichiers Office" /add-filegroup:"Fichiers ransomwares1" /add-filegroup:"Fichiers ransomwares10" /add-filegroup:"Fichiers ransomwares11" /add-filegroup:"Fichiers ransomwares12" /add-filegroup:"Fichiers ransomwares13" /add-filegroup:"Fichiers ransomwares14" /add-filegroup:"Fichiers ransomwares15" /add-filegroup:"Fichiers ransomwares2" /add-filegroup:"Fichiers ransomwares3" /add-filegroup:"Fichiers ransomwares4" /add-filegroup:"Fichiers ransomwares5" /add-filegroup:"Fichiers ransomwares6" /add-filegroup:"Fichiers ransomwares7" /add-filegroup:"Fichiers ransomwares8" /add-filegroup:"Fichiers ransomwares9" /add-filegroup:"Fichiers temporaires" /add-filegroup:"Fichiers texte"
        }
    }
    Send-DataToLogDNA -Message "The FSRM exclusion has been added successfully !" -Severity INFO -Application "Add_FSRM_Exclusion_NAble.ps1" -ApiKey "1ec3f3f8a4b8617ec6c8904c9c928a6b"
}
catch {
    Send-DataToLogDNA -Message $_ -Severity ERROR -Application "Add_FSRM_Exclusion_NAble.ps1" -ApiKey "1ec3f3f8a4b8617ec6c8904c9c928a6b"
}

