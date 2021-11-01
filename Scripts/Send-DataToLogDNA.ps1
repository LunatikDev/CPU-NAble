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