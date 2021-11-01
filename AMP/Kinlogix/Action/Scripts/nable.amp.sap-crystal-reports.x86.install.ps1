<#
.SYNOPSIS
    N-Able: Automation Policy - Installation de SAP Crystal Reports (x86)
.DESCRIPTION
    N-Able: Automation Policy - Installation de SAP Crystal Reports (x86)
.NOTES
    Fichier    : nable.amp.sap-crystal-reports.x86.install.ps1
    Author     : Jerome Couette - j.couette@cpu.ca
    Version    : 1.0
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
function Test-InstalledSoftware {
    <#
    .SYNOPSIS
    Test via WMI if the specified software is installed on the current device

    .DESCRIPTION
    Test via WMI if the specified software is installed on the current device

    .PARAMETER SoftwareId
    The Unique Software Id. Ex: "{457B25FC-1E1F-48CA-889C-2ECE37FE1D77}"

    .PARAMETER SoftwareName
    The Software Name as shown in add / remove software panel. Ex: "SAP Crystal Reports runtime engine for .NET Framework (32-bit)"

    .PARAMETER SoftwareVendor
    The Software Vendor Name as shown in add / remove software panel. Ex: "SAP"

    .PARAMETER SoftwareVersion 
    The specific software version that you want to test installation state (Optional). Ex: "3.5.8080.0"

    .EXAMPLE
    PS> Test-InstalledSoftware -SoftwareId "{457B25FC-1E1F-48CA-889C-2ECE37FE1D77}" -SoftwareName "SAP Crystal Reports runtime engine for .NET Framework (32-bit)" -SoftwareVendor "SAP" -SoftwareVersion "13.0.27.3480"
    PS> Test-InstalledSoftware -SoftwareId "{457B25FC-1E1F-48CA-889C-2ECE37FE1D77}" -SoftwareName "SAP Crystal Reports runtime engine for .NET Framework (32-bit)" -SoftwareVendor "SAP"
    
    .NOTES
    Author: Jerome Couette (jerome.couette@cpu.ca)
    Version: 1.0.0
    Date: 2021-07-26
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$SoftwareId,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$SoftwareName,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$SoftwareVendor,
        [Parameter(Mandatory=$false,Position=3)]
        [string]$SoftwareVersion
    )
    $IsSoftwareInstalled = $false
    Write-Host "Testing $SoftwareName Installation State.."
    $WmiObj = Get-WmiObject -Class Win32_Product | where {$_.IdentifyingNumber -eq "$SoftwareId"}
    if ($null -ne $WmiObj) {
        if ($null -ne $SoftwareVersion) {
            if ($SoftwareName -eq $WmiObj.Name -and $SoftwareVendor -eq $WmiObj.Vendor -and $SoftwareVersion -eq $WmiObj.Version) {
                $IsSoftwareInstalled = $true
            }
        }else {
            if ($SoftwareName -eq $WmiObj.Name -and $SoftwareVendor -eq $WmiObj.Vendor) {
                $IsSoftwareInstalled = $true
            }
        }
    }
    return $IsSoftwareInstalled
}
#----------------------------------------------------------[Declarations]----------------------------------------------------------
$choco = "$env:systemdrive\ProgramData\chocolatey\bin\choco.exe"
#-----------------------------------------------------------[Execution]------------------------------------------------------------

try {
    # check if software (32 bit) is already installed on the current device 
    $IsInstalled = (Test-InstalledSoftware -SoftwareId "{457B25FC-1E1F-48CA-889C-2ECE37FE1D77}" -SoftwareName "SAP Crystal Reports runtime engine for .NET Framework (32-bit)" -SoftwareVendor "SAP")

    # install software (32 bit) if not already installed on the current device
    if ($IsInstalled -eq $false) {
        &$choco install sap-crystal-reports-x86 -y --source "https://chocolatey.cpu.qc.ca/nuget/CPU-CHOCO/" --force
    }
}
catch {
    Send-DataToLogDNA -Message $_ -Severity ERROR -Application "nable.amp.sap-crystal-reports.x86.install.ps1" -ApiKey "1ec3f3f8a4b8617ec6c8904c9c928a6b"
}
