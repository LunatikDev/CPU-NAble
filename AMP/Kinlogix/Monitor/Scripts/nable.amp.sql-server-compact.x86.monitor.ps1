<#
.SYNOPSIS
    N-Able: Automation Policy - Monitoring de l'installation SQL Server Compact (x86)
.DESCRIPTION
    N-Able: Automation Policy - Monitoring de l'installation SQL Server Compact (x86)
.NOTES
    Fichier    : nable.amp.sql-server-compact.x86.monitor.ps1
    Author     : Jerome Couette - j.couette@cpu.ca
    Version    : 1.0.1 (2021-08-05)
#>

#-----------------------------------------------------------[Functions]------------------------------------------------------------
function Test-InstalledSoftware {
    <#
    .SYNOPSIS
    Test via WMI if the specified software is installed on the current device

    .DESCRIPTION
    Test via WMI if the specified software is installed on the current device

    .PARAMETER SoftwareName
    The Software Name as shown in add / remove software panel. Ex: "SAP Crystal Reports runtime engine for .NET Framework (32-bit)"

    .PARAMETER SoftwareVendor
    The Software Vendor Name as shown in add / remove software panel. Ex: "SAP"

    .EXAMPLE
    PS> Test-InstalledSoftware -SoftwareName "SAP Crystal Reports runtime engine for .NET Framework (32-bit)" -SoftwareVendor "SAP"
    
    .NOTES
    Author: Jerome Couette (jerome.couette@cpu.ca)
    Version: 1.0.0
    Date: 2021-08-05
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$SoftwareName,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$SoftwareVendor
    )
    $IsSoftwareInstalled = "False"
    Write-Host "Testing $SoftwareName Installation State.."
    $WmiObj = Get-WmiObject -Class Win32_Product | where {$_.Name -eq "$SoftwareName"}
    if ($null -ne $WmiObj) {
        if ($WmiObj.Name -eq $SoftwareName -and $WmiObj.Vendor -eq $SoftwareVendor) {
            $IsSoftwareInstalled = "True"
        }
    }
    return $IsSoftwareInstalled
}
#----------------------------------------------------------[Declarations]----------------------------------------------------------
#-----------------------------------------------------------[Execution]------------------------------------------------------------

# check if software (32 bit) is already installed on the current device 
$IsInstalled = (Test-InstalledSoftware -SoftwareName "Microsoft SQL Server Compact 3.5 SP2 ENU" -SoftwareVendor "Microsoft Corporation")