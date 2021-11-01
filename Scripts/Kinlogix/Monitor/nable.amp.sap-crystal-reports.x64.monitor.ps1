<#
.SYNOPSIS
    N-Able: Automation Policy - Monitoring de l'installation SAP Crystal Reports (x64)
.DESCRIPTION
    N-Able: Automation Policy - Monitoring de l'installation SAP Crystal Reports (x64)
.NOTES
    Fichier    : nable.amp.sap-crystal-reports.x64.monitor.ps1
    Author     : Jerome Couette - j.couette@cpu.ca
    Version    : 1.0.2 (2021-08-06)
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
        [Parameter(Mandatory=$false,Position=1)]
        [string]$OtherSoftwareName,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$SoftwareVendor
    )
    $IsSoftwareInstalled = "False"
    Write-Host "Testing $SoftwareName Installation State.."
    $WmiObj = Get-WmiObject -Class Win32_Product | where {$_.Name -eq "$SoftwareName"}
    if ($null -ne $WmiObj) {
        if ($WmiObj.Name -eq $SoftwareName -and $WmiObj.Vendor -eq $SoftwareVendor) {
            $IsSoftwareInstalled = "True"
        }
    }else {
        $WmiObj = Get-WmiObject -Class Win32_Product | where {$_.Name -eq "$OtherSoftwareName"}
        if ($WmiObj.Name -eq $OtherSoftwareName -and $WmiObj.Vendor -eq $SoftwareVendor) {
            $IsSoftwareInstalled = "True"
        }
    }
    return $IsSoftwareInstalled
}

function Get-ProcesorArchitecture () {
    if([System.IntPtr]::Size -eq 4){
        $Arch = "x86"
    }else{
        $Arch = "x64"
    }
    return $Arch
}
#----------------------------------------------------------[Declarations]----------------------------------------------------------
$CPU_Arch = Get-ProcesorArchitecture
#-----------------------------------------------------------[Execution]------------------------------------------------------------


# check if software (64 bit) is already installed on the current device 
switch ($CPU_Arch) {
    "x86" {
        $IsInstalled = "True"
    }
    "x64" {
        $IsInstalled = (Test-InstalledSoftware -SoftwareName "SAP Crystal Reports runtime engine for .NET Framework (64-bit)" -OtherSoftwareName "SAP Crystal Reports runtime engine for .NET Framework 4 (64-bit)" -SoftwareVendor "SAP")
    }
}
