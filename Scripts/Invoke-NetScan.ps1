<#
.SYNOPSIS
    N-Able - Script de découverte réseau
.DESCRIPTION
    N-Able - Script de découverte réseau: trouve toutes les machines qui sont en ligne sur un segment réseau et génère un inventaire
    détaillé comprenant: Addresses IP, MAC Address, Fabriquant (Vendor) ainsi que les ports ouverts ou fermés.

    Ports analysés:
    21	    #FTP	
    22	    #SSH	
    23	    #Telnet	
    25	    #SMTP	
    53      #DNS
    67      #DHCP
    68      #DHCP
    80	    #HTTP	
    113	    #IDENT	
    135	    #RPC	
    139	    #NetBIOS
    389	    #LDAP	
    443	    #HTTPS	
    445	    #MSFT DS	
    1002    #ms-ils	
    1024    #DCOM		
    3389    #RDP
    5000    #UPnP 
.NOTES
    Fichier    : Invoke-NetScan.ps1
    Author     : Jerome Couette - jerome.couette@cpu.ca
    Date       : March 30 2021
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
function Invoke-NetScan () {
    <#
        .DESCRIPTION
        List all ip addresses of a subnet

        .EXAMPLE
        PS> $SubnetAddresses = Get-SubnetAddressList

        .NOTES
        Author: Jerome Couette (jerome.couette@cpu.ca)
        Version: 1.0.0
        Date: 2021-03-30
    #>
    function Get-SubnetAddressList () {
        $Gateway = (Get-WmiObject -Class Win32_IP4RouteTable | where { $_.destination -eq '0.0.0.0' -and $_.mask -eq '0.0.0.0'} | Sort-Object metric1 | select nexthop, metric1, interfaceindex).nexthop
        # remove last digit
        $Subnet = $Gateway.Split(".")
        $Subnet = $Subnet[0..2] -join "."
        $Subnet = $Subnet + "."
        $SubnetAddressList = @()
        for($i=1; $i -le 254; $i++){
            $TargetIP = $Subnet + $i
            $SubnetAddressList += $TargetIP
        }
        return $SubnetAddressList
    }
    <#
        .DESCRIPTION
        Convert an IP Address to a MAC Address

        .EXAMPLE
        PS> Convert-IPToMAC -IPAddress "172.16.5.1"

        .NOTES
        Author: Jerome Couette (jerome.couette@cpu.ca)
        Version: 1.0.0
        Date: 2021-03-30
    #>
    function Convert-IPToMAC {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true,Position=0)]
            [string]$IPAddress
        )
        $Neighbors = Get-NetNeighbor 
        $MAC = ($Neighbors| where {$_.IPAddress -eq "$IPAddress"}[0])
        return $MAC.LinkLayerAddress
    }
    <#
        .DESCRIPTION
        Query the dns server to find hostname associed with specified IP

        .EXAMPLE
        PS> Get-Hostname -IPAddress "172.16.5.1"

        .NOTES
        Author: Jerome Couette (jerome.couette@cpu.ca)
        Version: 1.0.0
        Date: 2021-03-30
    #>
    function Get-Hostname {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true,Position=0)]
            [string]$IPAddress
        )
        $backup = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
        $Hostname = [System.Net.Dns]::GetHostEntry("$IPAddress").HostName
        $ErrorActionPreference = $backup
        return $Hostname
    }
    <#
        .DESCRIPTION
        Reverse MAC lookup to find manaufacturer of device

        .EXAMPLE
        PS> Convert-MACToVendor -MAC "18E829BA76F7"

        .NOTES
        Author: Jerome Couette (jerome.couette@cpu.ca)
        Version: 1.0.0
        Date: 2021-03-30
    #>
    function Convert-MACToVendor {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true,Position=0)]
            [string]$MAC
        )
        function Install-MACAddressLookupTool (){
            $PsModulePath1 = "$env:SystemDrive\Program Files\WindowsPowerShell\Modules"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            if (!(Test-Path -Path "$env:SystemDrive\Program Files\PackageManagement\ProviderAssemblies\nuget\")) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force
            }
            Set-PSRepository -Name 'PSGallery' -SourceLocation "https://www.powershellgallery.com/api/v2" -InstallationPolicy Trusted
            Install-Module -Name 7Zip4PowerShell -Force
            if (!(Test-Path "$env:systemdrive\Temp")) {mkdir "$env:systemdrive\Temp"}
            Invoke-WebRequest -Uri "http://chocolatey.cpu.qc.ca/endpoints/CPU/content/DEVOPS/mac-address-lookup-tool/MAC-Address-Lookup-Tool.zip" -Headers @{"AUTHORIZATION"="Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("DefaultFeedUser:RC8QCsIKUe"))} -OutFile "$env:systemdrive\Temp\MAC-Address-Lookup-Tool.zip"
            $sourcefile = "$env:systemdrive\Temp\MAC-Address-Lookup-Tool.zip"
            Expand-7Zip -ArchiveFileName $sourcefile -TargetPath $PsModulePath1
        }
        if (!(Test-Path -Path "$env:systemdrive\Program Files\WindowsPowerShell\Modules\MAC-Address-Lookup-Tool")) {
            Install-MACAddressLookupTool
            Import-Module -Name MAC-Address-Lookup-Tool
        }
        $backup = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
        $Vendor = (Get-MACVendor -MAC "$MAC" -ErrorAction SilentlyContinue).MACVendor
        $ErrorActionPreference = $backup
        return $Vendor
    }
    <#
        .DESCRIPTION
        Lighning fast ping command using .Net

        .EXAMPLE
        PS> Invoke-FastPing -IPAddress "172.16.5.1"

        .NOTES
        Author: Jerome Couette (jerome.couette@cpu.ca)
        Version: 1.0.0
        Date: 2021-03-30
    #>
    function Invoke-FastPing {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true,Position=0)]
            [string]$IPAddress
        )
        $IsPingable = $false
        $Task = (New-Object System.Net.NetworkInformation.Ping).SendPingAsync("$IPAddress")
        if ($Task.Result.Status -eq "Success") {
            $IsPingable = $true
        }
        return $IsPingable
    }
    <#
        .DESCRIPTION
        Ensure that the script doesn't scan a device more than one time by testing against already collected objects

        .EXAMPLE
        PS> Test-DuplicateIP -IPAddress "172.16.5.1"

        .NOTES
        Author: Jerome Couette (jerome.couette@cpu.ca)
        Version: 1.0.0
        Date: 2021-03-30
    #>
    function Test-DuplicateIP {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true,Position=0)]
            [string]$IPAddress
        )
        $IsDuplicate = $false
        $result = $Global:Hosts| where {$_.IPAddress -eq $IPAdress}
        if($null -ne $result){
            $IsDuplicate = $true
        }
        return $IsDuplicate
    }
    <#
        .DESCRIPTION
        Scan an IP Address to find open and closed ports

        .PARAMETER IPAddress
        IP Address to scan

        .PARAMETER Ports
        The list of ports to be tested [array]

        .EXAMPLE
        PS> $PortsToScan = @(21,22,23,25,53,67,68,80,113,135,139,389,443,445,1002,1024,3389)
        PS> Invoke-TCPPortScan -IPAddress "172.16.5.1" -Ports $PortsToScan

        .NOTES
        Author: Jerome Couette (jerome.couette@cpu.ca)
        Version: 1.0.0
        Date: 2021-03-30
    #>
    function Invoke-TCPPortScan {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true,Position=0)]
            [string]$IPAddress,
            [Parameter(Mandatory=$true,Position=1)]
            [System.Array]$Ports
        )
        $Global:Results = @()
        foreach ($Port in $Ports) {
            Write-host "Scanning $IPAddress and port $Port"
            $Net_Socket_Object = new-Object system.Net.Sockets.TcpClient
            #$Net_Socket_Object.NoDelay = $true
            $Net_Socket_Object.SendTimeout = 100
            $Net_Socket_Object.ReceiveTimeout = 100
            $Connection = $Net_Socket_Object.ConnectAsync("$IPAddress","$Port")
            while ($true) {
                if ($Connection.Status -eq "RanToCompletion") {
                    break 
                } elseif ($Connection.isCompleted -eq $true) {
                    break 
                } elseif ($Connection.Status -eq "Faulted") {
                    break
                }
                #Start-Sleep -Milliseconds 50
            } 
            $NetPort = New-Object -TypeName PSCustomObject
            $NetPort  | Add-Member -NotePropertyName IPAddress -NotePropertyValue $IPAddress
            $NetPort  | Add-Member -NotePropertyName Protocol -NotePropertyValue "TCP"
            $NetPort  | Add-Member -NotePropertyName Port -NotePropertyValue $Port
            if ($Connection.isFaulted -and $Connection.Exception -match "actively refused") {
                $NetPort  | Add-Member -NotePropertyName State -NotePropertyValue "Closed"
            } elseif ($Connection.Status -eq "RanToCompletion") {
                $NetPort  | Add-Member -NotePropertyName State -NotePropertyValue "Open"
            }else {
                $NetPort  | Add-Member -NotePropertyName State -NotePropertyValue "Filtered"
            }
            $Global:Results += $NetPort
        }
        return $Global:Results
    }

    # ********************************* Declarations ********************************
    $SubnetAddresses    = Get-SubnetAddressList
    Write-Host "Running Ping Sweep, please wait.."
    $ResolvedIPList     = ($SubnetAddresses | ForEach-Object {Get-WmiObject Win32_PingStatus -Filter "Address='$_' and Timeout=200 and ResolveAddressNames='true' and StatusCode=0" | select ProtocolAddress*}).ProtocolAddress
    Write-Host "Finding Neighbors (ARP table), please wait.."
    $StaleIPAdresses    = (Get-NetNeighbor -AddressFamily IPv4 | where {$_.State -eq "Stale"})
    #$StaleIPAdresses   = ($Neighbors.IPAddress)
    $Gateway            = ((Get-WmiObject -Class Win32_IP4RouteTable | where { $_.destination -eq '0.0.0.0' -and $_.mask -eq '0.0.0.0'} | Sort-Object metric1 | select nexthop, metric1, interfaceindex).nexthop | Select-Object -Unique)
    Write-Host "Gateway IP Address is $Gateway"
    $IsGatewayPingable  = $ResolvedIPList | where {$_ -eq $Gateway}
    $PortsToScan        = @(21,22,23,25,53,67,68,80,113,135,139,389,443,445,1002,1024,3389)
    # ********************************** Execution **********************************

    # There is a high probability that gateway is configured not to respond to pings, so it will not show up in ResolvedIPList. 
    if($null -ne $IsGatewayPingable) {
        $IsGatewayPingable = $true # The Gateway respond to Pings (true)
    }else {
        $IsGatewayPingable = $false # The Gateway doesn't respond to Pings (false)
    }
    # If it's not in ResolvedIPList add it to StaleIPAdresses so it is processed and we have a complete list.
    if ($IsGatewayPingable -eq $false) {
        $StaleIPAdresses += $Gateway
    }
    $Global:Hosts = @()
    # Create NetHost Objects by processing ResolvedIPList (IPAddress,MAC,Hostname,Manufacturer,Pingable)
    foreach ($IP in $ResolvedIPList) {
        Write-Host "Scanning $IP ..."
        $NetHost = New-Object -TypeName PSCustomObject
        $NetHost  | Add-Member -NotePropertyName IPAddress -NotePropertyValue $IP
        $NetHost  | Add-Member -NotePropertyName MAC -NotePropertyValue (Convert-IPToMAC -IPAddress "$IP" | where {$_ -ne "00-00-00-00-00-00"} | Select-Object -Unique)
        if ($null -ne $NetHost.MAC) {
            $mesage = "Mac Address found! [" + $NetHost.MAC + "]"
            Write-Host $mesage
        }
        $NetHost  | Add-Member -NotePropertyName Hostname -NotePropertyValue (Get-Hostname -IPAddress $IP)
        if ($null -ne $NetHost.Hostname) {
            $mesage = "Hostname found! [" + $NetHost.Hostname + "]"
            Write-Host $mesage
        }
        $NetHost  | Add-Member -NotePropertyName Manufacturer -NotePropertyValue (Convert-MACToVendor -MAC ($NetHost.MAC))
        if ($null -ne $NetHost.Vendor) {
            $mesage = "Vendor found! [" + $NetHost.Vendor + "]"
            Write-Host $mesage
        }
        $NetHost  | Add-Member -NotePropertyName Pingable -NotePropertyValue (Invoke-FastPing -IPAddress $IP)
        if ($NetHost.Pingable -eq $true) {
            Write-Host "Computer responds to ping"
        }else{
            Write-Host "Computer doesn't responds to ping"
        }
        $PortsScanResult = Invoke-TCPPortScan -IPAddress $IP -Ports $PortsToScan
        $OpenPorts = (($PortsScanResult | where {$_.State -eq "Open"}).Port -join ",")
        if ($null -ne $OpenPorts) {
            $mesage = "Open Ports found! [" + $OpenPorts + "]"
            Write-Host $mesage
        }
        $ClosedPorts = (($PortsScanResult | where {$_.State -eq "Closed"}).Port -join ",")
        if ($null -ne $ClosedPorts) {
            $mesage = "Close Ports found! [" + $ClosedPorts + "]"
            Write-Host $mesage
        }
        $NetHost  | Add-Member -NotePropertyName OpenPorts -NotePropertyValue $OpenPorts
        $NetHost  | Add-Member -NotePropertyName ClosedPorts -NotePropertyValue $ClosedPorts
        $Global:Hosts += $NetHost
    }
    # Create NetHost Objects by processing StaleIPAdresses (IPAddress,MAC,Hostname,Manufacturer,Pingable)
    foreach ($IP in $StaleIPAdresses) {
        if (!(Test-DuplicateIP -IPAdress $IP) -ne $true ) {
            Write-Host "Scanning $IP ..."
        $NetHost = New-Object -TypeName PSCustomObject
        $NetHost  | Add-Member -NotePropertyName IPAddress -NotePropertyValue $IP
        $NetHost  | Add-Member -NotePropertyName MAC -NotePropertyValue (Convert-IPToMAC -IPAddress "$IP" | where {$_ -ne "00-00-00-00-00-00"} | Select-Object -Unique)
        if ($null -ne $NetHost.MAC) {
            $mesage = "Mac Address found! [" + $NetHost.MAC + "]"
            Write-Host $mesage
        }
        $NetHost  | Add-Member -NotePropertyName Hostname -NotePropertyValue (Get-Hostname -IPAddress $IP)
        if ($null -ne $NetHost.Hostname) {
            $mesage = "Hostname found! [" + $NetHost.Hostname + "]"
            Write-Host $mesage
        }
        $NetHost  | Add-Member -NotePropertyName Manufacturer -NotePropertyValue (Convert-MACToVendor -MAC ($NetHost.MAC))
        if ($null -ne $NetHost.Vendor) {
            $mesage = "Vendor found! [" + $NetHost.Vendor + "]"
            Write-Host $mesage
        }
        $NetHost  | Add-Member -NotePropertyName Pingable -NotePropertyValue (Invoke-FastPing -IPAddress $IP)
        if ($NetHost.Pingable -eq $true) {
            Write-Host "Computer responds to ping"
        }else{
            Write-Host "Computer doesn't responds to ping"
        }
        $PortsScanResult = Invoke-TCPPortScan -IPAddress $IP -Ports $PortsToScan
        $OpenPorts = (($PortsScanResult | where {$_.State -eq "Open"}).Port -join ",")
        if ($null -ne $OpenPorts) {
            $mesage = "Open Ports found! [" + $OpenPorts + "]"
            Write-Host $mesage
        }
        $ClosedPorts = (($PortsScanResult | where {$_.State -eq "Closed"}).Port -join ",")
        if ($null -ne $ClosedPorts) {
            $mesage = "Close Ports found! [" + $ClosedPorts + "]"
            Write-Host $mesage
        }
        $NetHost  | Add-Member -NotePropertyName OpenPorts -NotePropertyValue $OpenPorts
        $NetHost  | Add-Member -NotePropertyName ClosedPorts -NotePropertyValue $ClosedPorts
        $Global:Hosts += $NetHost
        }
    }
    return $Global:Hosts
}
#----------------------------------------------------------[Declarations]----------------------------------------------------------
$OutputDir = "$env:systemdrive\ProgramData\NetScan"
$XMLPath   = $OutputDir + "\scanresults.xml"
$CSVPath   = $OutputDir + "\scanresults.csv"
#N-Able API Auth
$Global:NCentral_FQDN        = "ncod440.n-able.com"
$Global:NAble_SecureString   = ConvertTo-SecureString "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTb2xhcndpbmRzIE1TUCBOLWNlbnRyYWwiLCJ1c2VyaWQiOjY1Njk3NjQ5NiwiaWF0IjoxNjE0NjI3MzkwfQ.8yntfz1Rh5o245ylT9B-vJZZJ-1GWtRiDIB_qnacq3I" -AsPlainText -Force
$Global:NAble_Credentials    = New-Object PSCredential ("_JWT", $Global:NAble_SecureString)
#---------------------------------------------------------[Initialization]---------------------------------------------------------
$backup = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
if (!(Test-Path $OutputDir)) { mkdir $OutputDir }
#-----------------------------------------------------------[Execution]------------------------------------------------------------

## PART 1 ##
#scan the network
$NetworkHosts = Invoke-NetScan
#show the results
$NetworkHosts
# Export results to Xml
$NetworkHosts | Export-Clixml -Path $XMLPath -Encoding UTF8
# Export results to Csv
$NetworkHosts | Export-Csv -Path $CSVPath -Encoding UTF8 -NoTypeInformation

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
$ErrorActionPreference = $backup