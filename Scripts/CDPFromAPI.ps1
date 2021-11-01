

#
# Generate a pseudo-unique namespace to use with the New-WebServiceProxy and 
# associated types.
#
# By controlling the namespace, the script becomes portable and is not
# dependent upon the endpoint url the webservice is connecting.  However, this
# introduces another complexity because once the namespace is defined within a
# powershell session, it cannot be reused, nor can it be undefined.  As long as
# all the calls are made to the existing webserviceproxy, then everything would be
# OK. But, if you try to rerun the script without closing and reopening the
# powershell session, you will get an error.
#
# One way around this is to create a unique namespace each time the script is run.
# We do this by using the last 'word' of a GUID appended to our base namespace 'NAble'.
# This means our type names for parameters (such as T_KeyPair) now have a dynamic
# type.  We could pass types to each new-object call using "$NWSNameSpace.T_KeyPair",
# and I find it more readable to define our 'dynamic' types here and use the typenames
# in variables when calling New-Object.
#
$NWSNameSpace = "NAble" + ([guid]::NewGuid()).ToString().Substring(25)
$KeyPairType = "$NWSNameSpace.T_KeyPair"
$DevicePropertyType = "$NWSNameSpace.DeviceProperty"
$DevicePropertiesType = "$NWSNameSpace.DeviceProperties"

Write-Output "Using Namespace $NWSNameSpace"
Write-Output " "


#
# Locate the Windows Agent Config folder
#
# By querying the Windows Agent Service path, the folder will be correctly identified
# even if it's not on the C: drive.
#
$AgentConfigFolder = (gwmi win32_service -filter "Name like 'Windows Agent Service'").PathName
$AgentConfigFolder = $AgentConfigFolder.Replace("bin\agent.exe", "config").Replace('"','')


#
# Get the N-Central server out of the ServerConfig.xml file
#
function Get-NCentralSvr() {
	$ConfigXML = [xml](Get-Content "$Script:AgentConfigFolder\ServerConfig.xml")
	$ConfigXML.ServerConfig.ServerIP
	}


#
# Get the device's ApplianceID out of the ApplianceConfig.xml file
#
function Get-ApplianceID() {
	$ConfigXML = [xml](Get-Content "$Script:AgentConfigFolder\ApplianceConfig.xml")
	$ConfigXML.ApplianceConfig.ApplianceID
	}


#
# Determine where the N-Central server is
#
$serverHost = Read-Host "Enter the fqdn of the N-Central Server "

#
# Get credentials
# We could read them as plain text and then create a SecureString from it
# By reading it as a SecureString, the password is obscured on entry
#
# We still have to extract a plain-text version of the password to pass to
# the API call.
#
$username = Read-Host "Enter N-Central user id "
$secpasswd = Read-Host "Enter password " -AsSecureString

$creds = New-Object System.Management.Automation.PSCredential ("\$username", $secpasswd)
$password = $creds.GetNetworkCredential().Password

$bindingURL = "https://" + $serverHost + "/dms/services/ServerEI?wsdl"
$nws = New-Webserviceproxy $bindingURL -credential $creds -Namespace ($NWSNameSpace)

#
# Set up and execute the query
#
$DevProps = $nws.devicePropertyList(
    $username,
    $password,
    $null,	# Pass nulls and get *all devices*
    $null,
    $null,
    $null,
    $false
    )

($DevProps).Count 
Foreach ($Device in $DevProps) {
    $Device.Properties | ft *
}