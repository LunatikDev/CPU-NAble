Clear-Host

@"
GetCustomerListwithSites-Prompted.ps1

This script outputs the customer list.  The script prompts for paramters:

N-Central server name
N-Central userid
N-Central password
(Optional) Output CSV filename

Output is the customer id, the customer or site name, and the parent customer id

Created by:	Jon Czerwinski, Cohn Consulting Corporation
Date:		February 7, 2016
Version:	1.0

"@


#
# Determine where the N-Central server is
#
$serverHost = Read-Host "Enter the fqdn of the N-Central Server "


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
$KeyValueType = "$NWSNameSpace.T_KeyValue"


#
# Create PrinterData type to hold printer name and port
#
Add-Type -TypeDefinition @"
public class CustomerData {
	public string ID;
	public string Name;
	public string ParentID;
	}
"@


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
# Select the output file
#
Write-Host
# Uncomment the line below and the final line of the script to get output in a CSV file
# $CSVFile = (Read-Host "Enter the CSV output filename ").Trim()

#
# Set up and execute the query
#
$KeyPairs = @()
$KeyPair = New-Object -TypeName $KeyPairType
$KeyPair.Key = 'listSOs'
$KeyPair.Value = "true"
$KeyPairs += $KeyPair

$rc = $nws.customerListChildren($username, $password, $KeyPairs)


#
# Set up the customers array, then populate
#
$Customers = @()

foreach ($device in $rc) {
	$DeviceAssetInfo = @{}
	foreach ($item in $device.Info) {$DeviceAssetInfo[$item.key] = $item.Value}

	$Customer = New-Object CustomerData
	$Customer.ID = $DeviceAssetInfo["customer.customerid"]
	$Customer.Name = $DeviceAssetInfo["customer.customername"]
	$Customer.ParentID = $DeviceAssetInfo["customer.parentid"]
	
	$Script:Customers += $Customer

	Remove-Variable DeviceAssetInfo
}
	
$NCCustomersList = ($Customers | Sort-Object -Property ID | Format-Table -AutoSize)
$NCCustomersList | Export-Clixml -Path "c:\temp\NCCustomersList.xml" -NoTypeInformation -Force