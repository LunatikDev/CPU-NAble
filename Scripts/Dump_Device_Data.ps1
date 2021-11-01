#N-Able API Auth
$Global:NCentral_FQDN        = "ncod440.n-able.com"
$Global:NAble_SecureString   = ConvertTo-SecureString "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTb2xhcndpbmRzIE1TUCBOLWNlbnRyYWwiLCJ1c2VyaWQiOjY1Njk3NjQ5NiwiaWF0IjoxNjE0NjI3MzkwfQ.8yntfz1Rh5o245ylT9B-vJZZJ-1GWtRiDIB_qnacq3I" -AsPlainText -Force
$Global:NAble_Credentials    = New-Object PSCredential ("_JWT", $Global:NAble_SecureString)

New-NCentralConnection $Global:NCentral_FQDN $NAble_Credentials

#list all customers
$CustomerList = Get-NCCustomerList | Select-Object -Property customerid,customername
$path = "C:\temp\customerlist.xml"
$CustomerList | Export-Clixml -Path $path -Encoding utf8

### working ###
$customers = import-csv -Path "C:\temp\customers1.csv"

foreach ($customer in $customers) {
    $id = $customer.id
    write-host "processing devices for customer with id $id"
    $path = "C:\customers\" + $id
    if (!(Test-path $path)) { mkdir $path }
    Set-Location $path
    try {
        $oDevices = Get-NCDeviceList -CustomerIDs $id | Get-NCDeviceObject
    }
    catch {
        write-host "the connection was reset, reconnecting in 1 sec.."
        Start-Sleep -s 1
        $Global:NCentral_FQDN        = "ncod440.n-able.com"
        $Global:NAble_SecureString   = ConvertTo-SecureString "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTb2xhcndpbmRzIE1TUCBOLWNlbnRyYWwiLCJ1c2VyaWQiOjY1Njk3NjQ5NiwiaWF0IjoxNjE0NjI3MzkwfQ.8yntfz1Rh5o245ylT9B-vJZZJ-1GWtRiDIB_qnacq3I" -AsPlainText -Force
        $Global:NAble_Credentials    = New-Object PSCredential ("_JWT", $Global:NAble_SecureString)
        New-NCentralConnection $Global:NCentral_FQDN $NAble_Credentials
    }finally{
        $oDevices = (Get-NCDeviceList -CustomerIDs $id | Get-NCDeviceObject)
    }
    $filename = ".\" + $id + "_devices.xml"
    $oDevices | Export-Clixml -Path $filename -Encoding utf8
    Start-Sleep -s 1
}
$DevicesXml = (Get-ChildItem -Path "C:\customers" -Filter *.xml -Recurse).fullname
$global:oDevices = @()
foreach ($DeviceXml in $DevicesXml) {
    $devices = Import-Clixml -Path $DeviceXml | where { $_.deviceclass -Match "Windows*"}
    $global:oDevices += $devices
}
$global:oDevices | Export-Clixml -Path "C:\customers\WindowsDevices.xml" -Encoding utf8

# Custom convertion of osfeatures table to CSV (to preserve deviceid as integer)
$osfeatures = $global:oDevices.osfeatures
$csvosfeatures = @()
$csvosfeatures += '"pkey","pvalue","DeviceId","ItemId"'
foreach ($osfeature in $osfeatures) {
    if ($null -ne $osfeature.pkey -and $null -ne $osfeature.pvalue -and $null -ne $osfeature.DeviceId -and $null -ne $osfeature.ItemId) {
        $csvosfeatures += '"' + $osfeature.pkey + '",' + '"' + $osfeature.pvalue + '",' + $osfeature.DeviceId + ',"' + $osfeature.ItemId + '"'
    }
}
$csvosfeatures | Out-File -PSPath "C:\Customers\devices\osfeatures.csv" -Encoding utf8
# Custom convertion of motherboard table to CSV (to preserve deviceid as integer)
$motherboards = $global:oDevices.motherboard
$csvmotherboards = @()
$csvmotherboards += '"serialnumber","biosversion","ItemId","manufacturer","version","DeviceId","product"'
foreach ($motherboard in $motherboards) {
    if ($null -ne $motherboard.serialnumber -and $null -ne $motherboard.biosversion -and $null -ne $motherboard.ItemId -and $null -ne $motherboard.manufacturer -and $null -ne $motherboard.version -and $null -ne $motherboard.product -and $null -ne $motherboard.DeviceId) {
        if ($null -eq $motherboard.serialnumber) { $serialnumber = "N/A" } else { $serialnumber = $motherboard.serialnumber }
        switch ($motherboard.serialnumber) {
            "" { $csvmotherboards += '"N/A",' + '"' + $motherboard.biosversion + '","' + $motherboard.ItemId + '"' + ',"' + $motherboard.manufacturer + '",' + '"' + $motherboard.version + '",' + $motherboard.DeviceId + ',"' + $motherboard.product + '"' }
            $null { $csvmotherboards += '"N/A",' + '"' + $motherboard.biosversion + '","' + $motherboard.ItemId + '"' + ',"' + $motherboard.manufacturer + '",' + '"' + $motherboard.version + '",' + $motherboard.DeviceId + ',"' + $motherboard.product + '"' }
            Default { $csvmotherboards += '"' + $motherboard.serialnumber + '",' + '"' + $motherboard.biosversion + '","' + $motherboard.ItemId + '"' + ',"' + $motherboard.manufacturer + '",' + '"' + $motherboard.version + '",' + $motherboard.DeviceId + ',"' + $motherboard.product + '"' }
        }
    }
} 
$csvmotherboards | Out-File -PSPath "C:\Customers\devices\motherboards.csv" -Encoding utf8
# Custom convertion of processor table to CSV (to preserve deviceid as integer)
$processors = $global:oDevices.processor
$csvprocessors = @()
$csvprocessors += '"ItemId","vendor","architecture","description","cpuid","name","numberofcores","maxclockspeed","numberofcpus","DeviceId"'
foreach ($processor in $processors) {
    if ($null -ne $processor.ItemId -and $null -ne $processor.description -and $null -ne $processor.cpuid -and $null -ne $processor.name -and $null -ne $processor.numberofcores -and $null -ne $processor.maxclockspeed -and $null -ne $processor.numberofcpus -and $null -ne $processor.DeviceId) {
        $csvprocessors += '"' + $processor.ItemId + '",' + '"N/A",' + '"N/A",' + '"' + $processor.description + '",' + '"' + $processor.cpuid + '",' + '"' + $processor.name + '",' + $processor.numberofcores + ',' + $processor.maxclockspeed + ',' + $processor.numberofcpus+ ',' + $processor.DeviceId
    }
}
$csvprocessors | Out-File -PSPath "C:\Customers\devices\processors.csv" -Encoding utf8
# Custom convertion of os table to CSV (to preserve deviceid as integer)
$OSes = $global:oDevices.os
$csvos = @()
$csvos += '"ItemId","csdversion","reportedos","version","installdate","serialnumber","licensetype","osarchitecture","lastbootuptime","publisher","licensekey","supportedos","DeviceId"'
foreach ($OS in $OSes) {
    if ($null -ne $OS.ItemId -and $null -ne $OS.reportedos -and $null -ne $OS.version -and $null -ne $OS.installdate -and $null -ne $OS.serialnumber -and $null -ne $OS.licensetype -and $null -ne $OS.osarchitecture -and $null -ne $OS.lastbootuptime -and $null -ne $OS.publisher -and $null -ne $OS.licensekey -and $null -ne $OS.supportedos -and $null -ne $OS.DeviceId) {
        $csvos += '"' + $OS.ItemId + '",' + '"N/A",' + '"' + $OS.reportedos + '",' + '"' + $OS.version + '",' + '"' + $OS.installdate + '","' + $OS.serialnumber + '","' + $OS.licensetype + '","' + $OS.osarchitecture + '","' + $OS.lastbootuptime + '","' + $OS.publisher + '","' + $OS.licensekey + '","' + $OS.supportedos + '",' + $OS.DeviceId
    }
}
$csvos | Out-File -PSPath "C:\Customers\devices\oses.csv" -Encoding utf8
# Custom convertion of devices table to CSV (to preserve deviceid as integer)
$devices = $global:oDevices | Select-Object -Property deviceclass,deviceid,customerid,longname
$csvdevices = @()
$csvdevices += '"longname","deviceclass","CustomerId","DeviceId"'
foreach ($device in $devices) {
    if ($null -ne $device.longname -and $null -ne $device.deviceclass -and $null -ne $device.CustomerId -and $null -ne $device.DeviceId) {
        $csvdevices += '"' + $device.longname + '",' + '"' + $device.deviceclass + '",' + $device.CustomerId + ',' + $device.DeviceId
    }
}
$csvdevices | Out-File -PSPath "C:\Customers\devices\devices.csv" -Encoding utf8
$global:oDevices.service | Export-Csv -Path "C:\customers\devices\service.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.networkadapter | Export-Csv -Path "C:\customers\devices\networkadapter.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.os | Export-Csv -Path "C:\customers\devices\os.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.patch | Export-Csv -Path "C:\customers\devices\patch.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.physicaldrive | Export-Csv -Path "C:\customers\devices\physicaldrive.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.memory | Export-Csv -Path "C:\customers\devices\memory.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.port | Export-Csv -Path "C:\customers\devices\port.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.folderforshare | Export-Csv -Path "C:\customers\devices\folderforshare.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.usbdevice | Export-Csv -Path "C:\customers\devices\usbdevice.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.application | Export-Csv -Path "C:\customers\devices\application.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.socustomer | Export-Csv -Path "C:\customers\devices\socustomer.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.logicaldevice | Export-Csv -Path "C:\customers\devices\logicaldevice.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.mediaaccessdevice | Export-Csv -Path "C:\customers\devices\mediaaccessdevice.csv" -Encoding utf8 -NoTypeInformation
$global:oDevices.computersystem | Export-Csv -Path "C:\customers\devices\computersystem.csv" -Encoding utf8 -NoTypeInformation
"C:\customers\devices\"
"C:\customers\devices\"
"C:\customers\devices\"
"C:\customers\devices\"
"C:\customers\devices\"
"C:\customers\devices\"
"C:\customers\devices\"




#save device list for each customer
$CustomerList | ForEach-Object -Process {
    $path = "C:\temp\customers\" + $_.customername + ".xml"
    Get-NCDeviceList -CustomerIDs ($_.customerid) | Export-Clixml -Path $path -Encoding utf8
}

#load each customer xml file and get devices ID's list and extract 
$customersXml = (Get-ChildItem -Path "C:\Temp\Customers").fullname
$aDevicesIds = @()
foreach ($entry in $customersXml) {
    $xml = import-clixml -path "$entry"
    $devicesList = $xml.deviceid
    foreach ($device in $devicesList) {
        $aDevicesIds += $device
    }
}
$aDevicesIds
$oDevices = Get-NCDeviceObject -DeviceIDs $devicesList
    $path = "C:\Temp\Devices\" + $xml[0].customerid + "_" + $xml[0].customername + "_Devices.xml"
    $oDevices | Export-Clixml -Path $path -Encoding utf8
    Start-Sleep -s 1
#Filter the list to get only windows workstations
$Workstations = $oDevices | where { $_.deviceclass -eq "Workstations - Windows"}
$Laptops = $oDevices | where { $_.deviceclass -eq "Laptop - Windows"}
# get all devices as objects

$Batch1 = $Workstations[0..499]
$Batch2 = $Workstations[500..999]
$Batch3 = $Workstations[1000..1499]
$Batch4 = $Workstations[1500..1999]
$Batch5 = $Workstations[2000..2499]
$Batch6 = $Workstations[2500..2955]
$Batch7 = $Laptops[0..499]
$Batch8 = $Laptops[500..999]
$Batch9 = $Laptops[1000..1267]   

$global:AllDevicesObjects = @()
$Batch1 | ForEach-Object -Process {
    start-sleep -s 1
    $global:AllDevicesObjects += ($_ | Get-NCDeviceObject)
}
$global:AllDevicesObjects | Export-Clixml -Path "C:\temp\batch1.xml"

$global:AllDevicesObjects = @()
$Batch2 | ForEach-Object -Process {
    start-sleep -s 1
    $global:AllDevicesObjects += ($_ | Get-NCDeviceObject)
}
$global:AllDevicesObjects | Export-Clixml -Path "C:\temp\batch2.xml"

$global:AllDevicesObjects = @()
$Batch3 | ForEach-Object -Process {
    start-sleep -s 1
    $global:AllDevicesObjects += ($_ | Get-NCDeviceObject)
}
$global:AllDevicesObjects | Export-Clixml -Path "C:\temp\batch3.xml"

$global:AllDevicesObjects = @()
$Batch4 | ForEach-Object -Process {
    start-sleep -s 1
    $global:AllDevicesObjects += ($_ | Get-NCDeviceObject)
}
$global:AllDevicesObjects | Export-Clixml -Path "C:\temp\batch4.xml"

$global:AllDevicesObjects = @()
$Batch5 | ForEach-Object -Process {
    start-sleep -s 1
    $global:AllDevicesObjects += ($_ | Get-NCDeviceObject)
}
$global:AllDevicesObjects | Export-Clixml -Path "C:\temp\batch5.xml"

$global:AllDevicesObjects = @()
$Batch6 | ForEach-Object -Process {
    start-sleep -s 1
    $global:AllDevicesObjects += ($_ | Get-NCDeviceObject)
}
$global:AllDevicesObjects | Export-Clixml -Path "C:\temp\batch6.xml"

$global:AllDevicesObjects = @()
$Batch7 | ForEach-Object -Process {
    start-sleep -s 1
    $global:AllDevicesObjects += ($_ | Get-NCDeviceObject)
}
$global:AllDevicesObjects | Export-Clixml -Path "C:\temp\batch7.xml"

$global:AllDevicesObjects = @()
$Batch8 | ForEach-Object -Process {
    start-sleep -s 1
    $global:AllDevicesObjects += ($_ | Get-NCDeviceObject)
}
$global:AllDevicesObjects | Export-Clixml -Path "C:\temp\batch8.xml"

$global:AllDevicesObjects = @()
$Batch9 | ForEach-Object -Process {
    start-sleep -s 1
    $global:AllDevicesObjects += ($_ | Get-NCDeviceObject)
}
$global:AllDevicesObjects | Export-Clixml -Path "C:\temp\batch9.xml"