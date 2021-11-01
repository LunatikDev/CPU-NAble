#N-Able API Auth
$Global:NCentral_FQDN        = "ncod440.n-able.com"
$Global:NAble_SecureString   = ConvertTo-SecureString "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJTb2xhcndpbmRzIE1TUCBOLWNlbnRyYWwiLCJ1c2VyaWQiOjY1Njk3NjQ5NiwiaWF0IjoxNjE0NjI3MzkwfQ.8yntfz1Rh5o245ylT9B-vJZZJ-1GWtRiDIB_qnacq3I" -AsPlainText -Force
$Global:NAble_Credentials    = New-Object PSCredential ("_JWT", $Global:NAble_SecureString)

New-NCentralConnection $Global:NCentral_FQDN $NAble_Credentials

$CustomerList = Get-NCCustomerList | Select-Object -Property customerid,customername
#$Global:Customers = @()
mkdir "C:\clients"
$CustomerList | ForEach-Object {
    $FolderPath = "C:\clients\" + $_.customername + "\"
    mkdir $FolderPath
    $DevicesSavePath = $FolderPath + "Devices.csv"
    $Devices = Get-NCDeviceList -CustomerIDs $_.customerid | Select-Object -Property longname,deviceid,deviceclass,supportedos | Sort-Object -Property deviceclass
    $Devices | Export-Csv "$DevicesSavePath" -Encoding utf8 -NoTypeInformation
}
#$Global:Customers
<#
Copyright 2019 Mytech Partners, Inc
Script by Christian Oaksford

Upgrade Windows 7 and 2008 R2 devices with Powershell 2.0 to Powershell 5.1

The following inputs will alter behavior in these ways when set to "Y":
	"$Bulk" adds a delay of randomly up to 30 minutes, to avoid flooding weak connections on batch tasks.
	"$Force" ignores a check for whether attempted install seems to be unnecessary and reattempts install.
	"$Refresh" redownloads files that are already downloaded, useful if files are incomplete or corrupt.

If you want to pre-stage the installer files, you can put them at "C:\Win7AndW2K8R2-KB3191566-x64.msu"
for a 64-bit system or "C:\Win7-KB3191566-x86.msu" for a 32-bit system, and that will be used instead of
trying to download.
#>


if ($Bulk -eq "Y") {
	$Now = $False
} else {
	$Now = $True
}

if ($Force -eq "Y") {
	$Force = $True
} else {
	$Force = $False
}

if ($Refresh -eq "Y") {
	$Refresh = $True
} else {
	$Now = $False
}

$scriptresults = ""

$Lastboot = [Management.ManagementDateTimeConverter]::ToDateTime($(Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
$WindowsVersion = [System.Environment]::OSVersion.Version

# function "unzip" adapted from https://serverfault.com/questions/18872/how-to-zip-unzip-files-in-powershell?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
function unzip($zipfile, $destination) { 
	$shell_app=new-object -com shell.application
	$zipfile = $shell_app.namespace($zipfile)
	$destination = $shell_app.namespace($destination)
	$destination.Copyhere($zipfile.items(), 0x14) #0x14 means overwrite all, hide window
	#Asynchronous method, wait for it to complete
	sleep 10
}

# Filter in Windows 7 or 2008 R2 is running PS 2.0
if (($WindowsVersion.Major -eq 6) -and ($WindowsVersion.Minor -eq 1) -and ($PSVersionTable.PSVersion.Major -eq 2)) { 
	$scriptresults += "Checking .NET framework version..."
    if (-Not (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release -ge 379893) { #Check for .NET 4.5.2 or newer
		$scriptresults += "out of date. "
		if ((Get-WmiObject Win32_OperatingSystem).ServicePackMajorVersion -eq 0) {
			Write-Host "Service Pack 1 is required but is not installed."
		} else {
			# If -Force is specified, or if the dotnet datestamp file is missing, or if the date in it is older than the last bootup time
			if ($force -or (-not (Test-Path "C:\windows\temp\psupgrade_dotnet.txt")) -or ($Lastboot -gt [DateTime](Get-Content "C:\Windows\Temp\psupgrade_dotnet.txt"))) {
				$scriptresults +=  ".NET framework 4.5.2 or newer is required"
				if (-not (Test-Path "C:\Windows\Temp\NDP471-KB4033342-x86-x64-AllOS-ENU.exe") -or $Refresh) {
					$scriptresults +=  "Downloading .NET framework installer..."
					if (-not $Now) {sleep ((random) % 1800)} #wait a random time up to 30 minutes
					$dltime = (Measure-Command {(New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/9/E/6/9E63300C-0941-4B45-A0EC-0008F96DD480/NDP471-KB4033342-x86-x64-AllOS-ENU.exe", "C:\Windows\Temp\NDP471-KB4033342-x86-x64-AllOS-ENU.exe")}).TotalSeconds
					$scriptresults +=  "download took $dltime seconds. "
				}
				if (Test-Path "C:\Windows\Temp\NDP471-KB4033342-x86-x64-AllOS-ENU.exe") {
					C:\Windows\Temp\NDP471-KB4033342-x86-x64-AllOS-ENU.exe /quiet /norestart
					Set-Content -Path "C:\windows\temp\psupgrade_dotnet.txt" (Get-Date)
					$scriptresults +=  "Installing .NET framework 4.7.1"
				} else {
					$scriptresults +=  "Download of .Net framework failed"
				}
			} else {
				$scriptresults +=  ".Net framework install has already been attempted."
			}
		}
    } else {
		$scriptresults +=  ".NET framework looks good.`r`n"
	}
	# If -Force is specified, or if the wusa datestamp file is missing, or if the date in it is older than the last bootup time
    if ($force -or (-not (Test-Path "C:\Windows\Temp\psupgrade_wusa.txt")) -or ($Lastboot -gt [DateTime](Get-Content "C:\Windows\Temp\psupgrade_wusa.txt"))) {
		
		if (${env:ProgramFiles(x86)} -eq "C:\Program Files (x86)"){
			$arch = 64
			$zipurl = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip"
			$zipdest = "C:\windows\temp\Win7AndW2K8R2-KB3191566-x64.zip"
			$msudest = "C:\windows\temp\Win7AndW2K8R2-KB3191566-x64.msu"
			$drvsrc = "C:\Win7AndW2K8R2-KB3191566-x64.msu"
		} else {
			$arch = 32
			$zipurl = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7-KB3191566-x86.zip"
			$zipdest = "C:\Windows\Temp\Win7-KB3191566-x86.zip"
			$msudest = "C:\windows\temp\Win7-KB3191566-x86.msu"
			$drvsrc = "C:\Win7-KB3191566-x86.msu"
		}
		$scriptresults += "System is $arch-bit. "
		if (-not (Test-Path $msudest) -or $Refresh) {
			if (Test-Path $drvsrc) {
				$scriptresults += "Update file missing, copying from root..."
				Move-Item $drvsrc $msudest
			} else {
				$scriptresults += "Update file missing, downloading zip..."
				if (-not $Now) {sleep ((random) % 1800)} #wait a random time up to 30 minutes
				$dltime = (Measure-Command {(New-Object System.Net.WebClient).DownloadFile($zipurl, $zipdest)}).TotalSeconds
				if (Test-Path $zipdest) {
					$scriptresults += "Zip downloaded in $dltime seconds, extracting. "
					if (Test-Path $msudest) {Remove-Item $msudest}
					unzip $zipdest "C:\Windows\Temp\"
					if (Test-Path $msudest) {$scriptresults += "Extracted successfully. "}
				} else {
					$scriptresults += "Download took $dltime seconds, then failed ($arch-bit)"
				}
			}
		}
		if (Test-Path $msudest) {
			wusa $msudest /quiet /norestart
			Set-Content -Path "C:\windows\temp\psupgrade_wusa.txt" (Get-Date)
			$scriptresults += "Installing $arch-bit WMF 5.1"
		} else {
			$scriptresults += "Unzip failed ($arch-bit)"
		}
	} else {
		$scriptresults += "Script already run since last reboot, try with -Force if you're sure this needs to run again."
	}
} else {
	if ($PSVersionTable.PSVersion.Major -eq 2) {
		$scriptresults += "Update not applicable."
	} else {
		$scriptresults += "Update not needed"
	}
}
