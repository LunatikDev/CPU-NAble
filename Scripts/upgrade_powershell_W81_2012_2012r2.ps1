<#
.SYNOPSIS
    N-Able - Script pour upgrade powershell a 5.1 (Windows 8.1, Server 2012 & Server 2012 R2)
.DESCRIPTION
    N-Able - Script pour upgrade powershell a 5.1 (Windows 8.1, Server 2012 & Server 2012 R2)
.NOTES
    Fichier    : upgrade_powershell_W81_2012_2012r2.ps1
    Author     : Jerome Couette - jerome.couette@cpu.ca
    Date       : March 25 2021
    Version    : 1.0
#>
#---------------------------------------------------------[Initialization]---------------------------------------------------------

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#----------------------------------------------------------[Declarations]----------------------------------------------------------
$WindowsVersion = [System.Environment]::OSVersion.Version.ToString()
$Arch = $env:PROCESSOR_ARCHITECTURE
$URI_MSU_W81_2012R2_X64 = "http://chocolatey.cpu.qc.ca/endpoints/CPU/content/DEVOPS/WMF51/Win8.1AndW2K12R2-KB3191564-x64.msu"
$MSU_W81_2012R2_X64_DEST = "$env:SystemDrive\temp\Win8.1AndW2K12R2-KB3191564-x64.msu"
$URI_MSU_W81_X86 = "http://chocolatey.cpu.qc.ca/endpoints/CPU/content/DEVOPS/WMF51/Win8.1-KB3191564-x86.msu"
$MSU_W81_X86_DEST = "$env:SystemDrive\temp\Win8.1-KB3191564-x86.msu"
$URI_MSU_W2012_X64 = "http://chocolatey.cpu.qc.ca/endpoints/CPU/content/DEVOPS/WMF51/W2K12-KB3191565-x64.msu"
$MSU_W2012_X64_DEST = "$env:SystemDrive\temp\W2K12-KB3191565-x64.msu"
#-----------------------------------------------------------[Execution]------------------------------------------------------------
switch ($WindowsVersion) {
	# Windows 8.1
	"6.3.9600.0" {
		if ($Arch -eq "AMD64") { #OS is 64bit
			#create temp folder
			if (!(test-path "$env:SystemDrive\temp")) {mkdir "$env:SystemDrive\temp"}

			#download msu
			Invoke-WebRequest $URI_MSU_W81_2012R2_X64 -Headers @{"AUTHORIZATION"="Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("DefaultFeedUser:RC8QCsIKUe"))} -OutFile "$MSU_W81_2012R2_X64_DEST"
			
			#install msu
			if (Test-Path $MSU_W81_2012R2_X64_DEST) { wusa $MSU_W81_2012R2_X64_DEST /quiet /norestart }
		}else { #OS is 32bit
			#create temp folder
			if (!(test-path "$env:SystemDrive\temp")) {mkdir "$env:SystemDrive\temp"}

			#download msu
			Invoke-WebRequest $URI_MSU_W81_X86 -Headers @{"AUTHORIZATION"="Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("DefaultFeedUser:RC8QCsIKUe"))} -OutFile "$MSU_W81_X86_DEST"
			
			#install msu
			if (Test-Path $MSU_W81_X86_DEST) { wusa $MSU_W81_X86_DEST /quiet /norestart }
		}
	} 
	# Server 2012
	"6.2.9200.0" {
		#create temp folder
		if (!(test-path "$env:SystemDrive\temp")) {mkdir "$env:SystemDrive\temp"}

		#download msu
		Invoke-WebRequest $URI_MSU_W2012_X64 -Headers @{"AUTHORIZATION"="Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("DefaultFeedUser:RC8QCsIKUe"))} -OutFile "$MSU_W2012_X64_DEST"
		
		#install msu
		if (Test-Path $MSU_W2012_X64_DEST) { wusa $MSU_W2012_X64_DEST /quiet /norestart }
	} 
	# Server 2012 R2
	"6.3.9600.0" {
		#create temp folder
		if (!(test-path "$env:SystemDrive\temp")) {mkdir "$env:SystemDrive\temp"}

		#download msu
		Invoke-WebRequest $URI_MSU_W81_2012R2_X64 -Headers @{"AUTHORIZATION"="Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("DefaultFeedUser:RC8QCsIKUe"))} -OutFile "$MSU_W81_2012R2_X64_DEST"
		
		#install msu
		if (Test-Path $MSU_W81_2012R2_X64_DEST) { wusa $MSU_W81_2012R2_X64_DEST /quiet /norestart }
	} 
}
