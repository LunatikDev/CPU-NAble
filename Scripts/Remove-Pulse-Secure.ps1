$PulseUninstall = "$env:SystemDrive\Program Files (x86)\Juniper Networks\Junos Pulse\PulseUninstall.exe" 
$PulseUninstall2 = "$env:SystemDrive\Program Files (x86)\Pulse Secure\Pulse\PulseUninstall.exe" 
$PulseSCCUninstall = "$env:SystemDrive\Windows\Downloaded Program Files\JuniperSetupClientCtrlUninstaller.exe"
$PulseSCCUninstall64 = "$env:SystemDrive\Windows\Downloaded Program Files\JuniperSetupClientCtrlUninstaller64.exe"

#Uninstalling Juniper Setup Client
$users = (Get-ChildItem -Path "$env:SystemDrive\Users\").Name
foreach ($user in $users) {
    $PulseSCUninstall = "$env:SystemDrive\Users\$user\AppData\Roaming\Juniper Networks\Setup Client\uninstall.exe"
    if (Test-path -Path $PulseSCUninstall) {
        Write-host "Juniper Setup Client Uninstaller found for $user! Uninstalling..."
        &$PulseSCUninstall /S 
        Start-Sleep -s 2
        Write-Host "Cleaning up leftover files..."
        remove-item "$env:SystemDrive\Users\$user\AppData\Roaming\Juniper Networks" -Recurse -Force
    }
}

#remove Juniper Setup Client registry Entry in users profile
$UsersProfiles = Get-ChildItem Registry::HKEY_USERS | ? { $_.PSChildname -match $PatternSID } | Select @{ name = "SID"; expression = { $_.PSChildName } }
foreach ($SID in $UsersProfiles.SID) {
    $targetRegKey = "Registry::HKEY_USERS\$SID\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Juniper_Setup_Client"
    $result = test-path -Path $targetRegKey
    if ($result = $true) {
        Write-host "Juniper Setup Client Entry found for $SID! Deleting..."
        Remove-Item -Path $targetRegKey -Force
    }else {
        Write-host "Juniper Setup Client Entry was not found for $SID"
    }
}

#removing pulse secure installer service
$ProductId = (Get-WmiObject -Class Win32_Product | where {$_.Name -eq "Pulse Secure Installer Service"}).IdentifyingNumber
msiexec /x "$ProductId" /q
Start-Sleep -s 3
$ProductId2 = (Get-WmiObject -Class Win32_Product | where {$_.Name -eq "Pulse Secure"}).IdentifyingNumber
msiexec /x "$ProductId2" /q
Start-Sleep -s 3
$ProductId3 = (Get-WmiObject -Class Win32_Product | where {$_.Name -eq "Pulse Secure Installer Service 8.1"}).IdentifyingNumber
msiexec /x "$ProductId3" /q

#Removing pulse secure app
Write-host "Uninstalling pulse secure..."
if (Test-Path $PulseUninstall) {
    &$PulseUninstall /silent=1
}
Start-Sleep -s 3
if (Test-Path $PulseUninstall2) {
    &$PulseUninstall2 /silent=1
}
Start-Sleep -s 3
Write-host "Removing pulse secure app leftover files..."
Remove-Item -Path "$env:SystemDrive\Program Files (x86)\Juniper Networks" -Recurse -Force
Remove-Item -Path "$env:SystemDrive\Program Files (x86)\Pulse Secure" -Recurse -Force

#Removing active x controls
Write-host "Uninstalling pulse secure active x..."
if (Test-Path $PulseSCCUninstall) {
    &$PulseSCCUninstall /S 
}
Start-Sleep -s 3
if (Test-Path $PulseSCCUninstall64) {
    &$PulseSCCUninstall64 /S 
}
Start-Sleep -s 3
Write-host "Removing active x leftover files..."
Remove-Item -Path "$env:SystemDrive\Windows\Downloaded Program Files\JuniperSetup.inf" -Force
Remove-Item -Path "$env:SystemDrive\Windows\Downloaded Program Files\JuniperSetup.ocx" -Force

#Cleaning registry
Write-Host "Cleaning up registry..."
Remove-Item -Path "HKLM:\SOFTWARE\Juniper Networks" -recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Juniper Networks" -recurse -Force