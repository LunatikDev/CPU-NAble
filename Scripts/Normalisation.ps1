<#
.SYNOPSIS
    Launcher pour l'Installation du script de normalisation
.DESCRIPTION
    Launcher pour l'Installation du script de normalisation
.NOTES
    Fichier    : Normalisation.ps1
    Author     : Jerome Couette - j.couette@cpu.ca
    Version    : 1.0
#>
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
#-----------------------------------------------------------[Functions]------------------------------------------------------------
Function Global:Install-ChocolateyW78 {
  Set-ExecutionPolicy Bypass -Scope Process -Force;
  #----------------------------------------------------------[SubFunctions]----------------------------------------------------------
  function Fix-PowerShellOutputRedirectionBug {
    $poshMajorVerion = $PSVersionTable.PSVersion.Major

    if ($poshMajorVerion -lt 4) {
      try{
        # http://www.leeholmes.com/blog/2008/07/30/workaround-the-os-handles-position-is-not-what-filestream-expected/ plus comments
        $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetField"
        $objectRef = $host.GetType().GetField("externalHostRef", $bindingFlags).GetValue($host)
        $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetProperty"
        $consoleHost = $objectRef.GetType().GetProperty("Value", $bindingFlags).GetValue($objectRef, @())
        [void] $consoleHost.GetType().GetProperty("IsStandardOutputRedirected", $bindingFlags).GetValue($consoleHost, @())
        $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetField"
        $field = $consoleHost.GetType().GetField("standardOutputWriter", $bindingFlags)
        $field.SetValue($consoleHost, [Console]::Out)
        [void] $consoleHost.GetType().GetProperty("IsStandardErrorRedirected", $bindingFlags).GetValue($consoleHost, @())
        $field2 = $consoleHost.GetType().GetField("standardErrorWriter", $bindingFlags)
        $field2.SetValue($consoleHost, [Console]::Error)
      } catch {
        Write-Output 'Unable to apply redirection fix.'
      }
    }
  }
  function Get-Downloader {
    param (
      [string]$url
    )
    $downloader = new-object System.Net.WebClient

    $defaultCreds = [System.Net.CredentialCache]::DefaultCredentials
    if (Test-Path -Path variable:repoCreds) {
      Write-Debug "Using provided repository authentication credentials."
      $downloader.Credentials = $repoCreds
    } elseif ($defaultCreds -ne $null) {
      Write-Debug "Using default repository authentication credentials."
      $downloader.Credentials = $defaultCreds
    }

    $ignoreProxy = $env:chocolateyIgnoreProxy
    if ($ignoreProxy -ne $null -and $ignoreProxy -eq 'true') {
      Write-Debug 'Explicitly bypassing proxy due to user environment variable.'
      $downloader.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
    } else {
      # check if a proxy is required
      $explicitProxy = $env:chocolateyProxyLocation
      $explicitProxyUser = $env:chocolateyProxyUser
      $explicitProxyPassword = $env:chocolateyProxyPassword
      if ($explicitProxy -ne $null -and $explicitProxy -ne '') {
        # explicit proxy
        $proxy = New-Object System.Net.WebProxy($explicitProxy, $true)
        if ($explicitProxyPassword -ne $null -and $explicitProxyPassword -ne '') {
          $passwd = ConvertTo-SecureString $explicitProxyPassword -AsPlainText -Force
          $proxy.Credentials = New-Object System.Management.Automation.PSCredential ($explicitProxyUser, $passwd)
        }

        Write-Debug "Using explicit proxy server '$explicitProxy'."
        $downloader.Proxy = $proxy

      } elseif (!$downloader.Proxy.IsBypassed($url)) {
        # system proxy (pass through)
        $creds = $defaultCreds
        if ($creds -eq $null) {
          Write-Debug 'Default credentials were null. Attempting backup method'
          $cred = get-credential
          $creds = $cred.GetNetworkCredential();
        }

        $proxyaddress = $downloader.Proxy.GetProxy($url).Authority
        Write-Debug "Using system proxy server '$proxyaddress'."
        $proxy = New-Object System.Net.WebProxy($proxyaddress)
        $proxy.Credentials = $creds
        $downloader.Proxy = $proxy
      }
    }

    return $downloader
  }
  function Download-File {
    param (
      [string]$url,
      [string]$file
    )
    $downloader = Get-Downloader $url
    $downloader.DownloadFile($url, $file)
  }
  function Download-Package {
    param (
      [string]$packageODataSearchUrl,
      [string]$file
    )
    $downloader = Get-Downloader $packageODataSearchUrl

    Write-Output "Querying latest package from $packageODataSearchUrl"
    [xml]$pkg = $downloader.DownloadString($packageODataSearchUrl)
    $packageDownloadUrl = $pkg.feed.entry.content.src

    Write-Output "Downloading $packageDownloadUrl to $file"
    $downloader.DownloadFile($packageDownloadUrl, $file)
  }
  function Install-ChocolateyFromPackage {
    param (
      [string]$chocolateyPackageFilePath = ''
    )

    if ($chocolateyPackageFilePath -eq $null -or $chocolateyPackageFilePath -eq '') {
      throw "You must specify a local package to run the local install."
    }

    if (!(Test-Path($chocolateyPackageFilePath))) {
      throw "No file exists at $chocolateyPackageFilePath"
    }

    $chocTempDir = Join-Path $env:TEMP "chocolatey"
    $tempDir = Join-Path $chocTempDir "chocInstall"
    if (![System.IO.Directory]::Exists($tempDir)) {[System.IO.Directory]::CreateDirectory($tempDir)}
    $file = Join-Path $tempDir "chocolatey.zip"
    Copy-Item $chocolateyPackageFilePath $file -Force

    # unzip the package
    Write-Output "Extracting $file to $tempDir..."
    if ($unzipMethod -eq '7zip') {
      $7zaExe = Join-Path $tempDir '7za.exe'
      if (-Not (Test-Path ($7zaExe))) {
        Write-Output 'Downloading 7-Zip commandline tool prior to extraction.'
        # download 7zip
        Download-File $7zipUrl "$7zaExe"
      }

      $params = "x -o`"$tempDir`" -bd -y `"$file`""
      # use more robust Process as compared to Start-Process -Wait (which doesn't
      # wait for the process to finish in PowerShell v3)
      $process = New-Object System.Diagnostics.Process
      $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo($7zaExe, $params)
      $process.StartInfo.RedirectStandardOutput = $true
      $process.StartInfo.UseShellExecute = $false
      $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
      $process.Start() | Out-Null
      $process.BeginOutputReadLine()
      $process.WaitForExit()
      $exitCode = $process.ExitCode
      $process.Dispose()

      $errorMessage = "Unable to unzip package using 7zip. Perhaps try setting `$env:chocolateyUseWindowsCompression = 'true' and call install again. Error:"
      switch ($exitCode) {
        0 { break }
        1 { throw "$errorMessage Some files could not be extracted" }
        2 { throw "$errorMessage 7-Zip encountered a fatal error while extracting the files" }
        7 { throw "$errorMessage 7-Zip command line error" }
        8 { throw "$errorMessage 7-Zip out of memory" }
        255 { throw "$errorMessage Extraction cancelled by the user" }
        default { throw "$errorMessage 7-Zip signalled an unknown error (code $exitCode)" }
      }
    } else {
      if ($PSVersionTable.PSVersion.Major -lt 5) {
        try {
          $shellApplication = new-object -com shell.application
          $zipPackage = $shellApplication.NameSpace($file)
          $destinationFolder = $shellApplication.NameSpace($tempDir)
          $destinationFolder.CopyHere($zipPackage.Items(),0x10)
        } catch {
          throw "Unable to unzip package using built-in compression. Set `$env:chocolateyUseWindowsCompression = 'false' and call install again to use 7zip to unzip. Error: `n $_"
        }
      } else {
        Expand-Archive -Path "$file" -DestinationPath "$tempDir" -Force
      }
    }

    # Call Chocolatey install
    Write-Output 'Installing chocolatey on this machine'
    $toolsFolder = Join-Path $tempDir "tools"
    $chocInstallPS1 = Join-Path $toolsFolder "chocolateyInstall.ps1"

    & $chocInstallPS1

    Write-Output 'Ensuring chocolatey commands are on the path'
    $chocInstallVariableName = 'ChocolateyInstall'
    $chocoPath = [Environment]::GetEnvironmentVariable($chocInstallVariableName)
    if ($chocoPath -eq $null -or $chocoPath -eq '') {
      $chocoPath = 'C:\ProgramData\Chocolatey'
    }

    $chocoExePath = Join-Path $chocoPath 'bin'

    if ($($env:Path).ToLower().Contains($($chocoExePath).ToLower()) -eq $false) {
      $env:Path = [Environment]::GetEnvironmentVariable('Path',[System.EnvironmentVariableTarget]::Machine);
    }

    Write-Output 'Ensuring chocolatey.nupkg is in the lib folder'
    $chocoPkgDir = Join-Path $chocoPath 'lib\chocolatey'
    $nupkg = Join-Path $chocoPkgDir 'chocolatey.nupkg'
    if (!(Test-Path $nupkg)) {
      Write-Output 'Copying chocolatey.nupkg is in the lib folder'
      if (![System.IO.Directory]::Exists($chocoPkgDir)) { [System.IO.Directory]::CreateDirectory($chocoPkgDir); }
      Copy-Item "$file" "$nupkg" -Force -ErrorAction SilentlyContinue
    }
  }
  #----------------------------------------------------------[Declarations]----------------------------------------------------------
  $repoUrl           = 'http://chocolatey.cpu.qc.ca/nuget/CPU-CHOCO/'
  $repoUsername      = 'DefaultFeedUser'
  $repoPassword      = 'RC8QCsIKUe'
  $unzipMethod       = 'builtin'
  #-----------------------------------------------------------[Execution]------------------------------------------------------------
  # If the repository requires authentication, create the Credential object
  if ((-not [string]::IsNullOrEmpty($repoUsername)) -and (-not [string]::IsNullOrEmpty($repoPassword))) {
      $securePassword = ConvertTo-SecureString $repoPassword -AsPlainText -Force
      $repoCreds = New-Object System.Management.Automation.PSCredential ($repoUsername, $securePassword)
  }

  $searchUrl = ($repoUrl.Trim('/'), 'Packages()?$filter=(Id%20eq%20%27chocolatey%27)%20and%20IsLatestVersion') -join '/'

  New-Item -ItemType Directory -Path "$env:SystemDrive\" -Name "choco-install"
  $localChocolateyPackageFilePath = "$env:SystemDrive\choco-install\chocolatey.nupkg"
  $ChocoInstallPath = "$($env:SystemDrive)\ProgramData\Chocolatey\bin"
  $env:ChocolateyInstall = "$($env:SystemDrive)\ProgramData\Chocolatey"
  $env:Path += ";$ChocoInstallPath"
  $DebugPreference = 'Continue';

  Fix-PowerShellOutputRedirectionBug

  try {
    [System.Net.ServicePointManager]::SecurityProtocol = 3072 -bor 768 -bor 192 -bor 48
  } catch {
    Write-Output 'Unable to set PowerShell to use TLS 1.2 and TLS 1.1 due to old .NET Framework installed. If you see underlying connection closed or trust errors, you may need to upgrade to .NET Framework 4.5+ and PowerShell v3+.'
  }

    # download the package to the local path
    if (!(Test-Path $localChocolateyPackageFilePath)) {
      Download-Package $searchUrl $localChocolateyPackageFilePath
    }

    # Install Chocolatey
    Install-ChocolateyFromPackage $localChocolateyPackageFilePath

    #remove install files
    Remove-Item -Path "$env:SystemDrive\choco-install" -Recurse -Force
}
Function Global:Install-ChocolateyW10 {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  #----------------------------------------------------------[SubFunctions]----------------------------------------------------------
  function Unzip {
      param([string]$zipfile, [string]$outpath)
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
  }
  #----------------------------------------------------------[Declarations]----------------------------------------------------------
  $repoUrl           = 'https://chocolatey.cpu.qc.ca/nuget/CPU-CHOCO/'
  $repoUsername      = 'DefaultFeedUser'
  $repoPassword      = 'RC8QCsIKUe'
  $searchUrl         = $repoUrl + "packages?"
  $ChocoSS           = new-object System.Security.SecureString
  $ChocoChars        = $repoPassword.toCharArray()
  #-----------------------------------------------------------[Execution]------------------------------------------------------------
  $doc = New-Object System.Xml.XmlDocument
  $doc.Load("$searchUrl")
  $packages = @()
  Foreach ($item in $doc.feed.entry){
    $ID           = $item.Title."#text"
    $Title        = $item.properties.Title
    $Description  = $item.properties.Description
    $Version 			= $item.properties.Version
    $obj          = New-Object PSObject
    Add-Member -InputObject $obj -MemberType NoteProperty -Name ID -Value ($item.Title."#text")
    Add-Member -InputObject $obj -MemberType NoteProperty -Name Title -Value ($item.properties.Title)
    Add-Member -InputObject $obj -MemberType NoteProperty -Name Description -Value ($item.properties.Description)
    Add-Member -InputObject $obj -MemberType NoteProperty -Name Version -Value ($item.properties.Version)
    $packages 	 += $obj
  }
  $chocoPkgInfo = ($packages | where {$_.ID -eq "chocolatey"}).Version | Sort-Object -Descending
  $chocoPkgCount = $chocoPkgInfo.Count
  If ($chocoPkgCount -lt 2){
    $chocoPkgVer = (($packages | where {$_.ID -eq "chocolatey"}).Version | Sort-Object -Descending)
  }else{
    $chocoPkgVer = (($packages | where {$_.ID -eq "chocolatey"}).Version | Sort-Object -Descending)[0]
  }
  New-Item -ItemType Directory -Path "$env:SystemDrive\" -Name "choco-install"
  foreach ($char in $ChocoChars) {$ChocoSS.AppendChar($char)}
  $ChocoCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $repoUsername, $ChocoSS
  $URI = $repoUrl + "package/chocolatey/" + $chocoPkgVer
  Invoke-WebRequest -Uri $URI -OutFile "$env:SystemDrive\choco-install\chocolatey.nupkg" -Credential $ChocoCreds
  Unzip "$env:SystemDrive\choco-install\chocolatey.nupkg" "$env:SystemDrive\choco-install\chocolatey"
  invoke-expression -Command "$env:SystemDrive\choco-install\chocolatey\tools\chocolateyinstall.ps1"
  Remove-Item -Path "$env:SystemDrive\choco-install" -Recurse -Force
}
Function Global:Configure-Chocolatey ($chocoBinPath) {
  &$chocoBinPath source add -n=CPUChocoRep -s "https://chocolatey.cpu.qc.ca/nuget/CPU-CHOCO/" -u=DefaultFeedUser -p=RC8QCsIKUe --priority=1
  &$chocoBinPath source add -n=CPUChocoRepLocal -s "http://172.22.2.85/nuget/CPU-CHOCO/" -u=DefaultFeedUser -p=RC8QCsIKUe --priority=2
}
#----------------------------------------------------------[Declarations]----------------------------------------------------------
$PsModulePath1       = "$env:SystemDrive\Program Files\WindowsPowerShell\Modules"
$PsModulePath2       = "$env:SystemDrive\Program Files (x86)\WindowsPowerShell\Modules"
$Global:chocoBinPath = "$env:SystemDrive\ProgramData\chocolatey\bin\choco.exe"
$ChocoInstallPath    = "$($env:SystemDrive)\ProgramData\Chocolatey\bin"
$winbuild            = (Get-WmiObject -Class Win32_OperatingSystem).Version #verification build version windows
$dsclogs             = "$env:SystemDrive\dsc-logs"
#-----------------------------------------------------------[Execution]------------------------------------------------------------
#create folder dsc-logs
if(!(Test-path $dsclogs)){mkdir $dsclogs}
#install chocolatey
if($winbuild -like "*10*"){
  Install-ChocolateyW10
}else{
  Install-ChocolateyW78
}
start-sleep -s 5
#configure sources
Configure-Chocolatey($chocoBinPath)
Start-Process -FilePath "$env:SystemDrive\normalisation\update-sources.bat" -Verb Runas -WindowStyle Hidden

#install Normalisation
&$chocoBinPath install normalisation-montage --source "https://chocolatey.cpu.qc.ca/nuget/CPU-DEVOPS/" -y

#wait for the normalisation to finish
$Global:NormStatus = "0"
while($Global:NormStatus -ne "3"){
    $Global:NormStatus = Get-Content "$env:systemdrive\ProgramData\Normalisation\status.log"
    Start-Sleep -Seconds 10
}
#move logs to dsc-logs Folder
Move-Item -Path "$env:systemdrive\normalisation-steps.log" -Destination "$env:systemdrive\ProgramData\Normalisation"


