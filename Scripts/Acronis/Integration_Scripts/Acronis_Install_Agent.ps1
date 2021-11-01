# Install Cyber Protect Agent

# Script input parameters
# $CloudUrl             - Acronis cloud URL (required)
# $RegistrationToken    - Acronis registration token (required)
# $AgentAccountLogin    - Domain Controller username (optional)
# $AgentAccountPassword - Domain Controller password (optional)
# $VendorName           - name of the vendor

$ErrorActionPreference = "Stop"

$acronisRegistryPath = "HKLM:\SOFTWARE\Acronis\BackupAndRecovery\Settings\MachineManager"

# Register WebClient with 1 hour timeout
$timeoutWebClientCode = @"
public class TimeoutWebClient : System.Net.WebClient
{
    protected override System.Net.WebRequest GetWebRequest(System.Uri address)
    {
        System.Net.WebRequest request = base.GetWebRequest(address);
        if (request != null)
        {
            request.Timeout = System.Convert.ToInt32(System.TimeSpan.FromHours(1).TotalMilliseconds);
        }
        return request;
    }
}
"@;
Add-Type -TypeDefinition $timeoutWebclientCode -Language CSharp -WarningAction SilentlyContinue

function Get-AgentInstallerUrl {
    param ([string] $cloudUrl)
    
    $response = Invoke-RestMethod -Uri "${cloudUrl}/bc/api/ams/links/list" -Method Get
    foreach ($agent in $response.agents) {
        if ($agent.system -eq "exe" -and $agent.architecture -eq (32, 64)[[System.Environment]::Is64BitOperatingSystem]) {
            return $agent.url
        }
    }
}

function Get-AccessToken {
    param ([string] $cloudUrl, [string] $registrationToken)
    
    $headers = @{ "Content-Type" = "application/x-www-form-urlencoded" }
    $body = @{
        "grant_type" = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        "assertion"  = $registrationToken
    }
    $response = Invoke-RestMethod -Uri "${cloudUrl}/bc/idp/token" `
        -Method Post `
        -Headers $headers `
        -Body $body
    
    return $response.access_token
}

function Invoke-Plan {
    param ([string] $cloudUrl, [string] $accessToken, [string] $resourceId)
    
    $headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $accessToken"
    }
    $body = @{
        "context" = @{
            "items" = @($resourceId)
        }
    } | ConvertTo-Json
    Invoke-RestMethod -Uri "${cloudUrl}/api/policy_management/v4/applications" `
        -Method Post `
        -Headers $headers `
        -Body $body
}

$ScriptName = "InstallAgent"
$ScriptVersion = "1.0.0.0"
$ScriptLabel = "windows"
$VendorVersion = "1.0.0.0"

function Send-Statistics
{
    param (
        [string]$cloudUrl, 
        [string]$accessToken, 
        [string]$vendor = $VendorName,
        [string]$vendorVersion = $VendorVersion,
        [string]$scriptName = $ScriptName,
        [string]$scriptVersion = $ScriptVersion,
        [string]$eventCategory = $ScriptName,
        [string]$eventAction,
        [string]$eventLabel = $ScriptLabel,
        [int]$eventValue = 0
        )

    $acronisRegistryPath = "HKLM:\SOFTWARE\Acronis\BackupAndRecovery\Settings\MachineManager"
    $resourceId = Get-ItemProperty -Path $acronisRegistryPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InstanceID
    $agentId = Get-ItemProperty -Path $acronisRegistryPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MMSCurrentMachineID

    $applicationIds = @{
        "N-able N-central" = "702880c0-714f-4a95-aaf7-06e7f1da7d09" # N-able N-central
        "N-able RMM" = "4497f3ff-dc79-4189-9ad9-964b83f71b9b" # N-able RMM
        "Datto RMM" = "85f40c81-1c86-4fbd-8fea-a8d14cb548cc" # Datto RMM
    }

    $headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $accessToken"
    }

    $body = @{
        "application_id" = $applicationIds[$vendor]
        "workload" = @{
            "agent_id" = $agentId.ToLower()
            "resource_id" = $resourceId.ToLower()
            "hostname" = [Environment]::MachineName
        }
        "module" = @{
            "name" = $scriptName
            "version" = $scriptVersion
        }
        "vendor_system" = @{
            "name" = $vendor
            "version" = $vendorVersion
        }

        "events" = @(
                @{
                    "category" = $eventCategory
                    "action" = $eventAction
                    "label" = $eventLabel
                    "value" = $eventValue
                }
            )
    } | ConvertTo-Json
  
    try
    {
        $result = Invoke-WebRequest -Uri "${cloudUrl}/api/integration_management/v2/status" -UseBasicParsing `
            -Method Post `
            -Headers $headers `
            -Body $body
    }catch{
        $result = $_.Exception.Response
    }

    return $result
}

Write-Host "Resolving distributive on $CloudUrl"

$agentUrl = Get-AgentInstallerUrl $CloudUrl

Write-Host "Download distributive: $agentUrl"

# Resolve agent installer name and download path
$installerRequest = [System.Net.WebRequest]::Create($agentUrl)
$installerRequest.AllowAutoRedirect = $false
$installerRequest.Method = "HEAD"
$installerName = [System.IO.Path]::GetFileName($installerRequest.GetResponse().Headers["Location"])

$installerDir = Join-Path -Path $env:TMP -ChildPath "Acronis"
New-Item -ItemType Directory -Path $installerDir -Force | Out-Null
Set-Location -Path $installerDir

$installerPath = Join-Path -Path $installerDir -ChildPath $installerName
Remove-Item -Path $installerPath -ErrorAction SilentlyContinue

Write-Host "  to: $installerPath"

# Download agent installer
$webClient = New-Object TimeoutWebClient
try {
    $webClient.DownloadFile($agentUrl, $installerPath)
}
finally {
    $webClient.Dispose()
}

# Install agent
$logDir = Join-Path -Path $installerDir -ChildPath "Cyber_Protect_Agent_logs"
$reportFile = Join-Path -Path $installerDir -ChildPath "Cyber_Protect_Agent_report.txt"
$processStartArgs = @(
    "--add-components=commandLine,agentForWindows,trayMonitor",
    "--reg-address=$cloudUrl",
    "--registration=by-token",
    "--reg-token=$registrationToken",
    "--log-dir=$logDir",
    "--report-file=$reportFile",
    "--quiet"
)

if ($AgentAccountLogin -and $AgentAccountLogin -ne "-") {
    $processStartArgs += @(
        "--agent-account-login=$AgentAccountLogin",
        "--agent-account-password=$AgentAccountPassword")
}

Write-Host "Install agent: $processStartArgs"

$processStartInfo = New-Object System.Diagnostics.ProcessStartInfo -Property @{
    WorkingDirectory       = $installerDir
    FileName               = $installerPath
    RedirectStandardError  = $true
    RedirectStandardOutput = $true
    UseShellExecute        = $false
    CreateNoWindow         = $true
    Arguments              = $processStartArgs
}
$process = New-Object System.Diagnostics.Process -Property @{
    StartInfo = $processStartInfo
}
$process.Start() | Out-Null
$process.WaitForExit()

Remove-Item -Path $installerPath -ErrorAction SilentlyContinue

if ($process.ExitCode -ne 0) {
    Write-Error "Failed to install Cyber Protect Agent" -ErrorAction:Continue
    Write-Error "Exit code: $($process.ExitCode)" -ErrorAction:Continue
    Write-Error "Report: $reportFile" -ErrorAction:Continue
    Write-Error "Logs: $logDir" -ErrorAction:Continue
    $stdout = $process.StandardOutput.ReadToEnd()
    Write-Error "Stdout: $stdout" -ErrorAction:Continue
    $stderr = $process.StandardError.ReadToEnd()
    Write-Error "Stderr: $stderr" -ErrorAction:Stop  
    exit 1
}

Write-Host "Get access token..."

# Exchange registration token to access token and try to apply protection plan
$accessToken = Get-AccessToken $CloudUrl $RegistrationToken
if ($accessToken) {
    $resourceId = Get-ItemProperty -Path $acronisRegistryPath | Select-Object -ExpandProperty InstanceID
    try
    {
        Invoke-Plan $CloudUrl $accessToken $resourceId
    }
    catch
    {
        Write-Host "No protection plan can be assigned using this registration token"
    }

    Send-Statistics -cloudUrl $cloudUrl -accessToken $accessToken -eventAction "installed"
}

Write-Output "Cyber Protect Agent was successfully installed"