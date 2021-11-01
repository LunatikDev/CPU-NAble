$acrocmd = "C:\Program Files\BackupClient\CommandLineTool\acrocmd.exe"
&$acrocmd list tasks --output=formated

###
Invoke-RestMethod  -Uri "https://us-cloud.acronis.com/api/2/clients" -Headers $headers
Invoke-RestMethod  -Uri "https://us-cloud.acronis.com/api/2/users/me" -Headers $headers
###create token
$baseUrl = "https://us-cloud.acronis.com"

$client = "Powershell"
$clientId = "a65a21f9-24ed-4527-b024-68f751175526"
$clientSecret = "f67a355f0c0b47f38bd19ec709048007"
# Manually construct Basic Authentication Header
$pair = "${clientId}:${clientSecret}"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"
$headers = @{ "Authorization" = $basicAuthValue }

# Use param to tell type of credentials we request
$postParams = @{ grant_type = "client_credentials" }

# Add the request content type to the headers
$headers.Add("Content-Type", "application/x-www-form-urlencoded")
$headers.Add("User-Agent", "ACP 1.0/Acronis Cyber Platform PowerShell Examples")

$token = (Invoke-RestMethod -Method Post -Uri "${baseUrl}/api/2/idp/token" -Headers $headers -Body $postParams).access_token



### get_all_agents_info
$bearerToken = "Bearer $token"
$headers = @{ "Authorization" = $bearerToken }

# The request contains body with JSON
$headers.Add("Content-Type", "application/json")
$headers.Add("User-Agent", "ACP 1.0/Acronis Cyber Platform PowerShell Examples")

Invoke-RestMethod -Uri "https://us-cloud.acronis.com/api/agent_manager/v2/agents" -Headers $headers

### Get a list of all Clients ID
$bearerToken = "Bearer $token"
$headers = @{ "Authorization" = $bearerToken }
$tenantId = 1876001
$json = @"
{
    "type": "api_client",
    "tenant_id": "$tenantId",
    "token_endpoint_auth_method": "client_secret_basic",
    "data": {
        "client_name": "PowerShell.App"
    }
}
"@

$apiClientInfo = Invoke-RestMethod  -Uri "https://us-cloud.acronis.com/api/2/clients/${clientId}" -Headers $headers

Invoke-RestMethod -Uri "https://us-cloud.acronis.com/api/2/users/me" -Headers $headers

# The request contains body with JSON
$headers.Add("Content-Type", "application/json")
$headers.Add("User-Agent", "ACP 1.0/Acronis Cyber Platform PowerShell Examples")

### get simple report for customer
$bearerToken = "Bearer $token"
$headers = @{ "Authorization" = $bearerToken }
$headers.Add("Content-Type", "application/json")
$headers.Add("User-Agent", "ACP 1.0/Acronis Cyber Platform PowerShell Examples")

$tenantId = "a65a21f9-24ed-4527-b024-68f751175526"

# Body JSON to create a report
$json = @"
{
    "parameters": {
        "kind": "usage_current",
        "tenant_id": "08cc9293-5056-4288-b282-46a352ffb63f",
        "level": "accounts",
        "formats": [
            "csv_v2_0"
        ]
    },
    "schedule": {
        "type": "once"
    },
    "result_action": "save"
}
"@

#generate the report 
Invoke-RestMethod -Method Post -Uri "https://us-cloud.acronis.com/api/2/reports" -Headers $headers -Body $json
Invoke-RestMethod -Uri "https://us-cloud.acronis.com/api/2/reports/d7af06b8-181f-43b1-bd66-bde300da4252/stored" -Headers $headers

Invoke-WebRequest  -Uri "https://us-cloud.acronis.com/api/2/reports/d7af06b8-181f-43b1-bd66-bde300da4252/stored/b5776a12-32ea-4a08-9924-554d29bd0a13" -Headers $headers -OutFile "C:\temp\report.csv"
### get tasks

#**************************************************************************************************************
# Copyright © 2019-2020 Acronis International GmbH. This source code is distributed under MIT software license.
#**************************************************************************************************************

# includes common functions, base configuration and basis API checks
. ".\0-init.ps1"

# The size of page for pagination
$pageSize = 10

# The first call with limiting output limit=${pageSize}, the same as
# $page = Invoke-RestMethod -Uri "${baseUrl}api/task_manager/v2/tasks?limit=${pageSize}" -Headers $headers
#$page = Acronis-Get -Uri "https://us-cloud.acronis.com/api/task_manager/v2/tasks?limit=${pageSize}"
$page = Invoke-RestMethod -Uri "https://us-cloud.acronis.com/api/task_manager/v2/tasks?limit=10" -Headers $headers -Body $Body
$tasks = Invoke-RestMethod -Uri "https://us-cloud.acronis.com/api/task_manager/v2/tasks" -Headers $headers
# The cursor to go to the next page
$after = $page.paging.cursors.after

# Pages counter
$pageNumber = [System.Int32]1

Write-Output "The page number ${pageNumber}."

# Loop to move through all pages
while ($after) {

	$pagingParams = @{limit = $pageSize; after = $after}

	# The call for the next page 	limit=${pageSize}&after=${after}, the same as
	# $page = Invoke-RestMethod -Uri "${baseUrl}api/task_manager/v2/tasks?limit=${pageSize}&after=${after}" -Headers $headers
	$page = Acronis-Get -Uri "api/task_manager/v2/tasks" -Body $pagingParams
	# The cursor to go to the next page
	$after = $page.paging.cursors.after

	$pageNumber = $pageNumber+1

	Write-Output "The page number ${pageNumber}."

  }

Write-Output "The tasks were paged to the end."


### get all activities
$daysago= (Get-Date).ToUniversalTime().AddDays(-7).ToString("yyyy-MM-ddT00:00:00Z")
$activities = Invoke-RestMethod -Uri "https://us-cloud.acronis.com/api/task_manager/v2/activities?completedAt=gt(${daysago})" -Headers $headers

### get all tasks 
$tasks = Invoke-RestMethod -Uri "https://us-cloud.acronis.com/api/task_manager/v2/tasks" -Headers $headers

function Get-BackupStatus {
    param (
        $ComputerName
    )
    ($activities.items.context | where {$_.MachineName -eq "GMF06CART00011.clinique1851.reg06.gmf.qc.ca"}).CommandID
    

    8F01AC13-F59E-4851-9204-DE1FD77E36B4
D332948D-A7A9-4E07-B76C-253DCF6E17FB
45D64182-5DF4-4AE0-9D42-55E1C3DB942B
}


# Body JSON to create a report
$json = @"
{
    "parameters": {
        "kind": "usage_current",
        "tenant_id": "212222",
        "level": "accounts",
        "formats": [
            "csv_v2_0"
        ]
    },
    "schedule": {
        "type": "once"
    },
    "result_action": "save"
}
"@

Invoke-RestMethod -Method Post -Uri "https://us-cloud.acronis.com/api/2/reports" -Headers $headers -Body $json

$allLastWeekAlerts = Invoke-RestMethod -Uri "https://us-cloud.acronis.com/api/alert_manager/v1/alerts?updated_at=gt(${weekAgo})&order=desc(created_at)" -Headers $headers

#types d'alertes

function Get-Alerts {
    param ([string] $aakoreProxyLocation, [string] $accessToken, [string] $resourceName, $aakoreSession)
    
    $getAlertsUri = "https://us-cloud.acronis.com/api/alert_manager/v1/api/alert_manager/v1/alerts?query=${resourceName}"
    $previousScanTime = Get-LastScanTime
    if ($previousScanTime) {
        $getAlertsUri += "&created_at=gt($previousScanTime)"
    }
    
    $headers = @{ "Authorization" = "Bearer $accessToken" }
    
    $response = Invoke-RestMethod -Uri $getAlertsUri `
        -Method Get `
        -Headers $headers `
        -WebSession $aakoreSession
    $response.items
    
    $after = $response.paging.cursors.after
    while ($after) {
        $response = Invoke-RestMethod -Uri "${aakoreProxyLocation}/api/alert_manager/v1/alerts?after=${after}" `
            -Method Get `
            -Headers $headers `
            -WebSession $aakoreSession
        $response.items
        $after = $response.paging.cursors.after
    }
}




$IDs = $allLastWeekAlerts.items.tenant.id
$allagents = @()
foreach ($ID in $IDs) {
    $allagents += ($agents | where {$_.tenant.id -eq "$ID"})
}
$allagents