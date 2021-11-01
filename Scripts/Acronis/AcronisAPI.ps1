function Get-AcronisToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false,Position = 0)]
        [string]$baseUrl = "https://us-cloud.acronis.com",
        [Parameter(Mandatory = $false,Position = 1)]
        [string]$client = "Powershell",
        [Parameter(Mandatory = $false,Position = 2)]
        [string]$clientId = "a65a21f9-24ed-4527-b024-68f751175526",
        [Parameter(Mandatory = $false,Position = 3)]
        [string]$clientSecret = "f67a355f0c0b47f38bd19ec709048007"
    )

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
    $headers.Add("User-Agent", "N-Able/Acronis Cyber Platform Connector")

    $token = (Invoke-RestMethod -Method Post -Uri "${baseUrl}/api/2/idp/token" -Headers $headers -Body $postParams).access_token
    return $token
}

function Get-AcronisHeader {
    Param(
        [Parameter(Mandatory = $true,Position = 0)]
        [string]$token
    )
    $bearerToken = "Bearer $token"
    $headers = @{ "Authorization" = $bearerToken }
    $headers.Add("Content-Type", "application/json")
    $headers.Add("User-Agent", "N-Able/Acronis Cyber Platform Connector")
    return $headers
}

function Get-AcronisTasks {
    param (
        $headers
    )
    $weekAgo = (Get-Date).ToUniversalTime().AddDays(-1).ToString("yyyy-MM-ddT00:00:00Z")
    # Get a list of tasks, the same as
    $allLastWeekTasks = Invoke-RestMethod -Uri "https://us-cloud.acronis.com/api/task_manager/v2/tasks?completedAt=gt(${weekAgo})" -Headers $headers
    return $allLastWeekTasks
}

function Get-AllAcronisAgents {
    param (
        $headers
    )
    $agents = Invoke-RestMethod -Uri "https://us-cloud.acronis.com/api/agent_manager/v2/agents" -Headers $headers
    return $agents.items
}

function Get-AcronisAgentId {
    param (
        $computername,
        $headers
    )
    $Agents = Get-AcronisAgents -headers $headers
    $AgentId = ($Agents | where {$_.hostname -eq $computername}).id
    return $AgentId
}

#create token for Auth with API
$token = Get-AcronisToken
$headers = Get-AcronisHeader -token $token

#get the agent unique ID
$agentId = Get-AcronisAgentId -computername "GMF03CMBEA00022" -headers $headers
#$agentId = Get-AcronisAgentId -computername $env:computername -headers $headers

#get backup task results
$tasks = Get-AcronisTasks -headers $headers

#find the task executed by AgentId
$backupResults = ($tasks.items | where {$_.executor.id -eq $agentId})

#build powershell object from backup result
$report = new-object -TypeName psobject
$report | Add-Member -NotePropertyName MachineName -NotePropertyValue ()
$report | Add-Member -NotePropertyName Executor -NotePropertyValue ($backupResults.executor.id)
$report | Add-Member -NotePropertyName PolicyName -NotePropertyValue ($backupResults.policy.name)
$report | Add-Member -NotePropertyName State -NotePropertyValue ($backupResults.state)
$report | Add-Member -NotePropertyName StartedAt -NotePropertyValue ($backupResults.startedAt)
$report | Add-Member -NotePropertyName CompletedAt -NotePropertyValue ($backupResults.completedAt)
$report | Add-Member -NotePropertyName Result -NotePropertyValue ($backupResults.result.code)
$report