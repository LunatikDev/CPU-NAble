$ServiceState = (get-service | where{$_.DisplayName -like "Trend Micro Security Agent Listener"}).status
switch ($ServiceState) {
    "Running" { $Toggle = $true }
    "Stopped" { $Toggle = $false }
}
Write-Host "Is Trend Micro Security Agent Listener service running? $Toggle"