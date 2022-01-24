$ServiceState = (get-service|where{$_.DisplayName -like "Trend Micro Security Agent"}).status
switch ($ServiceState) {
    "Running" { $Toggle = $true }
    "Stopped" { $Toggle = $false }
}
Write-Host "Is Trend Micro Security Agent service running? $Toggle"