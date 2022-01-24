$ServiceState = (get-service|where{$_.DisplayName -like "Trend Micro Security Agent RealTime Scan"}).status
switch ($ServiceState) {
    "Running" {
        $Toggle = $true
    }
    "Stopped" {
        $Toggle = $false
    }
}
Write-Host "Is Trend Micro Security Agent RealTime Scan service running? $Toggle"
