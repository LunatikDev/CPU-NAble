$Global:SQL = @()
foreach ($Customer in $CustomerList) {
    $InsertCmd = "(" + $Customer.customerid + ",'" + $Customer.customername +"'),"
    $Global:SQL += $InsertCmd
}
$Global:SQL | Out-File -FilePath "C:\temp\insertcustomer.txt"