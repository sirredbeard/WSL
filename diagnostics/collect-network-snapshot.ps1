# Script to collect a snapshot of WSL network state. When investigating an issue, the script needs to be run when WSL is in the repro state.

$wslNetworkLog = ".\wsl_network_snapshot.log"
$stdOutLog = ".\wsl_network_stdout.log"
$stdErrLog = ".\wsl_network_stderr.log"

Write-Output "WSL Net Snapshot" | Out-File -FilePath $wslNetworkLog

Write-Output -----------------------------------------------------------------------   | Out-File -FilePath $wslNetworkLog -Append

Write-Output "Get-NetAdapter"  | Out-File -FilePath $wslNetworkLog -Append
Get-NetAdapter -includeHidden | select Name,ifIndex,NetLuid,InterfaceGuid,Status,MacAddress,MtuSize,InterfaceType,Hidden,HardwareInterface,ConnectorPresent,MediaType,PhysicalMediaType    | Out-File -FilePath $wslNetworkLog -Append

Write-Output -----------------------------------------------------------------------   | Out-File -FilePath $wslNetworkLog -Append

Write-Output "Get-NetFirewallHyperVVMCreator"  | Out-File -FilePath $wslNetworkLog -Append
Get-NetFirewallHyperVVMCreator  | Out-File -FilePath $wslNetworkLog -Append

Write-Output -----------------------------------------------------------------------   | Out-File -FilePath $wslNetworkLog -Append

Write-Output "Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore"  | Out-File -FilePath $wslNetworkLog -Append
Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore  | Out-File -FilePath $wslNetworkLog -Append

Write-Output -----------------------------------------------------------------------   | Out-File -FilePath $wslNetworkLog -Append

Write-Output "Get-NetFirewallHyperVProfile -PolicyStore ActiveStore"  | Out-File -FilePath $wslNetworkLog -Append
Get-NetFirewallHyperVProfile -PolicyStore ActiveStore  | Out-File -FilePath $wslNetworkLog -Append

Write-Output -----------------------------------------------------------------------   | Out-File -FilePath $wslNetworkLog -Append

$hypervVports = Get-NetFirewallHyperVPort
if (!$hypervVports)
{
    Write-Output "Get-NetFirewallHyperVPort returned no ports"  | Out-File -FilePath $wslNetworkLog -Append
}
else
{
    Write-Output "Get-NetFirewallHyperVPort"  | Out-File -FilePath $wslNetworkLog -Append
    Get-NetFirewallHyperVPort  | Out-File -FilePath $wslNetworkLog -Append
}

Write-Output -----------------------------------------------------------------------   | Out-File -FilePath $wslNetworkLog -Append

Write-Output "hnsdiag.exe list all" | Out-File -FilePath $wslNetworkLog -Append
Start-Process -FilePath "hnsdiag.exe" -ArgumentList "list all" -RedirectStandardOutput $stdOutLog -RedirectStandardError $stdErrLog -NoNewWindow -wait
Get-Content $stdOutLog, $stdErrLog | Out-File -FilePath $wslNetworkLog -Append

Write-Output -----------------------------------------------------------------------   | Out-File -FilePath $wslNetworkLog -Append

Write-Output "hnsdiag.exe list endpoints -df" | Out-File -FilePath $wslNetworkLog -Append
Start-Process -FilePath "hnsdiag.exe" -ArgumentList "list endpoints -df" -RedirectStandardOutput $stdOutLog -RedirectStandardError $stdErrLog -NoNewWindow -wait
Get-Content $stdOutLog, $stdErrLog | Out-File -FilePath $wslNetworkLog -Append

Write-Output -----------------------------------------------------------------------   | Out-File -FilePath $wslNetworkLog -Append

foreach ($a in Get-NetFirewallHyperVPort)
{
    $vfpctrlArg = "/port " + $a.PortName + " /get-port-state"
    Write-Output "Querying vfpctrl.exe $vfpctrlArg"  | Out-File -FilePath $wslNetworkLog -Append
    Start-Process -FilePath "vfpctrl.exe" -ArgumentList $vfpctrlArg -RedirectStandardOutput $stdOutLog -RedirectStandardError $stdErrLog -NoNewWindow -wait
    Get-Content $stdOutLog, $stdErrLog | Out-File -FilePath $wslNetworkLog -Append

    Write-Output -----------------------------------------------------------------------   | Out-File -FilePath $wslNetworkLog -Append

    $vfpctrlArg = "/port " + $a.PortName + " /list-rule"
    Write-Output "Querying vfpctrl.exe $vfpctrlArg"  | Out-File -FilePath $wslNetworkLog -Append
    Start-Process -FilePath "vfpctrl.exe" -ArgumentList $vfpctrlArg -RedirectStandardOutput $stdOutLog -RedirectStandardError $stdErrLog -NoNewWindow -wait
    Get-Content $stdOutLog, $stdErrLog | Out-File -FilePath $wslNetworkLog -Append

    Write-Output -----------------------------------------------------------------------   | Out-File -FilePath $wslNetworkLog -Append
}

Write-Output "Querying vfpctrl.exe /list-vmswitch-port"  | Out-File -FilePath $wslNetworkLog -Append
Start-Process -FilePath "vfpctrl.exe" -ArgumentList "/list-vmswitch-port" -RedirectStandardOutput $stdOutLog -RedirectStandardError $stdErrLog -NoNewWindow -wait
Get-Content $stdOutLog, $stdErrLog | Out-File -FilePath $wslNetworkLog -Append

del $stdOutLog
del $stdErrLog
