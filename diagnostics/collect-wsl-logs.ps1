#Requires -RunAsAdministrator

[CmdletBinding()]
Param (
    $LogProfile = $null,
    [switch]$Dump = $false
   )

Set-StrictMode -Version Latest

$folder = "WslLogs-" + (Get-Date -Format "yyyy-MM-dd_HH-mm-ss")
mkdir -p $folder

if ($LogProfile -eq $null)
{
    $LogProfile = "$folder/wsl.wprp"
    try {
        Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/microsoft/WSL/master/diagnostics/wsl.wprp" -OutFile $LogProfile
    }
    catch {
        throw
    }
}

reg.exe export HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Lxss $folder/HKCU.txt
reg.exe export HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Lxss $folder/HKLM.txt
reg.exe export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\P9NP $folder/P9NP.txt
reg.exe export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2 $folder/Winsock2.txt

$wslconfig = "$env:USERPROFILE/.wslconfig"
if (Test-Path $wslconfig)
{
    Copy-Item $wslconfig $folder
}

get-appxpackage MicrosoftCorporationII.WindowsSubsystemforLinux > $folder/appxpackage.txt
get-acl "C:\ProgramData\Microsoft\Windows\WindowsApps" -ErrorAction Ignore | Format-List > $folder/acl.txt
Get-WindowsOptionalFeature -Online > $folder/optional-components.txt

$wprOutputLog = "$folder/wpr.txt"

wpr.exe -start $LogProfile -filemode 2>&1 >> $wprOutputLog
if ($LastExitCode -Ne 0)
{
    Write-Host -ForegroundColor Yellow "Log collection failed to start (exit code: $LastExitCode), trying to reset it."
    wpr.exe -cancel 2>&1 >> $wprOutputLog

    wpr.exe -start $LogProfile -filemode 2>&1 >> $wprOutputLog
    if ($LastExitCode -Ne 0)
    {
        Write-Host -ForegroundColor Red "Couldn't start log collection (exitCode: $LastExitCode)"
    }
}

try
{
    Write-Host -NoNewLine -ForegroundColor Green "Log collection is running. Please reproduce the problem and press any key to save the logs."

    $KeysToIgnore =
          16,  # Shift (left or right)
          17,  # Ctrl (left or right)
          18,  # Alt (left or right)
          20,  # Caps lock
          91,  # Windows key (left)
          92,  # Windows key (right)
          93,  # Menu key
          144, # Num lock
          145, # Scroll lock
          166, # Back
          167, # Forward
          168, # Refresh
          169, # Stop
          170, # Search
          171, # Favorites
          172, # Start/Home
          173, # Mute
          174, # Volume Down
          175, # Volume Up
          176, # Next Track
          177, # Previous Track
          178, # Stop Media
          179, # Play
          180, # Mail
          181, # Select Media
          182, # Application 1
          183  # Application 2

    $Key = $null
    while ($Key -Eq $null -Or $Key.VirtualKeyCode -Eq $null -Or $KeysToIgnore -Contains $Key.VirtualKeyCode)
    {
        $Key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }

    Write-Host "`nSaving logs..."
}
finally
{
    wpr.exe -stop $folder/logs.etl 2>&1 >> $wprOutputLog
}

if ($Dump)
{
    $Assembly = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
    $DumpMethod = $Assembly.GetNestedType('NativeMethods', 'NonPublic').GetMethod('MiniDumpWriteDump', [Reflection.BindingFlags] 'NonPublic, Static')

    $dumpFolder = Join-Path (Resolve-Path "$folder") dumps
    New-Item -ItemType "directory" -Path "$dumpFolder"

    $executables = "wsl", "wslservice", "wslhost", "msrdc"
    foreach($process in Get-Process | Where-Object { $executables -contains $_.ProcessName})
    {
        $dumpFile =  "$dumpFolder/$($process.ProcessName).$($process.Id).dmp"
        Write-Host "Writing $($dumpFile)"

        $OutputFile = New-Object IO.FileStream($dumpFile, [IO.FileMode]::Create)

        $Result = $DumpMethod.Invoke($null, @($process.Handle,
                                              $process.id,
                                              $OutputFile.SafeFileHandle,
                                              [UInt32] 2
                                              [IntPtr]::Zero,
                                              [IntPtr]::Zero,
                                              [IntPtr]::Zero))

        $OutputFile.Close()
        if (-not $Result)
        {
            Write-Host "Failed to write dump for: $($dumpFile)"
        }
    }
}

# Collect networking state relevant for WSL
$stdOutLog = "$folder/wsl_network_stdout.log"
$stdErrLog = "$folder/wsl_network_stderr.log"

# Using a try/catch as some of the commands below do not exist on some OS versions
try
{
    Write-Output "Get-NetAdapter" | Out-File -FilePath "$folder/Get-NetAdapter.log" -Append
    Get-NetAdapter -includeHidden | select Name,ifIndex,NetLuid,InterfaceGuid,Status,MacAddress,MtuSize,InterfaceType,Hidden,HardwareInterface,ConnectorPresent,MediaType,PhysicalMediaType | Out-File -FilePath "$folder/Get-NetAdapter.log" -Append

    Write-Output "Get-NetFirewallHyperVVMCreator" | Out-File -FilePath "$folder/Get-NetFirewallHyperVVMCreator.log" -Append
    Get-NetFirewallHyperVVMCreator | Out-File -FilePath "$folder/Get-NetFirewallHyperVVMCreator.log" -Append

    Write-Output "Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore" | Out-File -FilePath "$folder/Get-NetFirewallHyperVVMSetting.log" -Append
    Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore | Out-File -FilePath "$folder/Get-NetFirewallHyperVVMSetting.log" -Append

    Write-Output "Get-NetFirewallHyperVProfile -PolicyStore ActiveStore" | Out-File -FilePath "$folder/Get-NetFirewallHyperVProfile.log" -Append
    Get-NetFirewallHyperVProfile -PolicyStore ActiveStore | Out-File -FilePath "$folder/Get-NetFirewallHyperVProfile.log" -Append

    Write-Output "Get-NetFirewallHyperVPort" | Out-File -FilePath "$folder/Get-NetFirewallHyperVPort.log" -Append
    Get-NetFirewallHyperVPort | Out-File -FilePath "$folder/Get-NetFirewallHyperVPort.log" -Append

    Write-Output "hnsdiag.exe list all" | Out-File -FilePath "$folder/hnsdiag_list_all.log" -Append
    Start-Process -FilePath "hnsdiag.exe" -ArgumentList "list all" -RedirectStandardOutput $stdOutLog -RedirectStandardError $stdErrLog -NoNewWindow -wait
    Get-Content $stdOutLog, $stdErrLog | Out-File -FilePath "$folder/hnsdiag_list_all.log" -Append

    Write-Output "hnsdiag.exe list endpoints -df" | Out-File -FilePath "$folder/hnsdiag_list_endpoints.log" -Append
    Start-Process -FilePath "hnsdiag.exe" -ArgumentList "list endpoints -df" -RedirectStandardOutput $stdOutLog -RedirectStandardError $stdErrLog -NoNewWindow -wait
    Get-Content $stdOutLog, $stdErrLog | Out-File -FilePath "$folder/hnsdiag_list_endpoints.log" -Append

    foreach ($a in Get-NetFirewallHyperVPort)
    {
        $vfpLogFile = "$folder/vfp-port-" + $a.PortName + ".log"

        $vfpctrlArg = "/port " + $a.PortName + " /get-port-state"
        Write-Output "Querying vfpctrl.exe $vfpctrlArg" | Out-File -FilePath $vfpLogFile -Append
        Start-Process -FilePath "vfpctrl.exe" -ArgumentList $vfpctrlArg -RedirectStandardOutput $stdOutLog -RedirectStandardError $stdErrLog -NoNewWindow -wait
        Get-Content $stdOutLog, $stdErrLog | Out-File -FilePath $vfpLogFile -Append

        $vfpctrlArg = "/port " + $a.PortName + " /list-rule"
        Write-Output "Querying vfpctrl.exe $vfpctrlArg" | Out-File -FilePath $vfpLogFile -Append
        Start-Process -FilePath "vfpctrl.exe" -ArgumentList $vfpctrlArg -RedirectStandardOutput $stdOutLog -RedirectStandardError $stdErrLog -NoNewWindow -wait
        Get-Content $stdOutLog, $stdErrLog | Out-File -FilePath $vfpLogFile -Append
    }

    Write-Output "Querying vfpctrl.exe /list-vmswitch-port" | Out-File -FilePath "$folder/vfpctrl_list_vmswitch_port.log" -Append
    Start-Process -FilePath "vfpctrl.exe" -ArgumentList "/list-vmswitch-port" -RedirectStandardOutput $stdOutLog -RedirectStandardError $stdErrLog -NoNewWindow -wait
    Get-Content $stdOutLog, $stdErrLog | Out-File -FilePath "$folder/vfpctrl_list_vmswitch_port.log" -Append
}
catch
{
}
finally
{
    if (Test-Path $stdOutLog)
    {
        Remove-Item $stdOutLog
    }
    if (Test-Path $stdErrLog)
    {
        Remove-Item $stdErrLog
    }
}

$logArchive = "$(Resolve-Path $folder).zip"
Compress-Archive -Path $folder -DestinationPath $logArchive
Remove-Item $folder -Recurse

Write-Host -ForegroundColor Green "Logs saved in: $logArchive. Please attach that file to the GitHub issue."
