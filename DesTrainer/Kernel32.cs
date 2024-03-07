using System;
using System.Runtime.InteropServices;

namespace DesTrainer;

internal static class Kernel32
{
    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, uint bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll")]
    public static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    public static extern int ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    public static extern int CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, uint size, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, uint size, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);
}

[Flags]
public enum MemoryProtection: uint
{
    PAGE_NOACCESS          = 0x01,
    PAGE_READONLY          = 0x02,
    PAGE_READWRITE         = 0x04,
    PAGE_WRITECOPY         = 0x08,
    PAGE_EXECUTE           = 0x10,
    PAGE_EXECUTE_READ      = 0x20,
    PAGE_EXECUTE_READWRITE = 0x40,
    PAGE_EXECUTE_WRITECOPY = 0x80,

    PAGE_GUARD        = 0x100,
    PAGE_NOCACHE      = 0x200,
    PAGE_WRITECOMBINE = 0x400,

    PAGE_TARGETS_INVALID   = 0x40000000,
    PAGE_TARGETS_NO_UPDATE = 0x40000000,

}

public struct SYSTEM_INFO
{
    public ushort processorArchitecture;
    public ushort reserved;
    public uint pageSize;
    public IntPtr minimumApplicationAddress;
    public IntPtr maximumApplicationAddress;
    public IntPtr activeProcessorMask;
    public uint numberOfProcessors;
    public uint processorType;
    public uint allocationGranularity;
    public ushort processorLevel;
    public ushort processorRevision;
}

[Flags]
public enum ThreadAccess : int
{
    TERMINATE = 0x0001,
    SUSPEND_RESUME = 0x0002,
    GET_CONTEXT = 0x0008,
    SET_CONTEXT = 0x0010,
    SET_INFORMATION = 0x0020,
    QUERY_INFORMATION = 0x0040,
    SET_THREAD_TOKEN = 0x0080,
    IMPERSONATE = 0x0100,
    DIRECT_IMPERSONATION = 0x0200
}

[Flags]
public enum ProcessAccessType
{
    DELETE = 0x00010000,
    READ_CONTROL = 0x00020000,
    WRITE_DAC = 0x00040000,
    WRITE_OWNER = 0x00080000,
    SYNCHRONIZE = 0x00100000,

    PROCESS_TERMINATE = 0x0001,
    PROCESS_CREATE_THREAD = 0x0002,
    PROCESS_SET_SESSIONID = 0x0004,
    PROCESS_VM_OPERATION = 0x0008,
    PROCESS_VM_READ = 0x0010,
    PROCESS_VM_WRITE = 0x0020,
    PROCESS_DUP_HANDLE = 0x0040,
    PROCESS_CREATE_PROCESS = 0x0080,
    PROCESS_SET_QUOTA = 0x0100,
    PROCESS_SET_INFORMATION = 0x0200,
    PROCESS_QUERY_INFORMATION = 0x0400,
    PROCESS_SUSPEND_RESUME = 0x0800,
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
}

[StructLayout(LayoutKind.Sequential)]
public struct MEMORY_BASIC_INFORMATION
{
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public MemoryProtection AllocationProtect;
    public IntPtr RegionSize;
    public MemoryBasicInformationState State;
    public uint Protect;
    public MemoryBasicInformationType Type;
}

public enum MemoryBasicInformationState : uint
{
    MEM_COMMIT = 0x00001000,
    MEM_RESERVE = 0x00002000,
    MEM_RESET = 0x00080000,
    MEM_RESET_UNDO = 0x1000000
}

public enum MemoryBasicInformationType : uint
{
    MEM_IMAGE = 0x1000000,
    MEM_MAPPED = 0x40000,
    MEM_PRIVATE = 0x20000
}