using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.System.Memory;
using Windows.Win32.System.Threading;

namespace DesTrainer;

[SupportedOSPlatform("windows6.0")]
public unsafe class ProcessMemoryReader: IDisposable
{
    private SafeHandle procHandle;

    public static ProcessMemoryReader OpenProcess(Process process)
        => new()
        {
            procHandle = PInvoke.OpenProcess_SafeHandle(
                PROCESS_ACCESS_RIGHTS.PROCESS_VM_OPERATION
                | PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ
                | PROCESS_ACCESS_RIGHTS.PROCESS_VM_WRITE,
                true,
                (uint)process.Id
            )
        };

    public void ReadProcessMemory(IntPtr address, uint bytesToRead, Span<byte> buffer, out uint bytesRead)
    {
        var changedProtection = PInvoke.VirtualProtectEx(procHandle, (void*)address, bytesToRead, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE, out var originalProtection);
        PInvoke.ReadProcessMemory(procHandle, (void*)address, buffer, out var lpBytesRead);
        if (changedProtection)
            PInvoke.VirtualProtectEx(procHandle, (void*)address, bytesToRead, originalProtection, out _);
        bytesRead = lpBytesRead.ToUInt32();
    }

    public void WriteProcessMemory(IntPtr address, Span<byte> bytesToWrite, out uint bytesWritten)
    {
        PInvoke.WriteProcessMemory(procHandle, (void*)address, bytesToWrite, out var lpBytesWritten);
        bytesWritten = lpBytesWritten.ToUInt32();
    }

    public List<(ulong offset, ulong length)> GetMemoryRegions()
    {
        var result = new List<(ulong offset, ulong length)>();
        UIntPtr queryResult;
        ulong offset = 0;
        do
        {
            queryResult = PInvoke.VirtualQueryEx(procHandle, (void*)offset, out var memInfo);
            //var allocationBase = (ulong)memInfo.AllocationBase;
            var baseAddress = (ulong)memInfo.BaseAddress;
            var regionSize = (ulong)memInfo.RegionSize;
            var newOffset = baseAddress + regionSize;
            if (newOffset > offset)
            {
                offset = newOffset;
                if (queryResult > 0)
                {
                    var newRegion = (baseAddress, regionSize);
                    result.Add(newRegion);
                }
            }
            else if (baseAddress > 0)
                offset += 4096;
            else
                break;
        } while (queryResult != 0);
        return result;
    }

    public void Dispose()
    {
        procHandle?.Dispose();
    }
}