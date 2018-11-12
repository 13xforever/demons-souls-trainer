using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace DesTrainer
{
    public class ProcessMemoryReader: IDisposable
    {
        private IntPtr procHandle = IntPtr.Zero;

        public static ProcessMemoryReader OpenProcess(Process process)
        {
            var access = ProcessAccessType.PROCESS_VM_READ |
                         ProcessAccessType.PROCESS_VM_WRITE |
                         ProcessAccessType.PROCESS_VM_OPERATION;
            return new ProcessMemoryReader { procHandle = Kernel32.OpenProcess((uint)access, 1, (uint)process.Id) };
        }

        public void ReadProcessMemory(IntPtr address, uint bytesToRead, byte[] buffer, out int bytesRead)
        {
            var changedProtection = Kernel32.VirtualProtectEx(procHandle, address, (UIntPtr)bytesToRead, MemoryProtection.PAGE_EXECUTE_READWRITE, out var originalProtection);
            Kernel32.ReadProcessMemory(procHandle, address, buffer, bytesToRead, out var ptrBytesRead);
            if (changedProtection)
                Kernel32.VirtualProtectEx(procHandle, address, (UIntPtr)bytesToRead, originalProtection, out _);
            bytesRead = ptrBytesRead.ToInt32();
        }

        public void WriteProcessMemory(IntPtr address, byte[] bytesToWrite, out int bytesWritten)
        {
            Kernel32.WriteProcessMemory(procHandle, address, bytesToWrite, (uint)bytesToWrite.Length, out var ptrBytesWritten);
            bytesWritten = ptrBytesWritten.ToInt32();
        }

        public List<(ulong offset, ulong length)> GetMemoryRegions()
        {
            var result = new List<(ulong offset, ulong length)>();
            var regions = new HashSet<(ulong offset, ulong length)>();
            int queryResult;
            ulong offset = 0;
            do
            {
                queryResult = Kernel32.VirtualQueryEx(procHandle, (IntPtr)offset, out var memInfo, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                var allocationBase = (ulong)memInfo.AllocationBase;
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
            if (procHandle != IntPtr.Zero)
                Kernel32.CloseHandle(procHandle);
        }
    }
}