using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DesTrainer
{
    public class ProcessMemoryReader: IDisposable
    {
        private IntPtr m_hProcess = IntPtr.Zero;

        public static ProcessMemoryReader OpenProcess(Process process)
        {
            var access = ProcessAccessType.PROCESS_VM_READ |
                         ProcessAccessType.PROCESS_VM_WRITE |
                         ProcessAccessType.PROCESS_VM_OPERATION;
            return new ProcessMemoryReader { m_hProcess = Kernel32.OpenProcess((uint)access, 1, (uint)process.Id) };
        }

        public void ReadProcessMemory(IntPtr MemoryAddress, uint bytesToRead, byte[] buffer, out int bytesRead)
        {
            var changedProtection = Kernel32.VirtualProtectEx(m_hProcess, MemoryAddress, (UIntPtr)bytesToRead, MemoryProtection.PAGE_EXECUTE_READWRITE, out var originalProtection);
            Kernel32.ReadProcessMemory(m_hProcess, MemoryAddress, buffer, bytesToRead, out var ptrBytesRead);
            if (changedProtection)
                Kernel32.VirtualProtectEx(m_hProcess, MemoryAddress, (UIntPtr)bytesToRead, originalProtection, out _);
            bytesRead = ptrBytesRead.ToInt32();
        }

        public void WriteProcessMemory(IntPtr MemoryAddress, byte[] bytesToWrite, out int bytesWritten)
        {
            Kernel32.WriteProcessMemory(m_hProcess, MemoryAddress, bytesToWrite, (uint)bytesToWrite.Length, out var ptrBytesWritten);
            bytesWritten = ptrBytesWritten.ToInt32();
        }

        public void Dispose()
        {
            if (m_hProcess != IntPtr.Zero)
                Kernel32.CloseHandle(m_hProcess);
        }
    }
}