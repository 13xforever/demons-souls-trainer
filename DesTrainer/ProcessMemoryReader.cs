using System;
using System.Diagnostics;

namespace DesTrainer
{
    public class ProcessMemoryReader:IDisposable
    {
        private IntPtr m_hProcess = IntPtr.Zero;

        public static ProcessMemoryReader OpenProcess(Process process)
        {
            var access = Kernel32.ProcessAccessType.PROCESS_VM_READ |
                         Kernel32.ProcessAccessType.PROCESS_VM_WRITE |
                         Kernel32.ProcessAccessType.PROCESS_VM_OPERATION;
            return new ProcessMemoryReader { m_hProcess = Kernel32.OpenProcess((uint)access, 1, (uint)process.Id) };
        }

        public void ReadProcessMemory(IntPtr MemoryAddress, uint bytesToRead, byte[] buffer, out int bytesRead)
        {
            Kernel32.ReadProcessMemory(m_hProcess, MemoryAddress, buffer, bytesToRead, out var ptrBytesRead);
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