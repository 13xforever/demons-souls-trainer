using System;
using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using BitConverter;

namespace DesTrainer
{
    static class Program
    {
        const int valueLength = 2*3*4;
        private static readonly ArrayPool<byte> ArrayPool = ArrayPool<byte>.Create(valueLength, 64);

        static void Main(string[] args)
        {
            AdjustPrivileges();

            Console.Clear();
            Console.WindowWidth = 60;
            Console.WindowHeight = 5;
            Console.BufferWidth = Console.WindowWidth;
            Console.BufferHeight = Console.WindowHeight;
            do
            {
                Console.Title = "Demon's Souls Trainer";
                Console.CursorLeft = 0;
                Console.Write("Searching for the process...");
                var procList = Process.GetProcesses()
                    .Where(p => p.MainWindowTitle.Contains("Demon's Souls", StringComparison.InvariantCultureIgnoreCase) &&
                                p.MainModule.ModuleName.Contains("rpcs3", StringComparison.InvariantCultureIgnoreCase)
                    ).ToList();
                if (procList.Count == 1)
                {
                    var des = procList[0];
                    Console.Clear();
                    Console.WriteLine($"Opened process {des.Id}: {des.MainModule.ModuleName}");
                    Console.Title += " (Active)";
                    Console.CursorVisible = false;
                    var ptrBuf = ArrayPool.Rent(4);
                    var valBuf = ArrayPool.Rent(valueLength);
                    var nameBuf = ArrayPool.Rent(2*16);
                    using (var pmr = ProcessMemoryReader.OpenProcess(des))
                    {

                        var rpcs3Base = pmr.GetMemoryRegions().First(r => r.offset >= 0x1_0000_0000 && (r.offset % 0x1000_0000 == 0)).offset; // should be either 0x1_0000_0000 or 0x3_0000_0000
                        Console.WriteLine($"Guest memory base: 0x{rpcs3Base:x8}");
                        const int statsPointer  = 0x01B4A5EC; // 4
                        const int characterName = 0x202E80B0; // 16*2
                        const int currentSouls  = 0x202E8098; // 4
                        const int offsetHp = 0x3c4;
                        var pBase = (IntPtr)(rpcs3Base + statsPointer);
                        do
                        {
                            pmr.ReadProcessMemory(pBase, 4, ptrBuf, out var readBytes);
                            if (readBytes == 4)
                            {
                                var ptr = (IntPtr)(rpcs3Base + EndianBitConverter.BigEndian.ToUInt32(ptrBuf, 0) + offsetHp);
                                pmr.ReadProcessMemory(ptr, valueLength, valBuf, out readBytes);
                                if (readBytes == valueLength)
                                {
                                    Buffer.BlockCopy(valBuf, 4, valBuf, 0, 4);
                                    Buffer.BlockCopy(valBuf, 12, valBuf, 8, 4);
                                    Buffer.BlockCopy(valBuf, 20, valBuf, 16, 4);
                                    pmr.WriteProcessMemory(ptr, valBuf, out _);
                                    pmr.ReadProcessMemory((IntPtr)(rpcs3Base + characterName), 2 * 16, nameBuf, out readBytes);

                                    var name = readBytes > 0 ? Encoding.BigEndianUnicode.GetString(nameBuf, 0, readBytes / 2) : "";
                                    name = name.TrimEnd('\0', ' ');
                                    if (!string.IsNullOrEmpty(name))
                                        name += " ";

                                    pmr.ReadProcessMemory((IntPtr)(rpcs3Base + currentSouls), 4, ptrBuf, out readBytes);
                                    var souls = readBytes == 4 ? EndianBitConverter.BigEndian.ToInt32(ptrBuf, 0).ToString() : "";

                                    var hp = EndianBitConverter.BigEndian.ToUInt32(valBuf, 0);
                                    var mp = EndianBitConverter.BigEndian.ToUInt32(valBuf, 8);
                                    var st = EndianBitConverter.BigEndian.ToUInt32(valBuf, 12);
                                    Console.CursorLeft = 0;
                                    Console.Write(name);
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.Write($"{hp} ");
                                    Console.ForegroundColor = ConsoleColor.Blue;
                                    Console.Write($"{mp} ");
                                    Console.ForegroundColor = ConsoleColor.Green;
                                    Console.Write($"{st} ");
                                    Console.ResetColor();
                                    Console.Write($"{souls}       ");
                                }
                            }
                            else
                            {
                                var error = Marshal.GetLastWin32Error();
                                var msg = new Win32Exception(error).Message;
                                Console.CursorLeft = 0;
                                Console.Write(msg);
                            }
                            Thread.Sleep(100);
                        } while (!des.HasExited);
                    }
                    ArrayPool.Return(nameBuf);
                    ArrayPool.Return(valBuf);
                    ArrayPool.Return(ptrBuf);
                    Console.Clear();
                    Console.CursorVisible = false;
                }
                else
                    Thread.Sleep(1000);
            } while (true);
        }

        private static void AdjustPrivileges()
        {
            try
            {
                TOKEN_PRIVILEGES tp;
                var hproc = Kernel32.GetCurrentProcess();
                var htok = IntPtr.Zero;
                Advapi32.OpenProcessToken(hproc, TokenPriveleges.TOKEN_ADJUST_PRIVILEGES | TokenPriveleges.TOKEN_QUERY, ref htok);
                tp.PrivilegeCount = 1;
                tp.Luid = new LUID();
                tp.Attributes = Advapi32.SE_PRIVILEGE_ENABLED;
                if (!Advapi32.LookupPrivilegeValue(null, SecurityEntity.SE_DEBUG_NAME, ref tp.Luid))
                    throw new UnauthorizedAccessException();

                Advapi32.AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
