using System;
using System.Buffers;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;
using Windows.Win32;
using Windows.Win32.Security;

namespace DesTrainer;

[SupportedOSPlatform("windows6.0")]
static unsafe class Program
{
    const int ValueLength = 2*3*4;
    const char ESC = '\u001B';

    static void Main(string[] args)
    {
        AdjustPrivileges();

        Console.Clear();
        Console.WindowWidth = 50;
        Console.WindowHeight = 5;
        Console.BufferWidth = Console.WindowWidth;
        Console.BufferHeight = Console.WindowHeight;
        Span<byte> ptrBuf = stackalloc byte[4];
        Span<byte> valBuf = stackalloc byte[ValueLength];
        Span<byte> nameBuf = stackalloc byte[2 * 16];
        do
        {
            Console.Title = "Demon's Souls Trainer";
            Console.CursorLeft = 0;
            Console.Write("Searching for the process...");
            var procList = Process.GetProcesses()
                .Where(p => p.MainWindowTitle.Contains("Demon's Souls", StringComparison.InvariantCultureIgnoreCase)
                            && (p.MainModule?.ModuleName.Contains("rpcs3", StringComparison.InvariantCultureIgnoreCase) ?? false)
                ).ToList();
            if (procList.Count == 1)
            {
                var des = procList[0];
                Console.Clear();
#if DEBUG                
                Console.WriteLine($"Opened process {des.Id}: {des.MainModule!.ModuleName}");
#endif
                Console.Title += " (Active)";
                Console.CursorVisible = false;
                using var pmr = ProcessMemoryReader.OpenProcess(des);
                var rpcs3Base = pmr.GetMemoryRegions()
                    .First(r => r.offset >= 0x1_0000_0000 && r.offset % 0x1000_0000 is 0)
                    .offset; // should be either 0x1_0000_0000 or 0x3_0000_0000
#if DEBUG                
                Console.WriteLine($"Guest memory base: 0x{rpcs3Base:x8}");
#endif
                const int statsPointer  = 0x01B4A5EC; // 4
                const int currentSouls  = 0x301E8098; //0x202E8098; // 4
                const int characterName = currentSouls+0x18; //0x202E80B0; // 16*2
                const int offsetHp = 0x3c4;
                var pBase = (IntPtr)(rpcs3Base + statsPointer);
                do
                {
                    pmr.ReadProcessMemory(pBase, 4, ptrBuf, out var readBytes);
                    if (readBytes == 4)
                    {
                            
                        var ptr = (IntPtr)(rpcs3Base + BinaryPrimitives.ReadUInt32BigEndian(ptrBuf) + offsetHp);
                        pmr.ReadProcessMemory(ptr, ValueLength, valBuf, out readBytes);
                        if (readBytes == ValueLength)
                        {
                            var hp = BinaryPrimitives.ReadUInt32BigEndian(valBuf[4..]);
                            var mp = BinaryPrimitives.ReadUInt32BigEndian(valBuf[12..]);
                            var st = BinaryPrimitives.ReadUInt32BigEndian(valBuf[20..]);
                            if (hp < 9999 && mp < 9999 && st < 9999)
                            {
                                valBuf[4..8].CopyTo(valBuf[0..4]);
                                valBuf[12..16].CopyTo(valBuf[8..12]);
                                valBuf[20..24].CopyTo(valBuf[16..20]);
                                pmr.WriteProcessMemory(ptr, valBuf, out _);

                                pmr.ReadProcessMemory((IntPtr)(rpcs3Base + currentSouls), 4, ptrBuf, out readBytes);
                                var souls = rpcs3Base == 0x3_0000_0000 && readBytes == 4
                                    ? BinaryPrimitives.ReadInt32BigEndian(ptrBuf).ToString()
                                    : "";

                                pmr.ReadProcessMemory((IntPtr)(rpcs3Base + characterName), 2 * 16, nameBuf, out readBytes);
                                var name = readBytes > 0 ? Encoding.BigEndianUnicode.GetString(nameBuf[..(int)readBytes]) : "";
                                name = name.TrimEnd('\0', ' ');
                                if (!string.IsNullOrEmpty(name))
                                    name += " ";
                                
                                Console.Write($"\e[G{name}\e[91m❤️{hp} \e[94m🔵{mp} \e[92m🟩{st} \e[0m👻{souls}       ");
                            }
                        }
                    }
#if DEBUG
                    else
                    {
                        var error = Marshal.GetLastWin32Error();
                        var msg = new Win32Exception(error).Message;
                        Console.CursorLeft = 0;
                        Console.Write(msg);
                    }
#endif
                    Thread.Sleep(100);
                } while (!des.HasExited);
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
            var hproc = Process.GetCurrentProcess().SafeHandle;
            PInvoke.OpenProcessToken(
                hproc,
                TOKEN_ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | TOKEN_ACCESS_MASK.TOKEN_QUERY,
                out var htok
            );
            if (!PInvoke.LookupPrivilegeValue(null, PInvoke.SE_DEBUG_NAME, out var luid))
                throw new UnauthorizedAccessException();

            TOKEN_PRIVILEGES tp = new()
            {
                PrivilegeCount = 1,
                Privileges = new()
                {
                    e0 = new()
                    {
                        Luid = luid,
                        Attributes = TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED,
                    }
                }
            };
            PInvoke.AdjustTokenPrivileges(htok, false, &tp, 0, default, default);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
}