﻿using System;
using System.Buffers;
using System.Diagnostics;
using System.Linq;
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
            do
            {
                Console.Title = "Demon's Souls Trainer";
                var procList = Process.GetProcesses()
                    .Where(p => p.MainWindowTitle.Contains("Demon's Souls", StringComparison.InvariantCultureIgnoreCase) &&
                                p.MainModule.ModuleName.Contains("rpcs3", StringComparison.InvariantCultureIgnoreCase)
                    ).ToList();
                if (procList.Count == 1)
                {
                    var des = procList[0];
                    Console.WriteLine($"Opened process {des.Id}: {des.MainModule.ModuleName}");
                    Console.Title += " (Active)";
                    Console.CursorVisible = false;
                    using (var pmr = ProcessMemoryReader.OpenProcess(des))
                    {

                        const ulong rpcs3Base = 0x1_0000_0000;
                        const int offsetHp = 0x3c4;
                        var pBase = (IntPtr)0x101B4A5EC;
                        do
                        {
                            var ptrBuf = ArrayPool.Rent(4);
                            var valBuf = ArrayPool.Rent(valueLength);
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

                                    var hp = EndianBitConverter.BigEndian.ToUInt32(valBuf, 0);
                                    var mp = EndianBitConverter.BigEndian.ToUInt32(valBuf, 8);
                                    var st = EndianBitConverter.BigEndian.ToUInt32(valBuf, 12);
                                    Console.CursorLeft = 0;
                                    Console.Write($"HP {hp} / MP {mp} / ST {st}            ");
                                }
                            }
                            Thread.Sleep(50);
                        } while (!des.HasExited);
                    }
                }
                else
                    Thread.Sleep(100);
            } while (true);
        }
    }
}