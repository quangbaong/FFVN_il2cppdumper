// Source/Il2CppDumper.Core/Utils/FreeFireUnpacker.cs
// C# / .NET 10 / Windows x64 / Free Fire VN libil2cpp.so runtime .rodata AES+XOR+permutation unpacker
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Il2CppDumper
{
    public sealed class FreeFireUnpackResult
    {
        public byte[] UnpackedBytes { get; init; }
        public uint RodataOffset { get; init; }
        public uint RodataSize { get; init; }
        public uint AlignedStartOffset { get; init; }
        public uint Seed { get; init; }
        public byte XorKey { get; init; }
        public uint PermutationKey { get; init; }
        public string PermSource { get; init; }
        public string Base64Key { get; init; }
        public int FullBlockCount { get; init; }
        public int TailXorBytes { get; init; }
    }

    /// <summary>
    /// Static unpacker for Free Fire VN's protected libil2cpp.so:
    /// locates the embedded #U#I#N#F#P#A#F# descriptor, derives the 32-bit seed from
    /// the Base64 token, AES-128-CBC decrypts the first 16 KB page block (8 x 0x800),
    /// XOR-decrypts each 16 KB block across 64 KB strides, and reverses the 8-block permutation
    /// via libanort.so's embedded permutation word (with boundary-continuity fallback).
    /// </summary>
    public static class FreeFireUnpacker
    {
        private static readonly byte[] RodataMarker = Encoding.ASCII.GetBytes("#U#I#N#F#P#A#F#\0");
        private static readonly byte[] AnortSigMarker = Encoding.ASCII.GetBytes("Txy*#xP?@xxP6~C\0");
        private const uint StubMagic = 0x12345678u;
        private const uint UnpackedMagic = 0x4B504E55u; // "UNPK"
        private const int PageBlockSize = 0x4000;
        private const int StrideSize = 0x10000;
        private const int GroupBlockCount = 8;

        public static bool IsPacked(byte[] il2cppBytes)
        {
            if (il2cppBytes == null || il2cppBytes.Length < 0x1000)
                return false;
            int markerOff = FindPatternReverse(il2cppBytes, RodataMarker);
            if (markerOff < 0 || markerOff + 0x14 > il2cppBytes.Length)
                return false;
            return BinaryPrimitives.ReadUInt32LittleEndian(il2cppBytes.AsSpan(markerOff + 0x10, 4)) == StubMagic;
        }

        public static FreeFireUnpackResult Unpack(byte[] il2cppBytes, byte[] anortBytes = null)
        {
            if (il2cppBytes == null)
                throw new ArgumentNullException(nameof(il2cppBytes));

            int markerOff = FindPatternReverse(il2cppBytes, RodataMarker);
            if (markerOff < 0 || markerOff + 0x200 > il2cppBytes.Length)
                throw new InvalidDataException("Free Fire packer descriptor (#U#I#N#F#P#A#F#) not found.");

            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(il2cppBytes.AsSpan(markerOff + 0x10, 4));
            if (magic != StubMagic)
                throw new InvalidDataException($"Unexpected stub descriptor magic: 0x{magic:X8}");

            string secName = ReadNullString(il2cppBytes, markerOff + 0x14, 16);
            if (secName != ".rodata")
                throw new InvalidDataException($"Expected .rodata entry in stub descriptor, got '{secName}'.");

            uint rodataVa = BinaryPrimitives.ReadUInt32LittleEndian(il2cppBytes.AsSpan(markerOff + 0x24, 4));
            uint rodataOff = BinaryPrimitives.ReadUInt32LittleEndian(il2cppBytes.AsSpan(markerOff + 0x28, 4));
            uint rodataSize = BinaryPrimitives.ReadUInt32LittleEndian(il2cppBytes.AsSpan(markerOff + 0x2c, 4));

            if (rodataOff == 0 || rodataSize < 0x20000 || (long)rodataOff + rodataSize > il2cppBytes.Length)
                throw new InvalidDataException($"Invalid .rodata bounds offset=0x{rodataOff:X}, size=0x{rodataSize:X}");

            string b64Key = ReadNullString(il2cppBytes, markerOff + 0x1b8, 128);
            byte[] keyRaw = Convert.FromBase64String(b64Key);
            if (keyRaw.Length < 20)
                throw new InvalidDataException($"Unexpected Base64 key decoded length ({keyRaw.Length} bytes).");

            uint word1 = BinaryPrimitives.ReadUInt32BigEndian(keyRaw.AsSpan(4, 4));
            uint word4 = BinaryPrimitives.ReadUInt32BigEndian(keyRaw.AsSpan(16, 4));
            uint seed = word1 ^ word4;

            var output = new byte[il2cppBytes.Length];
            Buffer.BlockCopy(il2cppBytes, 0, output, 0, il2cppBytes.Length);

            uint skip = 0x2000u - (rodataOff & 0xfffu);
            uint alignedStart = rodataOff + skip;
            uint remSize = rodataSize - skip;

            // Stage 1: fn_eb7f8 — AES-128-CBC on first 16 KB (8 x 0x800 blocks) with IV [2..17].
            byte[] aesKey = Encoding.ASCII.GetBytes($"{seed:x8}{seed:x8}");
            byte[] iv = new byte[16];
            for (int i = 0; i < 16; i++) iv[i] = (byte)(i + 2);

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.Key = aesKey;
                aes.IV = iv;
                for (int off = 0; off < PageBlockSize; off += 0x800)
                {
                    using var dec = aes.CreateDecryptor();
                    byte[] plain = dec.TransformFinalBlock(output, checked((int)(alignedStart + off)), 0x800);
                    Buffer.BlockCopy(plain, 0, output, checked((int)(alignedStart + off)), 0x800);
                }
            }

            // Stage 2: fn_fb128 — XOR remainder across 64 KB strides and un-permute 8-block groups.
            uint addr2 = alignedStart + StrideSize;
            uint size2 = remSize - StrideSize;
            byte xorKey = (byte)((seed >> 16) & 0xff);
            if (xorKey == 0) xorKey = 0x87;

            int fullStrideCount = (int)(size2 / StrideSize);
            for (int fp = 0; fp < fullStrideCount; fp++)
            {
                int blkOff = checked((int)(addr2 + (uint)fp * StrideSize));
                for (int i = 0; i < PageBlockSize; i++)
                {
                    output[blkOff + i] ^= xorKey;
                }
            }

            int tailStart = fullStrideCount * StrideSize;
            int tailXorBytes = 0;
            if (tailStart < (int)size2)
            {
                tailXorBytes = (int)size2 - tailStart;
                int absTailStart = checked((int)(addr2 + (uint)tailStart));
                for (int i = 0; i < tailXorBytes; i++)
                {
                    output[absTailStart + i] ^= xorKey;
                }
            }

            string permSource;
            uint perm = 0;
            if (TryReadPermFromAnort(anortBytes, out perm))
            {
                permSource = "libanort.so";
            }
            else if (TryInferPermFromBoundaries(output, addr2, fullStrideCount, out perm))
            {
                permSource = "boundary-inference";
            }
            else
            {
                throw new InvalidDataException("Unable to determine 8-block .rodata permutation key (provide libanort.so or valid .rodata boundaries).");
            }

            int[] nibbles = new int[GroupBlockCount];
            for (int i = 0; i < GroupBlockCount; i++)
            {
                nibbles[i] = (int)((perm >> (28 - i * 4)) & 0xf);
            }

            int groupCount = fullStrideCount / GroupBlockCount;
            byte[] groupBuf = new byte[GroupBlockCount * PageBlockSize];
            for (int g = 0; g < groupCount; g++)
            {
                int grpBase = checked((int)(addr2 + (uint)g * GroupBlockCount * StrideSize));
                for (int i = 0; i < GroupBlockCount; i++)
                {
                    Buffer.BlockCopy(output, grpBase + i * StrideSize, groupBuf, i * PageBlockSize, PageBlockSize);
                }
                for (int i = 0; i < GroupBlockCount; i++)
                {
                    Buffer.BlockCopy(groupBuf, i * PageBlockSize, output, grpBase + nibbles[i] * StrideSize, PageBlockSize);
                }
            }

            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(markerOff + 0x10, 4), UnpackedMagic);

            return new FreeFireUnpackResult
            {
                UnpackedBytes = output,
                RodataOffset = rodataOff,
                RodataSize = rodataSize,
                AlignedStartOffset = alignedStart,
                Seed = seed,
                XorKey = xorKey,
                PermutationKey = perm,
                PermSource = permSource,
                Base64Key = b64Key,
                FullBlockCount = fullStrideCount + 1,
                TailXorBytes = tailXorBytes
            };
        }

        private static bool TryReadPermFromAnort(byte[] anortBytes, out uint perm)
        {
            perm = 0;
            if (anortBytes == null || anortBytes.Length < 0x80)
                return false;
            int sigOff = FindPatternReverse(anortBytes, AnortSigMarker);
            if (sigOff < 0 || sigOff + 0x64 > anortBytes.Length)
                return false;
            uint cand = BinaryPrimitives.ReadUInt32LittleEndian(anortBytes.AsSpan(sigOff + 0x60, 4));
            if (!IsValidNibblePermutation(cand))
                return false;
            perm = cand;
            return true;
        }

        private static bool IsValidNibblePermutation(uint value)
        {
            int mask = 0;
            for (int i = 0; i < 8; i++)
            {
                int d = (int)((value >> (28 - i * 4)) & 0xf);
                if (d >= 8) return false;
                mask |= (1 << d);
            }
            return mask == 0xFF;
        }

        private static bool TryInferPermFromBoundaries(byte[] data, uint addr2, int fullStrideCount, out uint perm)
        {
            perm = 0;
            int groupCount = fullStrideCount / GroupBlockCount;
            if (groupCount <= 0)
                return false;

            // Score placement cost[src, dst] averaged over groups: matches ASCII identifiers/types or monotonic uint32 transitions.
            long[,] score = new long[8, 8];
            for (int g = 0; g < groupCount; g++)
            {
                int grpBase = checked((int)(addr2 + (uint)g * GroupBlockCount * StrideSize));
                for (int src = 0; src < 8; src++)
                {
                    int srcOff = grpBase + src * StrideSize;
                    for (int dst = 0; dst < 8; dst++)
                    {
                        int dstOff = grpBase + dst * StrideSize;
                        score[src, dst] += ScoreBoundaryFit(data, srcOff, dstOff);
                    }
                }
            }

            long bestScore = long.MinValue;
            uint bestPerm = 0;
            int[] current = new int[8];
            bool[] used = new bool[8];

            void Search(int depth, long acc)
            {
                if (depth == 8)
                {
                    if (acc > bestScore)
                    {
                        bestScore = acc;
                        uint p = 0;
                        for (int i = 0; i < 8; i++)
                            p = (p << 4) | (uint)current[i];
                        bestPerm = p;
                    }
                    return;
                }
                for (int dst = 0; dst < 8; dst++)
                {
                    if (used[dst]) continue;
                    used[dst] = true;
                    current[depth] = dst;
                    Search(depth + 1, acc + score[depth, dst]);
                    used[dst] = false;
                }
            }

            Search(0, 0);
            if (!IsValidNibblePermutation(bestPerm))
                return false;
            perm = bestPerm;
            return true;
        }

        private static long ScoreBoundaryFit(byte[] data, int srcOff, int dstOff)
        {
            long s = 0;
            // Compare plaintext byte/uint32 right before dstOff and right after dstOff+0x4000 against blk head & blk tail.
            if (dstOff >= 16)
            {
                byte before = data[dstOff - 1];
                byte head = data[srcOff];
                if (IsAsciiIdentChar(before) && IsAsciiIdentChar(head)) s += 50;
                else if (before == 0 && IsAsciiIdentChar(head)) s += 15;
                else if (IsAsciiIdentChar(before) ^ IsAsciiIdentChar(head)) s -= 25;

                uint uBefore = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(dstOff - 4, 4));
                uint uHead = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(srcOff, 4));
                if (uBefore < 0x100000 && uHead < 0x100000)
                {
                    long diff = (long)uHead - (long)uBefore;
                    if (diff >= -64 && diff <= 64) s += 20;
                    uint uBefore16 = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(dstOff - 16, 4));
                    if (uHead == uBefore16 + 1) s += 120;
                }
            }
            if (dstOff + PageBlockSize + 16 <= data.Length)
            {
                byte tail = data[srcOff + PageBlockSize - 1];
                byte after = data[dstOff + PageBlockSize];
                if (IsAsciiIdentChar(tail) && IsAsciiIdentChar(after)) s += 50;
                else if (tail == 0 && IsAsciiIdentChar(after)) s += 15;
                else if (IsAsciiIdentChar(tail) ^ IsAsciiIdentChar(after)) s -= 25;

                uint uTail = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(srcOff + PageBlockSize - 4, 4));
                uint uAfter = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(dstOff + PageBlockSize, 4));
                if (uTail < 0x100000 && uAfter < 0x100000)
                {
                    long diff = (long)uAfter - (long)uTail;
                    if (diff >= -64 && diff <= 64) s += 20;
                    uint uTail16 = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(srcOff + PageBlockSize - 16, 4));
                    if (uAfter == uTail16 + 1) s += 120;
                }
            }
            return s;
        }

        private static bool IsAsciiIdentChar(byte b)
        {
            return (b >= (byte)'A' && b <= (byte)'Z')
                || (b >= (byte)'a' && b <= (byte)'z')
                || (b >= (byte)'0' && b <= (byte)'9')
                || b == (byte)'_' || b == (byte)'.' || b == (byte)':';
        }

        private static int FindPatternReverse(byte[] haystack, byte[] needle)
        {
            int max = haystack.Length - needle.Length;
            for (int i = max; i >= 0; i--)
            {
                if (haystack[i] != needle[0]) continue;
                bool match = true;
                for (int j = 1; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }

        private static string ReadNullString(byte[] data, int offset, int maxLen)
        {
            int limit = Math.Min(data.Length, offset + maxLen);
            int end = offset;
            while (end < limit && data[end] != 0) end++;
            return Encoding.ASCII.GetString(data, offset, end - offset);
        }
    }
}
