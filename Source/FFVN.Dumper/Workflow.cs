// Source/FFVN.Dumper/Workflow.cs
// C# / .NET 10 / Windows x64 / Package extraction, Free Fire .rodata static unpack, IL2CPP dump and verification
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Il2CppDumper;

namespace FfvnDumper
{
    public sealed class DumpSummary
    {
        public string RunDirectory { get; init; } = "";
        public string PackagePath { get; init; } = "";
        public string Abi { get; init; } = "";
        public double MetadataVersion { get; init; }
        public int TypeCount { get; init; }
        public int MethodCount { get; init; }
        public int ImageCount { get; init; }
        public int DummyDllCount { get; init; }
        public bool WasPacked { get; init; }
        public uint? Seed { get; init; }
        public uint? PermutationKey { get; init; }
    }

    internal sealed class PackageArtifacts
    {
        public byte[]? Il2CppBytes;
        public string Il2CppEntry = "";
        public string Abi = "";
        public byte[]? AnortBytes;
        public string AnortEntry = "";
        public byte[]? MetadataBytes;
        public string MetadataEntry = "";
    }

    public static class Workflow
    {
        private const uint ElfMagic = 0x464C457Fu;
        private const uint MetadataMagic = 0xFAB11BAFu;
        private static readonly JsonSerializerOptions JsonIndented = new() { WriteIndented = true };

        public static DumpSummary RunPackage(
            string packagePath,
            string outputRoot,
            Action<string> log,
            Action<double>? progress = null)
        {
            if (string.IsNullOrWhiteSpace(packagePath) || !File.Exists(packagePath))
                throw new FileNotFoundException("Không tìm thấy gói APK/XAPK.", packagePath);

            string pkgName = SanitizeName(Path.GetFileNameWithoutExtension(packagePath));
            string runDir = CreateRunDirectory(outputRoot, pkgName);
            string inputDir = Path.Combine(runDir, "Input");
            Directory.CreateDirectory(inputDir);

            var logLines = new List<string>();
            void Emit(string msg)
            {
                string line = $"[{DateTime.Now:HH:mm:ss}] {msg}";
                logLines.Add(line);
                log(line);
            }

            try
            {
                Emit($"Mở gói: {packagePath}");
                progress?.Invoke(10);

                var artifacts = ExtractFromPackage(packagePath, Emit);
                if (artifacts.Il2CppBytes == null)
                    throw new InvalidDataException("Không tìm thấy libil2cpp.so trong gói.");
                if (artifacts.MetadataBytes == null)
                    throw new InvalidDataException("Không tìm thấy global-metadata.dat trong gói.");

                Emit($"Đã trích {artifacts.Il2CppEntry} ({artifacts.Il2CppBytes.Length:N0} bytes, ABI={artifacts.Abi})");
                if (artifacts.AnortBytes != null)
                {
                    Emit($"Đã trích {artifacts.AnortEntry} ({artifacts.AnortBytes.Length:N0} bytes)");
                    File.WriteAllBytes(Path.Combine(inputDir, "libanort.so"), artifacts.AnortBytes);
                }
                Emit($"Đã trích {artifacts.MetadataEntry} ({artifacts.MetadataBytes.Length:N0} bytes)");

                progress?.Invoke(25);
                return ExecuteCoreDump(
                    packagePath,
                    artifacts.Abi,
                    artifacts.Il2CppBytes,
                    artifacts.AnortBytes,
                    artifacts.MetadataBytes,
                    runDir,
                    inputDir,
                    Emit,
                    logLines,
                    progress);
            }
            catch
            {
                File.WriteAllLines(Path.Combine(runDir, "dump.log"), logLines, Encoding.UTF8);
                throw;
            }
        }

        public static DumpSummary RunPair(
            string il2cppPath,
            string metadataPath,
            string outputRoot,
            Action<string> log,
            Action<double>? progress = null)
        {
            if (!File.Exists(il2cppPath))
                throw new FileNotFoundException("Không tìm thấy libil2cpp.so.", il2cppPath);
            if (!File.Exists(metadataPath))
                throw new FileNotFoundException("Không tìm thấy global-metadata.dat.", metadataPath);

            string runDir = CreateRunDirectory(outputRoot, "FFVN_Binary");
            string inputDir = Path.Combine(runDir, "Input");
            Directory.CreateDirectory(inputDir);

            var logLines = new List<string>();
            void Emit(string msg)
            {
                string line = $"[{DateTime.Now:HH:mm:ss}] {msg}";
                logLines.Add(line);
                log(line);
            }

            try
            {
                byte[] il2cppBytes = File.ReadAllBytes(il2cppPath);
                byte[] metadataBytes = File.ReadAllBytes(metadataPath);
                string siblingAnort = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(il2cppPath)) ?? "", "libanort.so");
                byte[]? anortBytes = File.Exists(siblingAnort) ? File.ReadAllBytes(siblingAnort) : null;
                if (anortBytes != null)
                {
                    File.WriteAllBytes(Path.Combine(inputDir, "libanort.so"), anortBytes);
                }
                string abi = il2cppBytes.Length >= 5 && il2cppBytes[4] == 2 ? "arm64-v8a" : "armeabi-v7a";

                return ExecuteCoreDump(
                    il2cppPath,
                    abi,
                    il2cppBytes,
                    anortBytes,
                    metadataBytes,
                    runDir,
                    inputDir,
                    Emit,
                    logLines,
                    progress);
            }
            catch
            {
                File.WriteAllLines(Path.Combine(runDir, "dump.log"), logLines, Encoding.UTF8);
                throw;
            }
        }

        private static DumpSummary ExecuteCoreDump(
            string sourcePath,
            string abi,
            byte[] il2cppBytes,
            byte[]? anortBytes,
            byte[] metadataBytes,
            string runDir,
            string inputDir,
            Action<string> emit,
            List<string> logLines,
            Action<double>? progress)
        {
            if (il2cppBytes.Length < 16 || BinaryPrimitives.ReadUInt32LittleEndian(il2cppBytes) != ElfMagic)
                throw new InvalidDataException("libil2cpp.so không có header ELF hợp lệ.");
            if (metadataBytes.Length < 16 || BinaryPrimitives.ReadUInt32LittleEndian(metadataBytes) != MetadataMagic)
                throw new InvalidDataException("global-metadata.dat không có magic 0xFAB11BAF hợp lệ.");

            double metaVersion = BinaryPrimitives.ReadInt32LittleEndian(metadataBytes.AsSpan(4, 4));
            string il2cppOutPath = Path.Combine(inputDir, "libil2cpp.so");
            string metadataOutPath = Path.Combine(inputDir, "global-metadata.dat");
            File.WriteAllBytes(metadataOutPath, metadataBytes);

            FreeFireUnpackResult? unpackResult = null;
            byte[] workingElfBytes = il2cppBytes;
            if (FreeFireUnpacker.IsPacked(il2cppBytes))
            {
                emit("Phát hiện stub bảo vệ Free Fire (#U#I#N#F#P#A#F#); đang lưu bản gốc và giải mã .rodata...");
                File.WriteAllBytes(Path.Combine(inputDir, "libil2cpp.original.so"), il2cppBytes);
                unpackResult = FreeFireUnpacker.Unpack(il2cppBytes, anortBytes);
                workingElfBytes = unpackResult.UnpackedBytes;
                emit($"Giải mã .rodata hoàn tất: off=0x{unpackResult.RodataOffset:X}, size=0x{unpackResult.RodataSize:X}, seed=0x{unpackResult.Seed:x8}, xor=0x{unpackResult.XorKey:x2}, perm=0x{unpackResult.PermutationKey:x8} ({unpackResult.PermSource})");
            }
            else
            {
                emit("libil2cpp.so không bị mã hóa stub hoặc đã được giải mã sẵn.");
            }
            File.WriteAllBytes(il2cppOutPath, workingElfBytes);
            progress?.Invoke(45);

            var config = LoadConfig();
            bool sawDumpFailure = false;
            var prevWriter = Logger.Writer;
            Logger.Writer = (text, _) =>
            {
                string clean = text?.TrimEnd() ?? "";
                if (clean.Length == 0) return;
                if (clean.Contains("Some errors in dumping", StringComparison.OrdinalIgnoreCase) ||
                    clean.Contains("There was an error", StringComparison.OrdinalIgnoreCase) ||
                    clean.Contains("Index was outside the bounds", StringComparison.OrdinalIgnoreCase))
                {
                    sawDumpFailure = true;
                }
                emit("[core] " + clean);
            };

            try
            {
                var options = new DumpOptions
                {
                    Config = config,
                    WorkerThreads = Environment.ProcessorCount,
                    ScriptsDirectory = AppContext.BaseDirectory,
                    Abi = abi,
                    ExtractBinary = false,
                    ExtractMetadata = false
                };

                var runner = new DumpRunner(options, null);
                emit("Đang chạy Il2CppDumper...");
                bool ok = runner.Run(il2cppOutPath, metadataOutPath, runDir);
                if (!ok)
                    throw new InvalidOperationException("DumpRunner báo thất bại.");
            }
            finally
            {
                Logger.Writer = prevWriter;
            }

            if (sawDumpFailure)
                throw new InvalidDataException("Phát hiện lỗi chỉ mục trong quá trình giải xuất IL2CPP.");

            progress?.Invoke(85);
            ValidateOutputs(runDir, out int dllCount, out int methodCount, out int typeCount, out int imageCount);
            emit($"Kiểm tra kết quả: {dllCount} DLL trong DummyDll/, {typeCount:N0} types, {methodCount:N0} methods.");

            var resultPayload = new
            {
                PackagePath = sourcePath,
                Abi = abi,
                Engine = "Unity IL2CPP",
                MetadataVersion = metaVersion,
                TypeCount = typeCount,
                MethodCount = methodCount,
                ImageCount = imageCount,
                DummyDllCount = dllCount,
                FreeFireUnpack = unpackResult == null ? null : new
                {
                    Base64Key = unpackResult.Base64Key,
                    Seed = $"0x{unpackResult.Seed:x8}",
                    XorKey = $"0x{unpackResult.XorKey:x2}",
                    PermutationKey = $"0x{unpackResult.PermutationKey:x8}",
                    PermutationSource = unpackResult.PermSource,
                    RodataOffset = $"0x{unpackResult.RodataOffset:x}",
                    RodataSize = $"0x{unpackResult.RodataSize:x}",
                    FullBlocks = unpackResult.FullBlockCount,
                    TailXorBytes = unpackResult.TailXorBytes
                },
                Files = BuildFileHashes(runDir)
            };

            File.WriteAllText(Path.Combine(runDir, "result.json"), JsonSerializer.Serialize(resultPayload, JsonIndented), Encoding.UTF8);
            emit("Hoàn tất.");
            File.WriteAllLines(Path.Combine(runDir, "dump.log"), logLines, Encoding.UTF8);
            progress?.Invoke(100);

            return new DumpSummary
            {
                RunDirectory = runDir,
                PackagePath = sourcePath,
                Abi = abi,
                MetadataVersion = metaVersion,
                TypeCount = typeCount,
                MethodCount = methodCount,
                ImageCount = imageCount,
                DummyDllCount = dllCount,
                WasPacked = unpackResult != null,
                Seed = unpackResult?.Seed,
                PermutationKey = unpackResult?.PermutationKey
            };
        }

        private static Config LoadConfig()
        {
            string cfgPath = Path.Combine(AppContext.BaseDirectory, "config.json");
            if (File.Exists(cfgPath))
            {
                try
                {
                    var cfg = JsonSerializer.Deserialize<Config>(File.ReadAllText(cfgPath));
                    if (cfg != null) return cfg;
                }
                catch
                {
                    // Fallback to defaults if malformed.
                }
            }
            return new Config();
        }

        private static void ValidateOutputs(string runDir, out int dllCount, out int methodCount, out int typeCount, out int imageCount)
        {
            string dumpCs = Path.Combine(runDir, "dump.cs");
            string scriptJson = Path.Combine(runDir, "script.json");
            string headerPath = Path.Combine(runDir, "il2cpp.h");
            string strLitJson = Path.Combine(runDir, "stringliteral.json");
            string dummyDir = Path.Combine(runDir, "DummyDll");

            if (!File.Exists(dumpCs) || new FileInfo(dumpCs).Length < 1024)
                throw new InvalidDataException("dump.cs bị thiếu hoặc rỗng.");
            if (!File.Exists(scriptJson) || new FileInfo(scriptJson).Length < 1024)
                throw new InvalidDataException("script.json bị thiếu hoặc rỗng.");
            if (!File.Exists(headerPath) || new FileInfo(headerPath).Length < 1024)
                throw new InvalidDataException("il2cpp.h bị thiếu hoặc rỗng.");
            if (!File.Exists(strLitJson))
                throw new InvalidDataException("stringliteral.json bị thiếu.");
            if (!Directory.Exists(dummyDir))
                throw new InvalidDataException("Thư mục DummyDll bị thiếu.");

            var dllFiles = Directory.GetFiles(dummyDir, "*.dll");
            dllCount = dllFiles.Length;
            if (dllCount == 0)
                throw new InvalidDataException("DummyDll không có assembly .dll nào.");

            imageCount = dllCount;
            typeCount = 0;
            methodCount = 0;
            using (var doc = JsonDocument.Parse(File.ReadAllText(scriptJson)))
            {
                if (doc.RootElement.TryGetProperty("ScriptMethod", out var methods))
                    methodCount = methods.GetArrayLength();
            }

            // Count TypeDefIndex comments in dump.cs quickly without allocating huge strings.
            int tCount = 0;
            foreach (var line in File.ReadLines(dumpCs))
            {
                if (line.Contains("// TypeDefIndex:", StringComparison.Ordinal))
                    tCount++;
            }
            typeCount = tCount;
        }

        private static Dictionary<string, string> BuildFileHashes(string runDir)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string[] tracked =
            {
                "dump.cs",
                "il2cpp.h",
                "script.json",
                "stringliteral.json",
                "ida_with_struct.py",
                "ida_with_struct_py3.py",
                Path.Combine("Input", "libil2cpp.so"),
                Path.Combine("Input", "libil2cpp.original.so"),
                Path.Combine("Input", "libanort.so"),
                Path.Combine("Input", "global-metadata.dat")
            };
            foreach (var rel in tracked)
            {
                string full = Path.Combine(runDir, rel);
                if (!File.Exists(full)) continue;
                using var fs = File.OpenRead(full);
                dict[rel.Replace('\\', '/')] = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
            }
            return dict;
        }

        private static PackageArtifacts ExtractFromPackage(string packagePath, Action<string> emit)
        {
            var artifacts = new PackageArtifacts();
            var anortByAbi = new Dictionary<string, (string entry, byte[] bytes)>(StringComparer.OrdinalIgnoreCase);
            var il2cppByAbi = new Dictionary<string, (string entry, byte[] bytes)>(StringComparer.OrdinalIgnoreCase);

            using (var fs = File.OpenRead(packagePath))
            using (var archive = new ZipArchive(fs, ZipArchiveMode.Read))
            {
                ScanZipArchive(archive, "", depth: 0, il2cppByAbi, anortByAbi, artifacts, emit);
            }

            string[] abiPriority = { "arm64-v8a", "armeabi-v7a", "x86_64", "x86" };
            foreach (var abi in abiPriority)
            {
                if (il2cppByAbi.TryGetValue(abi, out var hit))
                {
                    artifacts.Abi = abi;
                    artifacts.Il2CppEntry = hit.entry;
                    artifacts.Il2CppBytes = hit.bytes;
                    if (anortByAbi.TryGetValue(abi, out var anortHit))
                    {
                        artifacts.AnortEntry = anortHit.entry;
                        artifacts.AnortBytes = anortHit.bytes;
                    }
                    break;
                }
            }

            if (artifacts.Il2CppBytes == null && il2cppByAbi.Count > 0)
            {
                var first = il2cppByAbi.First();
                artifacts.Abi = first.Key;
                artifacts.Il2CppEntry = first.Value.entry;
                artifacts.Il2CppBytes = first.Value.bytes;
                if (anortByAbi.TryGetValue(first.Key, out var anortHit))
                {
                    artifacts.AnortEntry = anortHit.entry;
                    artifacts.AnortBytes = anortHit.bytes;
                }
            }

            return artifacts;
        }

        private static void ScanZipArchive(
            ZipArchive archive,
            string prefix,
            int depth,
            Dictionary<string, (string entry, byte[] bytes)> il2cppByAbi,
            Dictionary<string, (string entry, byte[] bytes)> anortByAbi,
            PackageArtifacts artifacts,
            Action<string> emit)
        {
            foreach (var entry in archive.Entries)
            {
                string fullName = string.IsNullOrEmpty(prefix) ? entry.FullName : $"{prefix}!/{entry.FullName}";
                string norm = entry.FullName.Replace('\\', '/');

                if (norm.EndsWith("/libil2cpp.so", StringComparison.OrdinalIgnoreCase) ||
                    norm.Equals("libil2cpp.so", StringComparison.OrdinalIgnoreCase))
                {
                    string abi = ExtractAbi(norm);
                    if (!il2cppByAbi.ContainsKey(abi))
                    {
                        il2cppByAbi[abi] = (fullName, ReadEntryBytes(entry));
                    }
                }
                else if (norm.EndsWith("/libanort.so", StringComparison.OrdinalIgnoreCase) ||
                         norm.Equals("libanort.so", StringComparison.OrdinalIgnoreCase))
                {
                    string abi = ExtractAbi(norm);
                    if (!anortByAbi.ContainsKey(abi))
                    {
                        anortByAbi[abi] = (fullName, ReadEntryBytes(entry));
                    }
                }
                else if (artifacts.MetadataBytes == null &&
                         (norm.Equals("assets/bin/Data/Managed/Metadata/global-metadata.dat", StringComparison.OrdinalIgnoreCase) ||
                          norm.Equals("assets/AssetsData/Metadata/global-metadata.dat", StringComparison.OrdinalIgnoreCase) ||
                          norm.EndsWith("/global-metadata.dat", StringComparison.OrdinalIgnoreCase) ||
                          norm.Equals("global-metadata.dat", StringComparison.OrdinalIgnoreCase)))
                {
                    artifacts.MetadataEntry = fullName;
                    artifacts.MetadataBytes = ReadEntryBytes(entry);
                }
                else if (depth < 2 && entry.Length > 0 && entry.Length < 1024L * 1024L * 1024L &&
                         (norm.EndsWith(".apk", StringComparison.OrdinalIgnoreCase) ||
                          norm.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)))
                {
                    emit($"Quét gói con: {norm}");
                    using var ms = new MemoryStream((int)Math.Min(entry.Length, int.MaxValue));
                    using (var es = entry.Open())
                        es.CopyTo(ms);
                    ms.Position = 0;
                    using var nested = new ZipArchive(ms, ZipArchiveMode.Read);
                    ScanZipArchive(nested, fullName, depth + 1, il2cppByAbi, anortByAbi, artifacts, emit);
                }
            }
        }

        private static string ExtractAbi(string entryPath)
        {
            var m = Regex.Match(entryPath, @"(?:^|/)lib/([^/]+)/", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : "unknown";
        }

        private static byte[] ReadEntryBytes(ZipArchiveEntry entry)
        {
            using var ms = new MemoryStream(entry.Length > 0 && entry.Length < int.MaxValue ? (int)entry.Length : 0);
            using var s = entry.Open();
            s.CopyTo(ms);
            return ms.ToArray();
        }

        private static string CreateRunDirectory(string root, string label)
        {
            Directory.CreateDirectory(root);
            string suffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant();
            string dir = Path.Combine(root, $"{label}_{DateTime.Now:yyyyMMdd_HHmmss}_{suffix}");
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static string SanitizeName(string name)
        {
            var invalid = Path.GetInvalidFileNameChars();
            var sb = new StringBuilder(name.Length);
            foreach (char c in name)
                sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
            return sb.Length > 0 ? sb.ToString() : "Package";
        }
    }
}
