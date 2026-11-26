// Source/FFVN.Dumper/App.xaml.cs
// C# / .NET 10 / Windows x64 / WPF GUI + headless --dump CLI entrypoint for FFVN Dumper
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using Il2CppDumper;

namespace FfvnDumper
{
    public partial class App : Application
    {
        [DllImport("kernel32.dll")]
        private static extern bool AttachConsole(int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            if (e.Args.Length >= 2 && string.Equals(e.Args[0], "--dump", StringComparison.OrdinalIgnoreCase))
            {
                EnsureConsole();
                string packagePath = e.Args[1];
                string outputRoot = e.Args.Length >= 3 && !string.IsNullOrWhiteSpace(e.Args[2])
                    ? e.Args[2]
                    : Path.Combine(AppContext.BaseDirectory, "Output");

                try
                {
                    var result = Workflow.RunPackage(
                        packagePath,
                        outputRoot,
                        msg => Console.WriteLine(msg));
                    Console.WriteLine($"DUMP_SUCCESS {result.RunDirectory}");
                    Environment.Exit(0);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"ERROR: {ex.Message}");
                    Console.Error.WriteLine(ex.ToString());
                    Environment.Exit(1);
                }
                return;
            }

            if (e.Args.Length >= 3 && string.Equals(e.Args[0], "--binary", StringComparison.OrdinalIgnoreCase))
            {
                EnsureConsole();
                string il2cppPath = e.Args[1];
                string metadataPath = e.Args[2];
                string outputRoot = e.Args.Length >= 4 && !string.IsNullOrWhiteSpace(e.Args[3])
                    ? e.Args[3]
                    : Path.Combine(AppContext.BaseDirectory, "Output");

                try
                {
                    var result = Workflow.RunPair(
                        il2cppPath,
                        metadataPath,
                        outputRoot,
                        msg => Console.WriteLine(msg));
                    Console.WriteLine($"DUMP_SUCCESS {result.RunDirectory}");
                    Environment.Exit(0);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"ERROR: {ex.Message}");
                    Console.Error.WriteLine(ex.ToString());
                    Environment.Exit(1);
                }
                return;
            }

            var mainWindow = new MainWindow();
            mainWindow.Show();
        }

        private static void EnsureConsole()
        {
            if (!AttachConsole(-1))
            {
                AllocConsole();
            }
            try
            {
                Console.OutputEncoding = Encoding.UTF8;
            }
            catch
            {
                // Ignore redirected console handle errors.
            }
        }
    }
}
