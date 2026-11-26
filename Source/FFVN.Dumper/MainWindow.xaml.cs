// Source/FFVN.Dumper/MainWindow.xaml.cs
// C# / .NET 10 / Windows x64 / WPF controller for Free Fire VN IL2CPP Dumper
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Navigation;
using Microsoft.Win32;

namespace FfvnDumper
{
    public partial class MainWindow : Window
    {
        private static readonly string[] PackageExtensions = { ".xapk", ".apks", ".apk", ".zip" };
        private static readonly Brush DotReady = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#64748B"));
        private static readonly Brush DotRunning = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F59E0B"));
        private static readonly Brush DotSuccess = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#10B981"));
        private static readonly Brush DotError = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444"));
        private static readonly Brush DropBorderNormal = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1F2937"));
        private static readonly Brush DropBorderHighlight = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F97316"));

        private string? _lastRunDir;

        public MainWindow()
        {
            InitializeComponent();
            OutputTextBox.Text = Path.Combine(AppContext.BaseDirectory, "Output");
            PackageTextBox.Text = DetectDefaultPackage() ?? "";
        }

        private static string? DetectDefaultPackage()
        {
            string[] searchRoots =
            {
                AppContext.BaseDirectory,
                Directory.GetParent(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar))?.FullName ?? ""
            };

            foreach (var root in searchRoots.Where(r => !string.IsNullOrWhiteSpace(r) && Directory.Exists(r)).Distinct())
            {
                try
                {
                    var files = Directory.EnumerateFiles(root)
                        .Where(f => PackageExtensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase))
                        .OrderByDescending(f =>
                        {
                            string name = Path.GetFileName(f).ToLowerInvariant();
                            if (name.Contains("free") || name.Contains("ffvn") || name.Contains("garena.ff")) return 2;
                            return 1;
                        })
                        .ThenByDescending(File.GetLastWriteTimeUtc)
                        .ToList();
                    if (files.Count > 0)
                        return files[0];
                }
                catch
                {
                    // Ignore inaccessible directories.
                }
            }
            return null;
        }

        private void BrowsePackage_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Title = "Chọn gói APK / XAPK / APKS của Free Fire",
                Filter = "Android Packages (*.xapk;*.apk;*.apks;*.zip)|*.xapk;*.apk;*.apks;*.zip|All files (*.*)|*.*"
            };
            if (dlg.ShowDialog(this) == true)
            {
                PackageTextBox.Text = dlg.FileName;
            }
        }

        private void BrowseOutput_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFolderDialog
            {
                Title = "Chọn thư mục lưu kết quả dump"
            };
            if (Directory.Exists(OutputTextBox.Text))
            {
                dlg.InitialDirectory = OutputTextBox.Text;
            }
            if (dlg.ShowDialog(this) == true)
            {
                OutputTextBox.Text = dlg.FolderName;
            }
        }

        private void ClearLog_Click(object sender, RoutedEventArgs e)
        {
            LogTextBox.Clear();
            TimerText.Text = "";
        }

        private async void Start_Click(object sender, RoutedEventArgs e)
        {
            string pkg = PackageTextBox.Text.Trim();
            string outRoot = OutputTextBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(pkg) || !File.Exists(pkg))
            {
                MessageBox.Show(this, "Vui lòng chọn file .xapk / .apk / .apks hợp lệ.", "Thiếu tệp đầu vào", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (string.IsNullOrWhiteSpace(outRoot))
            {
                outRoot = Path.Combine(AppContext.BaseDirectory, "Output");
                OutputTextBox.Text = outRoot;
            }

            SetBusyState(true);
            LogTextBox.Clear();
            ChipAbi.Visibility = Visibility.Collapsed;
            ChipCrypto.Visibility = Visibility.Collapsed;
            ChipStats.Visibility = Visibility.Collapsed;
            ProgressBar.Value = 5;
            StatusDot.Fill = DotRunning;
            StatusText.Text = "Đang giải nén và giải mã .rodata...";

            var sw = Stopwatch.StartNew();
            try
            {
                var summary = await Task.Run(() =>
                    Workflow.RunPackage(
                        pkg,
                        outRoot,
                        msg => Dispatcher.Invoke(() =>
                        {
                            LogTextBox.AppendText(msg + Environment.NewLine);
                            LogTextBox.ScrollToEnd();
                            TimerText.Text = $"{sw.Elapsed.TotalSeconds:0.0}s";
                        }),
                        pct => Dispatcher.Invoke(() => ProgressBar.Value = pct)));

                sw.Stop();
                _lastRunDir = summary.RunDirectory;
                ProgressBar.Value = 100;
                StatusDot.Fill = DotSuccess;
                StatusText.Text = $"Hoàn tất ({sw.Elapsed.TotalSeconds:0.0}s) — {summary.DummyDllCount} DummyDll, {summary.TypeCount:N0} types.";
                TimerText.Text = $"Hoàn tất trong {sw.Elapsed.TotalSeconds:0.0}s";

                ChipAbiText.Text = $"ABI: {summary.Abi} · v{summary.MetadataVersion}";
                ChipAbi.Visibility = Visibility.Visible;

                if (summary.WasPacked && summary.Seed.HasValue && summary.PermutationKey.HasValue)
                {
                    ChipCryptoText.Text = $"Seed: 0x{summary.Seed.Value:x8} · Perm: 0x{summary.PermutationKey.Value:x8}";
                    ChipCrypto.Visibility = Visibility.Visible;
                }

                ChipStatsText.Text = $"{summary.MethodCount:N0} methods · {summary.DummyDllCount} DLL";
                ChipStats.Visibility = Visibility.Visible;
            }
            catch (Exception ex)
            {
                sw.Stop();
                ProgressBar.Value = 0;
                StatusDot.Fill = DotError;
                StatusText.Text = "Lỗi khi dump.";
                TimerText.Text = $"Thất bại sau {sw.Elapsed.TotalSeconds:0.0}s";
                LogTextBox.AppendText($"[FATAL] {ex}" + Environment.NewLine);
                LogTextBox.ScrollToEnd();
                MessageBox.Show(this, ex.Message, "Dump thất bại", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                SetBusyState(false);
            }
        }

        private void SetBusyState(bool busy)
        {
            StartButton.IsEnabled = !busy;
            BrowsePackageButton.IsEnabled = !busy;
            BrowseOutputButton.IsEnabled = !busy;
            ClearLogButton.IsEnabled = !busy;
        }

        private void OpenOutput_Click(object sender, RoutedEventArgs e)
        {
            string target = !string.IsNullOrWhiteSpace(_lastRunDir) && Directory.Exists(_lastRunDir)
                ? _lastRunDir
                : OutputTextBox.Text.Trim();
            if (!string.IsNullOrWhiteSpace(target) && Directory.Exists(target))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{target}\"") { UseShellExecute = true });
            }
            else
            {
                MessageBox.Show(this, "Thư mục kết quả chưa tồn tại.", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void Window_DragOver(object sender, DragEventArgs e)
        {
            if (GetDroppedPackage(e.Data) != null)
            {
                e.Effects = DragDropEffects.Copy;
                DropCard.BorderBrush = DropBorderHighlight;
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }
            e.Handled = true;
        }

        private void Window_DragLeave(object sender, DragEventArgs e)
        {
            DropCard.BorderBrush = DropBorderNormal;
        }

        private void Window_Drop(object sender, DragEventArgs e)
        {
            DropCard.BorderBrush = DropBorderNormal;
            string? dropped = GetDroppedPackage(e.Data);
            if (dropped != null)
            {
                PackageTextBox.Text = dropped;
                StatusDot.Fill = DotReady;
                StatusText.Text = $"Đã nạp: {Path.GetFileName(dropped)}";
            }
        }

        private static string? GetDroppedPackage(IDataObject data)
        {
            if (!data.GetDataPresent(DataFormats.FileDrop))
                return null;
            if (data.GetData(DataFormats.FileDrop) is not string[] files || files.Length == 0)
                return null;
            return files.FirstOrDefault(f =>
                File.Exists(f) &&
                PackageExtensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase));
        }

        private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
            }
            catch
            {
                // Ignore browser launch failures.
            }
            e.Handled = true;
        }
    }
}
