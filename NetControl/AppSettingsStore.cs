using System;
using System.IO;
using System.Text.Json;

namespace NetControl
{
    public class AppSettings
    {
        public bool AutoStartWithWindows { get; set; } = false;
        public bool StartMinimizedToTray { get; set; } = true;
        public bool MinimizeToTray { get; set; } = true;
        public bool AutoScanOnStartup { get; set; } = false;
        public bool AutoSpoofAfterScan { get; set; } = false;
        public bool OnlyAutoSpoofOnHomeRouter { get; set; } = true;
        public string HomeRouterMac { get; set; } = string.Empty;
        public string HomeRouterLabel { get; set; } = string.Empty;
        public string PreferredInterfaceName { get; set; } = string.Empty;
        public double WindowWidth { get; set; } = 0;
        public double WindowHeight { get; set; } = 0;
        public bool WindowMaximized { get; set; } = false;
    }

    /// <summary>
    /// Menyimpan dan memuat preferensi startup/autostart aplikasi dan pengaman MAC Router rumah.
    /// </summary>
    public static class AppSettingsStore
    {
        private static readonly object _lock = new();
        private static readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = true };
        private static AppSettings _cache;

        private static string PrimaryFilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetControl",
            "app_settings.json");

        private static string FallbackFilePath => Path.Combine(
            AppContext.BaseDirectory,
            "app_settings.json");

        public static AppSettings GetSettings()
        {
            lock (_lock)
            {
                EnsureLoadedLocked();
                return CloneSettings(_cache);
            }
        }

        public static void SaveSettings(AppSettings settings)
        {
            if (settings == null) return;

            lock (_lock)
            {
                _cache = CloneSettings(settings);
                SaveLocked();
            }
        }

        public static string NormalizeMac(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return string.Empty;
            string trimmed = mac.Trim();
            if (trimmed == "—") return string.Empty;

            Span<char> hex = stackalloc char[12];
            int count = 0;
            for (int i = 0; i < trimmed.Length; i++)
            {
                char c = trimmed[i];
                if (c == ':' || c == '-' || char.IsWhiteSpace(c)) continue;
                if (!Uri.IsHexDigit(c)) return trimmed.ToUpperInvariant();
                if (count < 12)
                {
                    hex[count++] = char.ToUpperInvariant(c);
                }
                else
                {
                    return trimmed.ToUpperInvariant();
                }
            }

            if (count == 12)
            {
                return $"{hex[0]}{hex[1]}:{hex[2]}{hex[3]}:{hex[4]}{hex[5]}:{hex[6]}{hex[7]}:{hex[8]}{hex[9]}:{hex[10]}{hex[11]}";
            }

            return trimmed.ToUpperInvariant();
        }

        public static string FormatMacBytes(byte[] macBytes)
        {
            if (macBytes == null || macBytes.Length != 6) return string.Empty;
            return $"{macBytes[0]:X2}:{macBytes[1]:X2}:{macBytes[2]:X2}:{macBytes[3]:X2}:{macBytes[4]:X2}:{macBytes[5]:X2}";
        }

        public static bool ShouldAllowAutoSpoof(AppSettings settings, string detectedRouterMac, out string skipReason)
        {
            if (settings == null || !settings.AutoSpoofAfterScan)
            {
                skipReason = "Auto-Spoof nonaktif.";
                return false;
            }

            string normDetected = NormalizeMac(detectedRouterMac);
            if (string.IsNullOrEmpty(normDetected))
            {
                skipReason = "MAC router belum terdeteksi.";
                return false;
            }

            if (settings.OnlyAutoSpoofOnHomeRouter)
            {
                string normHome = NormalizeMac(settings.HomeRouterMac);
                if (string.IsNullOrEmpty(normHome))
                {
                    skipReason = "MAC Router rumah belum disimpan (klik 'Pakai Router Ini' di tab Autostart).";
                    return false;
                }

                if (!string.Equals(normHome, normDetected, StringComparison.OrdinalIgnoreCase))
                {
                    skipReason = $"Bukan jaringan rumah (router terdeteksi {normDetected}) — Auto-Spoof dilewati demi keamanan.";
                    return false;
                }
            }

            skipReason = string.Empty;
            return true;
        }

        public static bool SanitizeWindowBounds(
            double width,
            double height,
            double minWidth,
            double minHeight,
            out double safeWidth,
            out double safeHeight)
        {
            if (double.IsNaN(width) || double.IsInfinity(width) ||
                double.IsNaN(height) || double.IsInfinity(height) ||
                width < minWidth || width > 7680 ||
                height < minHeight || height > 4320)
            {
                safeWidth = 0;
                safeHeight = 0;
                return false;
            }

            safeWidth = Math.Round(width);
            safeHeight = Math.Round(height);
            return true;
        }

        private static AppSettings CloneSettings(AppSettings s) => new()
        {
            AutoStartWithWindows = s.AutoStartWithWindows,
            StartMinimizedToTray = s.StartMinimizedToTray,
            MinimizeToTray = s.MinimizeToTray,
            AutoScanOnStartup = s.AutoScanOnStartup,
            AutoSpoofAfterScan = s.AutoScanOnStartup && s.AutoSpoofAfterScan,
            OnlyAutoSpoofOnHomeRouter = s.OnlyAutoSpoofOnHomeRouter,
            HomeRouterMac = NormalizeMac(s.HomeRouterMac),
            HomeRouterLabel = s.HomeRouterLabel?.Trim() ?? string.Empty,
            PreferredInterfaceName = s.PreferredInterfaceName?.Trim() ?? string.Empty,
            WindowWidth = (!double.IsNaN(s.WindowWidth) && !double.IsInfinity(s.WindowWidth) && s.WindowWidth > 0) ? Math.Round(s.WindowWidth) : 0,
            WindowHeight = (!double.IsNaN(s.WindowHeight) && !double.IsInfinity(s.WindowHeight) && s.WindowHeight > 0) ? Math.Round(s.WindowHeight) : 0,
            WindowMaximized = s.WindowMaximized
        };

        private static void EnsureLoadedLocked()
        {
            if (_cache != null) return;

            _cache = new AppSettings();

            string pathToRead = File.Exists(PrimaryFilePath)
                ? PrimaryFilePath
                : (File.Exists(FallbackFilePath) ? FallbackFilePath : null);

            if (pathToRead == null) return;

            try
            {
                string json = File.ReadAllText(pathToRead);
                var loaded = JsonSerializer.Deserialize<AppSettings>(json);
                if (loaded != null)
                {
                    _cache = CloneSettings(loaded);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[APP SETTINGS] Gagal membaca pengaturan aplikasi: {ex.Message}");
            }
        }

        private static void SaveLocked()
        {
            string json = JsonSerializer.Serialize(_cache, _jsonOptions);

            try
            {
                string dir = Path.GetDirectoryName(PrimaryFilePath);
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                File.WriteAllText(PrimaryFilePath, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[APP SETTINGS] Gagal menyimpan ke {PrimaryFilePath}: {ex.Message}");
            }

            try
            {
                File.WriteAllText(FallbackFilePath, json);
            }
            catch
            {
                // Fallback copy is best-effort
            }
        }
    }
}
