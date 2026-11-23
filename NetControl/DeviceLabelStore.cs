using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace NetControl
{
    /// <summary>
    /// Menyimpan dan memuat label perangkat kustom secara permanen berdasarkan MAC Address.
    /// Label dapat diubah atau dihapus kapan saja melalui antarmuka.
    /// </summary>
    public static class DeviceLabelStore
    {
        private static readonly object _lock = new();
        private static readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = true };
        private static Dictionary<string, string> _cache;

        private static string PrimaryFilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetControl",
            "device_labels.json");

        private static string FallbackFilePath => Path.Combine(
            AppContext.BaseDirectory,
            "device_labels.json");

        public static string GetLabel(string mac)
        {
            string normalized = NormalizeMac(mac);
            if (string.IsNullOrEmpty(normalized)) return null;

            lock (_lock)
            {
                EnsureLoadedLocked();
                return _cache.TryGetValue(normalized, out string label) ? label : null;
            }
        }

        public static void SetLabel(string mac, string label)
        {
            string normalized = NormalizeMac(mac);
            if (string.IsNullOrEmpty(normalized)) return;

            lock (_lock)
            {
                EnsureLoadedLocked();

                string trimmed = label?.Trim();
                if (string.IsNullOrWhiteSpace(trimmed))
                {
                    _cache.Remove(normalized);
                }
                else
                {
                    _cache[normalized] = trimmed;
                }

                SaveLocked();
            }
        }

        private static string NormalizeMac(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac) || mac.Trim() == "—") return string.Empty;
            return mac.Trim().ToUpperInvariant();
        }

        private static void EnsureLoadedLocked()
        {
            if (_cache != null) return;

            _cache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            string pathToRead = File.Exists(PrimaryFilePath)
                ? PrimaryFilePath
                : (File.Exists(FallbackFilePath) ? FallbackFilePath : null);

            if (pathToRead == null) return;

            try
            {
                string json = File.ReadAllText(pathToRead);
                var loaded = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (loaded != null)
                {
                    foreach (var kv in loaded)
                    {
                        string key = NormalizeMac(kv.Key);
                        string val = kv.Value?.Trim();
                        if (!string.IsNullOrEmpty(key) && !string.IsNullOrWhiteSpace(val))
                        {
                            _cache[key] = val;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LABEL STORE] Gagal membaca label tersimpan: {ex.Message}");
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
                Console.WriteLine($"[LABEL STORE] Gagal menyimpan ke {PrimaryFilePath}: {ex.Message}");
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
