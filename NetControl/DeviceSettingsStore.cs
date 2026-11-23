using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace NetControl
{
    public class DeviceProfile
    {
        public int BandwidthLimitKb { get; set; }
        public bool Redirect { get; set; }
        public bool Block { get; set; }
        public int DataQuotaMb { get; set; }
    }

    /// <summary>
    /// Menyimpan pengaturan kontrol perangkat (Batas KB/s, status Spoof/Blokir, dan Kuota Data MB)
    /// secara permanen berdasarkan MAC Address.
    /// </summary>
    public static class DeviceSettingsStore
    {
        private static readonly object _lock = new();
        private static readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = true };
        private static Dictionary<string, DeviceProfile> _cache;

        private static string PrimaryFilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetControl",
            "device_settings.json");

        private static string FallbackFilePath => Path.Combine(
            AppContext.BaseDirectory,
            "device_settings.json");

        public static DeviceProfile GetProfile(string mac)
        {
            string normalized = NormalizeMac(mac);
            if (string.IsNullOrEmpty(normalized)) return null;

            lock (_lock)
            {
                EnsureLoadedLocked();
                return _cache.TryGetValue(normalized, out var profile) ? CloneProfile(profile) : null;
            }
        }

        public static void SaveProfile(string mac, int bandwidthLimitKb, bool redirect, bool block, int dataQuotaMb)
        {
            string normalized = NormalizeMac(mac);
            if (string.IsNullOrEmpty(normalized)) return;

            int clampedBw = Math.Max(0, bandwidthLimitKb);
            int clampedQuota = Math.Max(0, dataQuotaMb);
            bool effectiveRedirect = block ? false : redirect;

            lock (_lock)
            {
                EnsureLoadedLocked();

                if (clampedBw == 0 && !effectiveRedirect && !block && clampedQuota == 0)
                {
                    if (_cache.Remove(normalized))
                    {
                        SaveLocked();
                    }
                    return;
                }

                _cache[normalized] = new DeviceProfile
                {
                    BandwidthLimitKb = clampedBw,
                    Redirect = effectiveRedirect,
                    Block = block,
                    DataQuotaMb = clampedQuota
                };
                SaveLocked();
            }
        }

        public static void RemoveProfile(string mac)
        {
            string normalized = NormalizeMac(mac);
            if (string.IsNullOrEmpty(normalized)) return;

            lock (_lock)
            {
                EnsureLoadedLocked();
                if (_cache.Remove(normalized))
                {
                    SaveLocked();
                }
            }
        }

        public static IReadOnlyDictionary<string, DeviceProfile> GetAllProfiles()
        {
            lock (_lock)
            {
                EnsureLoadedLocked();
                var copy = new Dictionary<string, DeviceProfile>(_cache.Count, StringComparer.OrdinalIgnoreCase);
                foreach (var kv in _cache)
                {
                    copy[kv.Key] = CloneProfile(kv.Value);
                }
                return copy;
            }
        }

        private static DeviceProfile CloneProfile(DeviceProfile p) => new()
        {
            BandwidthLimitKb = Math.Max(0, p.BandwidthLimitKb),
            Redirect = p.Block ? false : p.Redirect,
            Block = p.Block,
            DataQuotaMb = Math.Max(0, p.DataQuotaMb)
        };

        private static string NormalizeMac(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac) || mac.Trim() == "—") return string.Empty;
            return mac.Trim().ToUpperInvariant();
        }

        private static void EnsureLoadedLocked()
        {
            if (_cache != null) return;

            _cache = new Dictionary<string, DeviceProfile>(StringComparer.OrdinalIgnoreCase);

            string pathToRead = File.Exists(PrimaryFilePath)
                ? PrimaryFilePath
                : (File.Exists(FallbackFilePath) ? FallbackFilePath : null);

            if (pathToRead == null) return;

            try
            {
                string json = File.ReadAllText(pathToRead);
                var loaded = JsonSerializer.Deserialize<Dictionary<string, DeviceProfile>>(json);
                if (loaded != null)
                {
                    foreach (var kv in loaded)
                    {
                        string key = NormalizeMac(kv.Key);
                        if (string.IsNullOrEmpty(key) || kv.Value == null) continue;

                        var cloned = CloneProfile(kv.Value);
                        if (cloned.BandwidthLimitKb > 0 || cloned.Redirect || cloned.Block || cloned.DataQuotaMb > 0)
                        {
                            _cache[key] = cloned;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SETTINGS STORE] Gagal membaca pengaturan perangkat: {ex.Message}");
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
                Console.WriteLine($"[SETTINGS STORE] Gagal menyimpan ke {PrimaryFilePath}: {ex.Message}");
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
