using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetControl
{
    public enum ScheduleKind
    {
        Timer,
        DailyWindow
    }

    public enum ScheduleActionType
    {
        BlockInternet,
        BlockDomain
    }

    public class BlockScheduleRule
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N").Substring(0, 8);
        public ScheduleKind Kind { get; set; } = ScheduleKind.Timer;
        public ScheduleActionType ActionType { get; set; } = ScheduleActionType.BlockInternet;
        public string TargetMac { get; set; } = string.Empty;
        public string TargetLabel { get; set; } = "Semua";
        public string Domain { get; set; } = string.Empty;
        public DateTime? ExpiresAt { get; set; }
        public string StartTime { get; set; } = "19:00";
        public string EndTime { get; set; } = "21:00";
        public bool Enabled { get; set; } = true;

        [JsonIgnore]
        public bool IsActiveNow => BlockScheduleStore.IsRuleActiveAt(this, DateTime.Now);

        [JsonIgnore]
        public string ActionSummary => ActionType == ScheduleActionType.BlockInternet
            ? "Blokir Internet"
            : $"Blokir {Domain}";

        [JsonIgnore]
        public string TargetDisplay => string.IsNullOrWhiteSpace(TargetMac)
            ? "Semua"
            : (!string.IsNullOrWhiteSpace(TargetLabel) ? TargetLabel : TargetMac);

        [JsonIgnore]
        public string TimingDisplay
        {
            get
            {
                if (Kind == ScheduleKind.DailyWindow)
                {
                    return $"Harian {StartTime}–{EndTime}";
                }

                TimeSpan remaining = ExpiresAt.HasValue ? ExpiresAt.Value - DateTime.Now : TimeSpan.Zero;
                if (remaining <= TimeSpan.Zero) return "Selesai";
                if (remaining.TotalHours >= 1.0)
                {
                    return $"Sisa {(int)remaining.TotalHours}j {remaining.Minutes}m";
                }
                return $"Sisa {remaining.Minutes}m {remaining.Seconds}d";
            }
        }

        [JsonIgnore]
        public string StatusBadgeText => !Enabled
            ? "NONAKTIF"
            : (IsActiveNow ? "AKTIF" : (Kind == ScheduleKind.Timer ? "SELESAI" : "TERJADWAL"));

        [JsonIgnore]
        public string StatusBrushHex => IsActiveNow ? "#F85149" : "#D29922";
    }

    /// <summary>
    /// Menyimpan dan mengevaluasi aturan jadwal/timer pemblokiran internet atau domain.
    /// </summary>
    public static class BlockScheduleStore
    {
        private static readonly object _lock = new();
        private static readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = true };
        private static List<BlockScheduleRule> _rules;

        private static string PrimaryFilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetControl",
            "block_schedules.json");

        private static string FallbackFilePath => Path.Combine(
            AppContext.BaseDirectory,
            "block_schedules.json");

        public static bool TryParseTimeOfDay(string text, out TimeSpan result)
        {
            result = TimeSpan.Zero;
            if (string.IsNullOrWhiteSpace(text)) return false;

            string trimmed = text.Trim();
            string[] parts = trimmed.Split(':');
            if (parts.Length != 2) return false;

            if (parts[0].Length is < 1 or > 2 || parts[1].Length != 2) return false;

            if (!int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out int hours) ||
                !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int minutes))
            {
                return false;
            }

            if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59) return false;

            result = new TimeSpan(hours, minutes, 0);
            return true;
        }

        public static bool IsRuleActiveAt(BlockScheduleRule rule, DateTime now)
        {
            if (rule == null || !rule.Enabled) return false;

            if (rule.Kind == ScheduleKind.Timer)
            {
                return rule.ExpiresAt.HasValue && now < rule.ExpiresAt.Value;
            }

            if (!TryParseTimeOfDay(rule.StartTime, out var start) ||
                !TryParseTimeOfDay(rule.EndTime, out var end))
            {
                return false;
            }

            if (start == end) return true;

            TimeSpan cur = now.TimeOfDay;
            if (start < end)
            {
                return cur >= start && cur < end;
            }

            // Overnight window (e.g. 22:00 - 06:00)
            return cur >= start || cur < end;
        }

        public static IReadOnlyList<BlockScheduleRule> GetRules()
        {
            DateTime now = DateTime.Now;
            lock (_lock)
            {
                EnsureLoadedLocked();
                return _rules
                    .OrderByDescending(r => IsRuleActiveAt(r, now))
                    .ThenBy(r => r.Kind)
                    .ThenBy(r => r.ActionType)
                    .Select(CloneRule)
                    .ToArray();
            }
        }

        public static BlockScheduleRule AddTimerRule(
            ScheduleActionType actionType,
            string targetMac,
            string targetLabel,
            string rawDomain,
            int durationMinutes)
        {
            if (durationMinutes < 1) return null;

            string normMac = NormalizeMac(targetMac);
            if (actionType == ScheduleActionType.BlockInternet && string.IsNullOrEmpty(normMac))
            {
                return null;
            }

            string normDomain = string.Empty;
            if (actionType == ScheduleActionType.BlockDomain)
            {
                normDomain = BlockedDomainStore.NormalizeDomain(rawDomain);
                if (string.IsNullOrEmpty(normDomain)) return null;
            }

            string resolvedLabel = ResolveLabel(normMac, targetLabel);
            var rule = new BlockScheduleRule
            {
                Id = Guid.NewGuid().ToString("N").Substring(0, 8),
                Kind = ScheduleKind.Timer,
                ActionType = actionType,
                TargetMac = normMac,
                TargetLabel = resolvedLabel,
                Domain = normDomain,
                ExpiresAt = DateTime.Now.AddMinutes(durationMinutes),
                Enabled = true
            };

            lock (_lock)
            {
                EnsureLoadedLocked();
                _rules.Add(rule);
                SaveLocked();
            }

            if (!string.IsNullOrEmpty(normDomain))
            {
                BlockedDomainStore.PreResolveDomain(normDomain);
            }

            return CloneRule(rule);
        }

        public static BlockScheduleRule AddDailyRule(
            ScheduleActionType actionType,
            string targetMac,
            string targetLabel,
            string rawDomain,
            string startTime,
            string endTime)
        {
            if (!TryParseTimeOfDay(startTime, out var start) ||
                !TryParseTimeOfDay(endTime, out var end))
            {
                return null;
            }

            string normMac = NormalizeMac(targetMac);
            if (actionType == ScheduleActionType.BlockInternet && string.IsNullOrEmpty(normMac))
            {
                return null;
            }

            string normDomain = string.Empty;
            if (actionType == ScheduleActionType.BlockDomain)
            {
                normDomain = BlockedDomainStore.NormalizeDomain(rawDomain);
                if (string.IsNullOrEmpty(normDomain)) return null;
            }

            string canonicalStart = string.Create(CultureInfo.InvariantCulture, $"{start.Hours:D2}:{start.Minutes:D2}");
            string canonicalEnd = string.Create(CultureInfo.InvariantCulture, $"{end.Hours:D2}:{end.Minutes:D2}");
            string resolvedLabel = ResolveLabel(normMac, targetLabel);

            var rule = new BlockScheduleRule
            {
                Id = Guid.NewGuid().ToString("N").Substring(0, 8),
                Kind = ScheduleKind.DailyWindow,
                ActionType = actionType,
                TargetMac = normMac,
                TargetLabel = resolvedLabel,
                Domain = normDomain,
                StartTime = canonicalStart,
                EndTime = canonicalEnd,
                Enabled = true
            };

            lock (_lock)
            {
                EnsureLoadedLocked();
                _rules.Add(rule);
                SaveLocked();
            }

            if (!string.IsNullOrEmpty(normDomain))
            {
                BlockedDomainStore.PreResolveDomain(normDomain);
            }

            return CloneRule(rule);
        }

        public static bool RemoveRule(string id)
        {
            if (string.IsNullOrWhiteSpace(id)) return false;

            lock (_lock)
            {
                EnsureLoadedLocked();
                int removed = _rules.RemoveAll(r => string.Equals(r.Id, id.Trim(), StringComparison.OrdinalIgnoreCase));
                if (removed > 0)
                {
                    SaveLocked();
                    return true;
                }
            }

            return false;
        }

        public static void UpdateTargetLabel(string targetMac, string newLabel)
        {
            string normMac = NormalizeMac(targetMac);
            if (string.IsNullOrEmpty(normMac)) return;

            string resolved = !string.IsNullOrWhiteSpace(newLabel) ? newLabel.Trim() : normMac;

            lock (_lock)
            {
                EnsureLoadedLocked();
                bool changed = false;
                foreach (var rule in _rules)
                {
                    if (string.Equals(rule.TargetMac, normMac, StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(rule.TargetLabel, resolved, StringComparison.Ordinal))
                    {
                        rule.TargetLabel = resolved;
                        changed = true;
                    }
                }
                if (changed)
                {
                    SaveLocked();
                }
            }
        }

        public static List<BlockScheduleRule> PurgeExpiredTimers(DateTime now)
        {
            var expired = new List<BlockScheduleRule>();
            lock (_lock)
            {
                EnsureLoadedLocked();
                for (int i = _rules.Count - 1; i >= 0; i--)
                {
                    var rule = _rules[i];
                    if (rule.Kind == ScheduleKind.Timer && (!rule.ExpiresAt.HasValue || now >= rule.ExpiresAt.Value))
                    {
                        expired.Add(CloneRule(rule));
                        _rules.RemoveAt(i);
                    }
                }

                if (expired.Count > 0)
                {
                    SaveLocked();
                }
            }

            return expired;
        }

        public static bool IsDomainScheduledBlocked(string normalizedDomain, string normMac, DateTime now)
        {
            if (string.IsNullOrWhiteSpace(normalizedDomain)) return false;

            string normalizedTargetMac = NormalizeMac(normMac);
            lock (_lock)
            {
                EnsureLoadedLocked();
                foreach (var rule in _rules)
                {
                    if (rule.ActionType != ScheduleActionType.BlockDomain || !IsRuleActiveAt(rule, now))
                    {
                        continue;
                    }

                    bool macMatches = string.IsNullOrEmpty(rule.TargetMac) ||
                                      (!string.IsNullOrEmpty(normalizedTargetMac) &&
                                       string.Equals(rule.TargetMac, normalizedTargetMac, StringComparison.OrdinalIgnoreCase));

                    if (macMatches && BlockedDomainStore.RuleCoversDomain(rule.Domain, normalizedDomain))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static HashSet<string> GetActiveInternetBlockedMacs(DateTime now, out Dictionary<string, string> macToReason)
        {
            var macs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            macToReason = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            lock (_lock)
            {
                EnsureLoadedLocked();
                foreach (var rule in _rules)
                {
                    if (rule.ActionType != ScheduleActionType.BlockInternet ||
                        string.IsNullOrEmpty(rule.TargetMac) ||
                        !IsRuleActiveAt(rule, now))
                    {
                        continue;
                    }

                    macs.Add(rule.TargetMac);
                    if (!macToReason.ContainsKey(rule.TargetMac))
                    {
                        macToReason[rule.TargetMac] = FormatActiveReason(rule, now);
                    }
                }
            }

            return macs;
        }

        private static string FormatActiveReason(BlockScheduleRule rule, DateTime now)
        {
            if (rule.Kind == ScheduleKind.DailyWindow)
            {
                return $"⏱ Jadwal {rule.StartTime}–{rule.EndTime}";
            }

            TimeSpan rem = rule.ExpiresAt.HasValue ? rule.ExpiresAt.Value - now : TimeSpan.Zero;
            if (rem.TotalHours >= 1.0)
            {
                return $"⏱ Timer sisa {(int)rem.TotalHours}j {rem.Minutes}m";
            }
            if (rem.TotalMinutes >= 1.0)
            {
                return $"⏱ Timer sisa {(int)Math.Ceiling(rem.TotalMinutes)}m";
            }
            return $"⏱ Timer sisa {Math.Max(1, rem.Seconds)}d";
        }

        private static string NormalizeMac(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac) || mac.Trim() == "—") return string.Empty;
            return mac.Trim().ToUpperInvariant();
        }

        private static string ResolveLabel(string normMac, string targetLabel)
        {
            if (string.IsNullOrEmpty(normMac)) return "Semua";
            string stored = DeviceLabelStore.GetLabel(normMac);
            if (!string.IsNullOrWhiteSpace(stored)) return stored;
            return !string.IsNullOrWhiteSpace(targetLabel) ? targetLabel.Trim() : normMac;
        }

        private static BlockScheduleRule CloneRule(BlockScheduleRule r) => new()
        {
            Id = r.Id,
            Kind = r.Kind,
            ActionType = r.ActionType,
            TargetMac = r.TargetMac,
            TargetLabel = r.TargetLabel,
            Domain = r.Domain,
            ExpiresAt = r.ExpiresAt,
            StartTime = r.StartTime,
            EndTime = r.EndTime,
            Enabled = r.Enabled
        };

        private static void EnsureLoadedLocked()
        {
            if (_rules != null) return;

            _rules = new List<BlockScheduleRule>();

            string pathToRead = File.Exists(PrimaryFilePath)
                ? PrimaryFilePath
                : (File.Exists(FallbackFilePath) ? FallbackFilePath : null);

            if (pathToRead == null) return;

            try
            {
                string json = File.ReadAllText(pathToRead);
                var loaded = JsonSerializer.Deserialize<List<BlockScheduleRule>>(json);
                if (loaded != null)
                {
                    foreach (var r in loaded)
                    {
                        if (r == null) continue;
                        r.Id = string.IsNullOrWhiteSpace(r.Id) ? Guid.NewGuid().ToString("N").Substring(0, 8) : r.Id.Trim();
                        r.TargetMac = NormalizeMac(r.TargetMac);
                        r.TargetLabel = ResolveLabel(r.TargetMac, r.TargetLabel);
                        r.Domain = r.ActionType == ScheduleActionType.BlockDomain
                            ? BlockedDomainStore.NormalizeDomain(r.Domain)
                            : string.Empty;

                        if (r.ActionType == ScheduleActionType.BlockDomain && string.IsNullOrEmpty(r.Domain)) continue;
                        if (r.ActionType == ScheduleActionType.BlockInternet && string.IsNullOrEmpty(r.TargetMac)) continue;

                        _rules.Add(r);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SCHEDULE STORE] Gagal membaca jadwal blokir: {ex.Message}");
            }
        }

        private static void SaveLocked()
        {
            string json = JsonSerializer.Serialize(_rules, _jsonOptions);

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
                Console.WriteLine($"[SCHEDULE STORE] Gagal menyimpan ke {PrimaryFilePath}: {ex.Message}");
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
