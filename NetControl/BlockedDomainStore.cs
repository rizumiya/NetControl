using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;

namespace NetControl
{
    public class BlockedDomainRule
    {
        public string Domain { get; set; } = string.Empty;
        public string TargetMac { get; set; } = string.Empty;
        public string TargetLabel { get; set; } = "Semua";

        public bool IsGlobal => string.IsNullOrWhiteSpace(TargetMac);
        public string TargetBadgeText => IsGlobal
            ? "Semua"
            : (!string.IsNullOrWhiteSpace(TargetLabel) ? TargetLabel : TargetMac);
    }

    /// <summary>
    /// Menyimpan daftar aturan blokir domain/website (global atau per MAC Address perangkat)
    /// secara permanen dalam JSON, beserta pemetaan IPv4 untuk pemblokiran aktif HTTPS/DNS/QUIC.
    /// </summary>
    public static class BlockedDomainStore
    {
        private static readonly object _lock = new();
        private static readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = true };
        private static List<BlockedDomainRule> _rules;
        private static readonly Dictionary<uint, HashSet<string>> _ipToDomains = new();

        private static readonly Dictionary<string, string[]> _companionDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            ["youtube.com"] = new[]
            {
                "googlevideo.com", "ytimg.com", "youtu.be", "youtubei.googleapis.com",
                "youtube.googleapis.com", "jnn-pa.googleapis.com", "ggpht.com",
                "youtube-nocookie.com", "youtubekids.com"
            },
            ["roblox.com"] = new[] { "rbxcdn.com", "roblox.cn", "robloxlabs.com" },
            ["tiktok.com"] = new[] { "tiktokv.com", "tiktokcdn.com", "byteoversea.com", "ibytedtos.com", "musical.ly" },
            ["instagram.com"] = new[] { "cdninstagram.com", "ig.me" },
            ["facebook.com"] = new[] { "fbcdn.net", "fb.com", "fbsbx.com" },
            ["twitter.com"] = new[] { "twimg.com", "t.co", "x.com" },
            ["x.com"] = new[] { "twimg.com", "t.co", "twitter.com" },
            ["netflix.com"] = new[] { "nflxvideo.net", "nflximg.net", "nflxext.com" },
            ["telegram.org"] = new[] { "t.me", "telegram.me", "tdesktop.com", "stel.com", "telesco.pe" },
            ["t.me"] = new[] { "telegram.org", "telegram.me", "tdesktop.com", "stel.com", "telesco.pe" },
            ["whatsapp.com"] = new[] { "whatsapp.net", "wa.me" }
        };

        private static string PrimaryFilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetControl",
            "blocked_domains.json");

        private static string FallbackFilePath => Path.Combine(
            AppContext.BaseDirectory,
            "blocked_domains.json");

        public static string NormalizeDomain(string rawDomain)
        {
            if (string.IsNullOrWhiteSpace(rawDomain)) return string.Empty;

            string d = rawDomain.Trim().ToLowerInvariant();
            if (d.StartsWith("https://", StringComparison.Ordinal)) d = d.Substring(8);
            else if (d.StartsWith("http://", StringComparison.Ordinal)) d = d.Substring(7);

            int slashIdx = d.IndexOfAny(new[] { '/', '?', '#' });
            if (slashIdx >= 0) d = d.Substring(0, slashIdx);

            int portIdx = d.IndexOf(':');
            if (portIdx >= 0) d = d.Substring(0, portIdx);

            d = d.Trim('.');
            if (d.StartsWith("www.", StringComparison.Ordinal) && d.Length > 4)
            {
                d = d.Substring(4);
            }

            if (string.IsNullOrWhiteSpace(d) || !d.Contains('.') || d.Contains(' '))
            {
                return string.Empty;
            }

            return d;
        }

        private static string NormalizeMac(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac) || mac.Trim() == "—") return string.Empty;
            return mac.Trim().ToUpperInvariant();
        }

        public static IReadOnlyList<BlockedDomainRule> GetBlockedRules()
        {
            lock (_lock)
            {
                EnsureLoadedLocked();
                return _rules
                    .OrderBy(r => r.Domain, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(r => r.TargetBadgeText, StringComparer.OrdinalIgnoreCase)
                    .Select(r => new BlockedDomainRule
                    {
                        Domain = r.Domain,
                        TargetMac = r.TargetMac,
                        TargetLabel = r.TargetLabel
                    })
                    .ToArray();
            }
        }

        public static IReadOnlyList<string> GetBlockedDomains()
        {
            lock (_lock)
            {
                EnsureLoadedLocked();
                return _rules
                    .Select(r => r.Domain)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }

        public static bool AddDomain(string rawDomain, string targetMac = null, string targetLabel = null)
        {
            string normalized = NormalizeDomain(rawDomain);
            if (string.IsNullOrEmpty(normalized)) return false;

            string normMac = NormalizeMac(targetMac);
            string resolvedLabel = string.IsNullOrEmpty(normMac)
                ? "Semua"
                : (!string.IsNullOrWhiteSpace(targetLabel) ? targetLabel.Trim() : normMac);

            bool added = false;
            lock (_lock)
            {
                EnsureLoadedLocked();
                bool exists = _rules.Any(r =>
                    string.Equals(r.Domain, normalized, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(r.TargetMac, normMac, StringComparison.OrdinalIgnoreCase));

                if (!exists)
                {
                    _rules.Add(new BlockedDomainRule
                    {
                        Domain = normalized,
                        TargetMac = normMac,
                        TargetLabel = resolvedLabel
                    });
                    SaveLocked();
                    added = true;
                }
            }

            if (added)
            {
                _ = ResolveAndCacheDomainIpsAsync(normalized);
            }

            return added;
        }

        public static void PreResolveDomain(string rawDomain)
        {
            string norm = NormalizeDomain(rawDomain);
            if (!string.IsNullOrEmpty(norm))
            {
                _ = ResolveAndCacheDomainIpsAsync(norm);
            }
        }

        public static bool RemoveDomain(string rawDomain, string targetMac = null)
        {
            string normalized = NormalizeDomain(rawDomain);
            if (string.IsNullOrEmpty(normalized)) return false;

            string normMac = NormalizeMac(targetMac);

            lock (_lock)
            {
                EnsureLoadedLocked();
                int removedCount = _rules.RemoveAll(r =>
                    string.Equals(r.Domain, normalized, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(r.TargetMac, normMac, StringComparison.OrdinalIgnoreCase));

                if (removedCount > 0)
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

        public static bool IsDomainBlocked(string domain, string deviceMac = null)
        {
            string normalized = NormalizeDomain(domain);
            if (string.IsNullOrEmpty(normalized)) return false;

            string normMac = NormalizeMac(deviceMac);

            bool staticMatch;
            lock (_lock)
            {
                EnsureLoadedLocked();
                staticMatch = FindMatchingRuleLocked(normalized, normMac) != null;
            }

            if (staticMatch) return true;
            return BlockScheduleStore.IsDomainScheduledBlocked(normalized, normMac, DateTime.Now);
        }

        public static BlockedDomainRule GetMatchingRule(string domain, string deviceMac = null)
        {
            string normalized = NormalizeDomain(domain);
            if (string.IsNullOrEmpty(normalized)) return null;

            string normMac = NormalizeMac(deviceMac);

            lock (_lock)
            {
                EnsureLoadedLocked();
                var rule = FindMatchingRuleLocked(normalized, normMac);
                if (rule == null) return null;

                return new BlockedDomainRule
                {
                    Domain = rule.Domain,
                    TargetMac = rule.TargetMac,
                    TargetLabel = rule.TargetLabel
                };
            }
        }

        public static void RegisterBlockedIp(uint ipv4Uint, string domain)
        {
            if (ipv4Uint == 0) return;
            string normDomain = NormalizeDomain(domain);
            if (string.IsNullOrEmpty(normDomain)) return;

            lock (_lock)
            {
                if (_ipToDomains.Count > 4096)
                {
                    _ipToDomains.Clear();
                }
                if (!_ipToDomains.TryGetValue(ipv4Uint, out var set))
                {
                    set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    _ipToDomains[ipv4Uint] = set;
                }
                set.Add(normDomain);
            }
        }

        public static bool IsIpBlocked(uint ipv4Uint, out string matchedDomain)
        {
            return IsIpBlocked(ipv4Uint, null, out matchedDomain);
        }

        public static bool IsIpBlocked(uint ipv4Uint, string deviceMac, out string matchedDomain)
        {
            if (ipv4Uint == 0)
            {
                matchedDomain = null;
                return false;
            }

            string[] mappedDomains = null;
            lock (_lock)
            {
                if (_ipToDomains.TryGetValue(ipv4Uint, out var set) && set.Count > 0)
                {
                    mappedDomains = set.ToArray();
                }
            }

            if (mappedDomains != null)
            {
                foreach (string d in mappedDomains)
                {
                    if (IsDomainBlocked(d, deviceMac))
                    {
                        matchedDomain = d;
                        return true;
                    }
                }
            }

            if (DomainInspector.TryGetCachedIpDomain(ipv4Uint, out string cachedDom) &&
                IsDomainBlocked(cachedDom, deviceMac))
            {
                matchedDomain = cachedDom;
                return true;
            }

            if (DomainInspector.TryMatchWellKnownAppIp(ipv4Uint, out string appDom, out _) &&
                IsDomainBlocked(appDom, deviceMac))
            {
                matchedDomain = appDom;
                return true;
            }

            matchedDomain = null;
            return false;
        }

        private static BlockedDomainRule FindMatchingRuleLocked(string normalizedDomain, string normMac)
        {
            // Check per-device rules first when a device MAC is specified
            if (!string.IsNullOrEmpty(normMac))
            {
                foreach (var rule in _rules)
                {
                    if (!rule.IsGlobal &&
                        string.Equals(rule.TargetMac, normMac, StringComparison.OrdinalIgnoreCase) &&
                        RuleCoversDomain(rule.Domain, normalizedDomain))
                    {
                        return rule;
                    }
                }
            }

            // Fall back to global rules
            foreach (var rule in _rules)
            {
                if (rule.IsGlobal && RuleCoversDomain(rule.Domain, normalizedDomain))
                {
                    return rule;
                }
            }

            return null;
        }

        internal static bool RuleCoversDomain(string ruleDomain, string candidateDomain)
        {
            if (DomainMatchesPattern(candidateDomain, ruleDomain))
            {
                return true;
            }

            if (_companionDomains.TryGetValue(ruleDomain, out string[] companions))
            {
                foreach (string comp in companions)
                {
                    if (DomainMatchesPattern(candidateDomain, comp))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static bool DomainMatchesPattern(string candidate, string pattern)
        {
            if (string.Equals(candidate, pattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return candidate.EndsWith("." + pattern, StringComparison.OrdinalIgnoreCase);
        }

        private static async Task ResolveAndCacheDomainIpsAsync(string normalizedDomain)
        {
            string[] hosts = new[] { normalizedDomain, "www." + normalizedDomain };
            foreach (string host in hosts)
            {
                try
                {
                    var addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
                    foreach (IPAddress addr in addresses)
                    {
                        if (addr.AddressFamily == AddressFamily.InterNetwork)
                        {
                            byte[] b = addr.GetAddressBytes();
                            uint ipUint = (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
                            RegisterBlockedIp(ipUint, normalizedDomain);
                        }
                    }
                }
                catch
                {
                    // Best-effort background resolution
                }
            }
        }

        private static void EnsureLoadedLocked()
        {
            if (_rules != null) return;

            _rules = new List<BlockedDomainRule>();

            string pathToRead = File.Exists(PrimaryFilePath)
                ? PrimaryFilePath
                : (File.Exists(FallbackFilePath) ? FallbackFilePath : null);

            if (pathToRead == null) return;

            try
            {
                string json = File.ReadAllText(pathToRead);
                using JsonDocument doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind != JsonValueKind.Array) return;

                foreach (JsonElement elem in doc.RootElement.EnumerateArray())
                {
                    string domain = null;
                    string targetMac = string.Empty;
                    string targetLabel = "Semua";

                    if (elem.ValueKind == JsonValueKind.String)
                    {
                        domain = NormalizeDomain(elem.GetString());
                    }
                    else if (elem.ValueKind == JsonValueKind.Object)
                    {
                        if (elem.TryGetProperty("Domain", out var dProp))
                        {
                            domain = NormalizeDomain(dProp.GetString());
                        }
                        if (elem.TryGetProperty("TargetMac", out var macProp))
                        {
                            targetMac = NormalizeMac(macProp.GetString());
                        }
                        if (!string.IsNullOrEmpty(targetMac))
                        {
                            string storedCustom = DeviceLabelStore.GetLabel(targetMac);
                            if (!string.IsNullOrWhiteSpace(storedCustom))
                            {
                                targetLabel = storedCustom;
                            }
                            else if (elem.TryGetProperty("TargetLabel", out var lblProp) &&
                                     !string.IsNullOrWhiteSpace(lblProp.GetString()))
                            {
                                targetLabel = lblProp.GetString().Trim();
                            }
                            else
                            {
                                targetLabel = targetMac;
                            }
                        }
                    }

                    if (!string.IsNullOrEmpty(domain))
                    {
                        bool duplicate = _rules.Any(r =>
                            string.Equals(r.Domain, domain, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(r.TargetMac, targetMac, StringComparison.OrdinalIgnoreCase));

                        if (!duplicate)
                        {
                            _rules.Add(new BlockedDomainRule
                            {
                                Domain = domain,
                                TargetMac = targetMac,
                                TargetLabel = targetLabel
                            });
                        }
                    }
                }

                foreach (string d in _rules.Select(r => r.Domain).Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    _ = ResolveAndCacheDomainIpsAsync(d);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[BLOCKED DOMAINS] Gagal membaca daftar domain terblokir: {ex.Message}");
            }
        }

        private static void SaveLocked()
        {
            var ordered = _rules
                .OrderBy(r => r.Domain, StringComparer.OrdinalIgnoreCase)
                .ThenBy(r => r.TargetBadgeText, StringComparer.OrdinalIgnoreCase)
                .ToList();

            string json = JsonSerializer.Serialize(ordered, _jsonOptions);

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
                Console.WriteLine($"[BLOCKED DOMAINS] Gagal menyimpan ke {PrimaryFilePath}: {ex.Message}");
            }

            try
            {
                File.WriteAllText(FallbackFilePath, json);
            }
            catch
            {
                // Best-effort fallback copy
            }
        }
    }
}
