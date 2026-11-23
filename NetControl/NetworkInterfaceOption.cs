using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SharpPcap.LibPcap;

namespace NetControl
{
    /// <summary>
    /// Wrapper tampilan ramah pengguna untuk <see cref="LibPcapLiveDevice"/> agar dropdown
    /// antarmuka menampilkan nama adapter yang mudah dibaca (mis. "Wi-Fi — 192.168.1.68").
    /// </summary>
    public sealed class NetworkInterfaceOption
    {
        private static readonly string[] VirtualKeywords =
        {
            "vethernet", "wsl", "hyper-v", "virtualbox", "vmware", "loopback",
            "tap-", "tailscale", "zerotier", "nordlynx", "wintun", "bluetooth",
            "teredo", "isatap"
        };

        public LibPcapLiveDevice Device { get; set; }
        public string DisplayName { get; set; } = string.Empty;
        public string TooltipText { get; set; } = string.Empty;
        public string Ipv4Address { get; set; } = string.Empty;
        public string GatewayAddress { get; set; } = string.Empty;
        public bool HasGateway { get; set; }
        public bool IsVirtual { get; set; }
        public string DeviceName => Device?.Name ?? string.Empty;

        public override string ToString() => DisplayName;

        public static List<NetworkInterfaceOption> BuildInterfaceOptions(IEnumerable<LibPcapLiveDevice> devices)
        {
            var results = new List<NetworkInterfaceOption>();
            if (devices == null) return results;

            NetworkInterface[] allNics;
            try
            {
                allNics = NetworkInterface.GetAllNetworkInterfaces();
            }
            catch
            {
                allNics = Array.Empty<NetworkInterface>();
            }

            foreach (var device in devices)
            {
                if (device == null) continue;

                string ipv4 = string.Empty;
                if (device.Addresses != null)
                {
                    foreach (var addr in device.Addresses)
                    {
                        var ip = addr?.Addr?.ipAddress;
                        if (ip != null && ip.AddressFamily == AddressFamily.InterNetwork)
                        {
                            ipv4 = ip.ToString();
                            break;
                        }
                    }
                }

                string gateway = string.Empty;
                if (device.Interface?.GatewayAddresses != null)
                {
                    foreach (var gw in device.Interface.GatewayAddresses)
                    {
                        if (gw != null && gw.AddressFamily == AddressFamily.InterNetwork)
                        {
                            string gwStr = gw.ToString();
                            if (!string.IsNullOrWhiteSpace(gwStr) && gwStr != "0.0.0.0")
                            {
                                gateway = gwStr;
                                break;
                            }
                        }
                    }
                }

                NetworkInterface matchedNic = FindMatchingNetworkInterface(allNics, device, ipv4);

                if (string.IsNullOrEmpty(gateway) && matchedNic != null)
                {
                    try
                    {
                        foreach (var gw in matchedNic.GetIPProperties().GatewayAddresses)
                        {
                            if (gw?.Address != null && gw.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                string gwStr = gw.Address.ToString();
                                if (!string.IsNullOrWhiteSpace(gwStr) && gwStr != "0.0.0.0")
                                {
                                    gateway = gwStr;
                                    break;
                                }
                            }
                        }
                    }
                    catch
                    {
                        // Abaikan jika properti IP adapter tidak dapat dibaca
                    }
                }

                string friendlyName = matchedNic?.Name ?? device.Interface?.FriendlyName;
                string description = matchedNic?.Description ?? device.Description;
                string displayName = FormatDisplayName(friendlyName, description, ipv4, device.Name);
                bool isVirtual = IsVirtualAdapter(friendlyName, description);
                bool hasGateway = !string.IsNullOrWhiteSpace(gateway) && gateway != "0.0.0.0";

                string tooltip = BuildTooltip(friendlyName, description, ipv4, gateway, device.Name);

                results.Add(new NetworkInterfaceOption
                {
                    Device = device,
                    DisplayName = displayName,
                    TooltipText = tooltip,
                    Ipv4Address = ipv4,
                    GatewayAddress = gateway,
                    HasGateway = hasGateway,
                    IsVirtual = isVirtual
                });
            }

            return results
                .OrderByDescending(o => o.HasGateway)
                .ThenBy(o => o.IsVirtual)
                .ThenBy(o => o.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public static string FormatDisplayName(string friendlyName, string description, string ipv4, string fallbackName)
        {
            string baseName = !string.IsNullOrWhiteSpace(friendlyName)
                ? friendlyName.Trim()
                : (!string.IsNullOrWhiteSpace(description)
                    ? description.Trim()
                    : (!string.IsNullOrWhiteSpace(fallbackName) ? fallbackName.Trim() : "Adapter Tidak Dikenal"));

            if (baseName.Length > 28)
            {
                baseName = string.Concat(baseName.AsSpan(0, 27), "…");
            }

            return !string.IsNullOrWhiteSpace(ipv4) ? $"{baseName} — {ipv4}" : baseName;
        }

        public static bool IsVirtualAdapter(string name, string description)
        {
            string combined = $"{name} {description}";
            if (string.IsNullOrWhiteSpace(combined)) return false;

            foreach (string keyword in VirtualKeywords)
            {
                if (combined.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static NetworkInterface FindMatchingNetworkInterface(
            NetworkInterface[] allNics,
            LibPcapLiveDevice device,
            string ipv4)
        {
            if (allNics == null || allNics.Length == 0) return null;

            if (!string.IsNullOrWhiteSpace(ipv4))
            {
                foreach (var nic in allNics)
                {
                    try
                    {
                        foreach (var uni in nic.GetIPProperties().UnicastAddresses)
                        {
                            if (uni?.Address != null &&
                                uni.Address.AddressFamily == AddressFamily.InterNetwork &&
                                string.Equals(uni.Address.ToString(), ipv4, StringComparison.Ordinal))
                            {
                                return nic;
                            }
                        }
                    }
                    catch
                    {
                        // Abaikan adapter yang tidak mendukung pembacaan unicast
                    }
                }
            }

            if (!string.IsNullOrEmpty(device?.Name))
            {
                foreach (var nic in allNics)
                {
                    if (!string.IsNullOrEmpty(nic.Id) &&
                        device.Name.Contains(nic.Id, StringComparison.OrdinalIgnoreCase))
                    {
                        return nic;
                    }
                }
            }

            return null;
        }

        private static string BuildTooltip(
            string friendlyName,
            string description,
            string ipv4,
            string gateway,
            string rawName)
        {
            var lines = new List<string>();
            if (!string.IsNullOrWhiteSpace(friendlyName)) lines.Add($"Adapter: {friendlyName.Trim()}");
            if (!string.IsNullOrWhiteSpace(description) && !string.Equals(description.Trim(), friendlyName?.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                lines.Add($"Perangkat: {description.Trim()}");
            }
            if (!string.IsNullOrWhiteSpace(ipv4)) lines.Add($"IPv4: {ipv4}");
            if (!string.IsNullOrWhiteSpace(gateway)) lines.Add($"Gateway: {gateway}");
            if (!string.IsNullOrWhiteSpace(rawName)) lines.Add($"ID: {rawName}");

            return string.Join(Environment.NewLine, lines);
        }
    }
}
