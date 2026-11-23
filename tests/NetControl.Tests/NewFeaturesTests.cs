using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Xml.Linq;
using Xunit;

namespace NetControl.Tests
{
    public class NewFeaturesTests
    {
        [Fact]
        public void NetworkInterfaceOption_ShouldFormatFriendlyNameAndDetectVirtualAdapters()
        {
            Assert.Equal(
                "Wi-Fi — 192.168.1.68",
                NetworkInterfaceOption.FormatDisplayName("Wi-Fi", "Intel(R) Dual Band Wireless-AC 7265", "192.168.1.68", @"\Device\NPF_{123}"));

            Assert.Equal(
                "Intel Wireless Adapter — 10.0.0.5",
                NetworkInterfaceOption.FormatDisplayName("", "Intel Wireless Adapter", "10.0.0.5", @"\Device\NPF_{123}"));

            Assert.True(NetworkInterfaceOption.IsVirtualAdapter("vEthernet (WSL (Hyper-V firewall))", "Hyper-V Virtual Ethernet Adapter"));
            Assert.True(NetworkInterfaceOption.IsVirtualAdapter("Tailscale", "Tailscale Tunnel"));
            Assert.False(NetworkInterfaceOption.IsVirtualAdapter("Wi-Fi", "Intel(R) Dual Band Wireless-AC 7265"));
            Assert.False(NetworkInterfaceOption.IsVirtualAdapter("Ethernet", "Realtek PCIe GbE Family Controller"));
        }

        [Fact]
        public void ParseArpTableOutput_ShouldExtractValidSubnetEntriesAndIgnoreBroadcastAndMulticast()
        {
            byte[] localIp = new byte[] { 192, 168, 1, 68 };
            byte[] subnetMask = new byte[] { 255, 255, 255, 0 };

            string windowsArp = @"
Interface: 192.168.1.68 --- 0x10
  Internet Address      Physical Address      Type
  192.168.1.64          02-aa-bb-cc-dd-64     dynamic
  192.168.1.68          02-aa-bb-cc-dd-01     static
  192.168.1.99          00-00-00-00-00-00     invalid
  192.168.1.254         02-aa-bb-cc-dd-fe     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  172.25.240.1          00-15-5d-01-02-03     dynamic
";

            var parsed = CArp.ParseArpTableOutput(windowsArp, localIp, subnetMask);

            Assert.Equal(2, parsed.Count);
            Assert.Contains(parsed, e => e.Ip.Equals(IPAddress.Parse("192.168.1.64")) && e.Mac.Equals(PhysicalAddress.Parse("02AABBCCDD64")));
            Assert.Contains(parsed, e => e.Ip.Equals(IPAddress.Parse("192.168.1.254")) && e.Mac.Equals(PhysicalAddress.Parse("02AABBCCDDFE")));

            string linuxArp = @"
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.77     0x1         0x2         02:aa:bb:cc:dd:77     *        wlan0
";
            var parsedLinux = CArp.ParseArpTableOutput(linuxArp, localIp, subnetMask);
            Assert.Single(parsedLinux);
            Assert.Equal(IPAddress.Parse("192.168.1.77"), parsedLinux[0].Ip);
            Assert.Equal(PhysicalAddress.Parse("02AABBCCDD77"), parsedLinux[0].Mac);
        }

        [Fact]
        public void DeviceSettingsStore_ShouldSaveLoadAndCleanDefaultProfile()
        {
            const string testMac = "02:00:00:00:00:31";
            DeviceSettingsStore.RemoveProfile(testMac);

            try
            {
                DeviceSettingsStore.SaveProfile(testMac, 256, redirect: true, block: false, dataQuotaMb: 500);
                var loaded = DeviceSettingsStore.GetProfile(testMac);

                Assert.NotNull(loaded);
                Assert.Equal(256, loaded.BandwidthLimitKb);
                Assert.True(loaded.Redirect);
                Assert.False(loaded.Block);
                Assert.Equal(500, loaded.DataQuotaMb);

                // Block=true should enforce Redirect=false
                DeviceSettingsStore.SaveProfile(testMac, 128, redirect: true, block: true, dataQuotaMb: 200);
                var blockedProfile = DeviceSettingsStore.GetProfile(testMac);
                Assert.NotNull(blockedProfile);
                Assert.True(blockedProfile.Block);
                Assert.False(blockedProfile.Redirect);

                // Saving default values removes the stored entry
                DeviceSettingsStore.SaveProfile(testMac, 0, redirect: false, block: false, dataQuotaMb: 0);
                Assert.Null(DeviceSettingsStore.GetProfile(testMac));
            }
            finally
            {
                DeviceSettingsStore.RemoveProfile(testMac);
            }
        }

        [Fact]
        public void BlockScheduleStore_TimeWindowAndTimerEvaluationShouldHandleSameDayAndOvernight()
        {
            Assert.True(BlockScheduleStore.TryParseTimeOfDay("19:00", out var t19));
            Assert.Equal(new TimeSpan(19, 0, 0), t19);
            Assert.True(BlockScheduleStore.TryParseTimeOfDay("6:05", out var t6));
            Assert.Equal(new TimeSpan(6, 5, 0), t6);
            Assert.False(BlockScheduleStore.TryParseTimeOfDay("25:00", out _));
            Assert.False(BlockScheduleStore.TryParseTimeOfDay("abc", out _));

            var timerRule = new BlockScheduleRule
            {
                Kind = ScheduleKind.Timer,
                ExpiresAt = new DateTime(2026, 11, 23, 20, 0, 0),
                Enabled = true
            };
            Assert.True(BlockScheduleStore.IsRuleActiveAt(timerRule, new DateTime(2026, 11, 23, 19, 59, 0)));
            Assert.False(BlockScheduleStore.IsRuleActiveAt(timerRule, new DateTime(2026, 11, 23, 20, 0, 0)));

            var sameDayWindow = new BlockScheduleRule
            {
                Kind = ScheduleKind.DailyWindow,
                StartTime = "19:00",
                EndTime = "21:00",
                Enabled = true
            };
            Assert.True(BlockScheduleStore.IsRuleActiveAt(sameDayWindow, new DateTime(2026, 11, 23, 19, 30, 0)));
            Assert.False(BlockScheduleStore.IsRuleActiveAt(sameDayWindow, new DateTime(2026, 11, 23, 21, 0, 0)));

            var overnightWindow = new BlockScheduleRule
            {
                Kind = ScheduleKind.DailyWindow,
                StartTime = "22:00",
                EndTime = "06:00",
                Enabled = true
            };
            Assert.True(BlockScheduleStore.IsRuleActiveAt(overnightWindow, new DateTime(2026, 11, 23, 23, 30, 0)));
            Assert.True(BlockScheduleStore.IsRuleActiveAt(overnightWindow, new DateTime(2026, 11, 24, 4, 15, 0)));
            Assert.False(BlockScheduleStore.IsRuleActiveAt(overnightWindow, new DateTime(2026, 11, 24, 12, 0, 0)));

            overnightWindow.Enabled = false;
            Assert.False(BlockScheduleStore.IsRuleActiveAt(overnightWindow, new DateTime(2026, 11, 23, 23, 30, 0)));
        }

        [Fact]
        public void BlockScheduleStore_ScheduledDomainRuleShouldIsolateByMacAndTriggerThroughBlockedDomainStore()
        {
            const string macA = "02:00:00:00:00:41";
            const string macB = "02:00:00:00:00:42";

            bool preBlocked = BlockedDomainStore.IsDomainBlocked("vimeo.com", macB);
            if (preBlocked) return;

            var rule = BlockScheduleStore.AddTimerRule(
                ScheduleActionType.BlockDomain,
                macA,
                "Test Device A",
                "vimeo.com",
                15);

            Assert.NotNull(rule);
            try
            {
                Assert.True(BlockedDomainStore.IsDomainBlocked("player.vimeo.com", macA));
                Assert.False(BlockedDomainStore.IsDomainBlocked("player.vimeo.com", macB));

                // Also verify companion domain matching through IsDomainScheduledBlocked
                var ytRule = BlockScheduleStore.AddTimerRule(
                    ScheduleActionType.BlockDomain,
                    macA,
                    "Test Device A",
                    "youtube.com",
                    15);
                Assert.NotNull(ytRule);
                try
                {
                    DateTime now = DateTime.Now;
                    Assert.True(BlockScheduleStore.IsDomainScheduledBlocked("rr1---sn.googlevideo.com", macA, now));
                    Assert.False(BlockScheduleStore.IsDomainScheduledBlocked("rr1---sn.googlevideo.com", macB, now));
                }
                finally
                {
                    BlockScheduleStore.RemoveRule(ytRule.Id);
                }
            }
            finally
            {
                BlockScheduleStore.RemoveRule(rule.Id);
            }
        }

        [Fact]
        public void PcCumulativeData_ShouldPersistAcrossIntervalResetsAndTriggerQuota()
        {
            Assert.Equal("0 B", PC.FormatDataSize(0));
            Assert.Equal("512 B", PC.FormatDataSize(512));
            Assert.Equal("2.5 KB", PC.FormatDataSize(2560));
            Assert.Equal("1.5 MB", PC.FormatDataSize(1572864));
            Assert.Equal("1.50 GB", PC.FormatDataSize(1610612736L));

            var pc = new PC
            {
                Ip = IPAddress.Parse("192.168.1.90"),
                Mac = PhysicalAddress.Parse("020000000050"),
                DataQuotaMb = 1
            };

            pc.AddBytesReceived(600_000);
            pc.AddBytesSent(100_000);
            Assert.False(pc.IsQuotaExceeded);

            var (rx, tx) = pc.ResetByteAccumulators();
            Assert.Equal(600_000, rx);
            Assert.Equal(100_000, tx);
            Assert.Equal(0, pc.BytesReceived);
            Assert.Equal(0, pc.BytesSent);
            Assert.Equal(700_000, pc.TotalBytesCombined);

            // Crossing 1 MB (1,048,576 bytes) triggers IsQuotaExceeded
            pc.AddBytesReceived(400_000);
            Assert.Equal(1_100_000, pc.TotalBytesCombined);
            Assert.True(pc.IsQuotaExceeded);
            Assert.Equal("#F85149", pc.TotalDataBrushHex);

            pc.ResetTotalData();
            Assert.Equal(0, pc.TotalBytesCombined);
            Assert.False(pc.IsQuotaExceeded);
            Assert.Equal("0 B", pc.TotalDataFormatted);
        }

        [Fact]
        public void AutostartManager_BuildWindowsTaskXml_ShouldConfigureHighestPrivilegesAndBatteryFriendlySettings()
        {
            string xml = AutostartManager.BuildWindowsTaskXml(
                @"M:\Net&Control\NetControl.exe",
                "--autostart",
                @"M:\Net&Control",
                @"PC\User&Name");

            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

            Assert.Equal("HighestAvailable", doc.Root?.Element(ns + "Principals")?.Element(ns + "Principal")?.Element(ns + "RunLevel")?.Value);
            Assert.Equal("false", doc.Root?.Element(ns + "Settings")?.Element(ns + "DisallowStartIfOnBatteries")?.Value);
            Assert.Equal("false", doc.Root?.Element(ns + "Settings")?.Element(ns + "StopIfGoingOnBatteries")?.Value);
            Assert.Equal("PT0S", doc.Root?.Element(ns + "Settings")?.Element(ns + "ExecutionTimeLimit")?.Value);
            Assert.Equal("--autostart", doc.Root?.Element(ns + "Actions")?.Element(ns + "Exec")?.Element(ns + "Arguments")?.Value);
            Assert.Equal(@"M:\Net&Control\NetControl.exe", doc.Root?.Element(ns + "Actions")?.Element(ns + "Exec")?.Element(ns + "Command")?.Value);
            Assert.Equal(@"M:\Net&Control", doc.Root?.Element(ns + "Actions")?.Element(ns + "Exec")?.Element(ns + "WorkingDirectory")?.Value);
            Assert.Equal(@"PC\User&Name", doc.Root?.Element(ns + "Triggers")?.Element(ns + "LogonTrigger")?.Element(ns + "UserId")?.Value);
        }

        [Fact]
        public void AppSettingsStore_ShouldAllowAutoSpoof_ShouldEnforceHomeRouterSafeguard()
        {
            var disabled = new AppSettings
            {
                AutoScanOnStartup = true,
                AutoSpoofAfterScan = false,
                OnlyAutoSpoofOnHomeRouter = true,
                HomeRouterMac = "02:AA:BB:CC:DD:FE"
            };
            Assert.False(AppSettingsStore.ShouldAllowAutoSpoof(disabled, "02:AA:BB:CC:DD:FE", out _));

            var missingHomeMac = new AppSettings
            {
                AutoScanOnStartup = true,
                AutoSpoofAfterScan = true,
                OnlyAutoSpoofOnHomeRouter = true,
                HomeRouterMac = ""
            };
            Assert.False(AppSettingsStore.ShouldAllowAutoSpoof(missingHomeMac, "02:AA:BB:CC:DD:FE", out string missingReason));
            Assert.Contains("Pakai Router Ini", missingReason, StringComparison.Ordinal);

            var homeConfig = new AppSettings
            {
                AutoScanOnStartup = true,
                AutoSpoofAfterScan = true,
                OnlyAutoSpoofOnHomeRouter = true,
                HomeRouterMac = "02:AA:BB:CC:DD:FE"
            };
            Assert.True(AppSettingsStore.ShouldAllowAutoSpoof(homeConfig, "02aabbccddfe", out string okReason));
            Assert.Equal(string.Empty, okReason);

            Assert.False(AppSettingsStore.ShouldAllowAutoSpoof(homeConfig, "AA:BB:CC:DD:EE:FF", out string cafeReason));
            Assert.Contains("Bukan jaringan rumah", cafeReason, StringComparison.Ordinal);

            var allowAnyNetwork = new AppSettings
            {
                AutoScanOnStartup = true,
                AutoSpoofAfterScan = true,
                OnlyAutoSpoofOnHomeRouter = false,
                HomeRouterMac = ""
            };
            Assert.True(AppSettingsStore.ShouldAllowAutoSpoof(allowAnyNetwork, "AA:BB:CC:DD:EE:FF", out _));
        }

        [Fact]
        public void AppSettingsStore_NormalizeAndFormatMacBytes_ShouldProduceCanonicalColonFormat()
        {
            Assert.Equal(
                "02:AA:BB:CC:DD:FE",
                AppSettingsStore.FormatMacBytes(new byte[] { 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xFE }));

            Assert.Equal("02:AA:BB:CC:DD:FE", AppSettingsStore.NormalizeMac("02aabbccddfe"));
            Assert.Equal("02:AA:BB:CC:DD:FE", AppSettingsStore.NormalizeMac("02-aa-bb-cc-dd-fe"));
            Assert.Equal(string.Empty, AppSettingsStore.NormalizeMac("—"));
            Assert.Equal(string.Empty, AppSettingsStore.FormatMacBytes(new byte[] { 1, 2, 3 }));
        }

        [Fact]
        public void CArp_IsValidLanArpSender_ShouldRejectZeroIpProbeAndOutOfSubnetEntries()
        {
            byte[] localIp = new byte[] { 192, 168, 1, 68 };
            byte[] mask = new byte[] { 255, 255, 255, 0 };
            byte[] validMac = new byte[] { 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x70 };
            byte[] zeroMac = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] bcastMac = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

            Assert.True(CArp.IsValidLanArpSender(new byte[] { 192, 168, 1, 70 }, validMac, localIp, mask));
            Assert.False(CArp.IsValidLanArpSender(new byte[] { 0, 0, 0, 0 }, validMac, localIp, mask));
            Assert.False(CArp.IsValidLanArpSender(new byte[] { 192, 168, 1, 0 }, validMac, localIp, mask));
            Assert.False(CArp.IsValidLanArpSender(new byte[] { 192, 168, 1, 255 }, validMac, localIp, mask));
            Assert.False(CArp.IsValidLanArpSender(new byte[] { 172, 25, 240, 1 }, validMac, localIp, mask));
            Assert.False(CArp.IsValidLanArpSender(new byte[] { 224, 0, 0, 22 }, validMac, localIp, mask));
            Assert.False(CArp.IsValidLanArpSender(new byte[] { 192, 168, 1, 70 }, zeroMac, localIp, mask));
            Assert.False(CArp.IsValidLanArpSender(new byte[] { 192, 168, 1, 70 }, bcastMac, localIp, mask));
        }

        [Fact]
        public void AppSettingsStore_SanitizeWindowBounds_ShouldValidateAndRejectInvalidDimensions()
        {
            Assert.True(AppSettingsStore.SanitizeWindowBounds(1280.4, 840.6, 880, 660, out double w, out double h));
            Assert.Equal(1280, w);
            Assert.Equal(841, h);

            Assert.False(AppSettingsStore.SanitizeWindowBounds(500, 400, 880, 660, out _, out _));
            Assert.False(AppSettingsStore.SanitizeWindowBounds(0, 0, 880, 660, out _, out _));
            Assert.False(AppSettingsStore.SanitizeWindowBounds(-1200, 800, 880, 660, out _, out _));
            Assert.False(AppSettingsStore.SanitizeWindowBounds(double.NaN, 800, 880, 660, out _, out _));
            Assert.False(AppSettingsStore.SanitizeWindowBounds(1200, double.PositiveInfinity, 880, 660, out _, out _));
            Assert.False(AppSettingsStore.SanitizeWindowBounds(99999, 800, 880, 660, out _, out _));
        }

        [Fact]
        public void PcCompareForDisplay_ShouldPlaceTargetDevicesByIpFirstThenLocalPcThenGateway()
        {
            var gateway = new PC { Ip = IPAddress.Parse("192.168.1.1"), Mac = PhysicalAddress.Parse("02AABBCCDDFE"), IsGateway = true };
            var local = new PC { Ip = IPAddress.Parse("192.168.1.68"), Mac = PhysicalAddress.Parse("02AABBCCDD01"), IsLocalPc = true };
            var dev77 = new PC { Ip = IPAddress.Parse("192.168.1.77"), Mac = PhysicalAddress.Parse("02AABBCCDD77") };
            var dev64 = new PC { Ip = IPAddress.Parse("192.168.1.64"), Mac = PhysicalAddress.Parse("02AABBCCDD64") };
            var dev70 = new PC { Ip = IPAddress.Parse("192.168.1.70"), Mac = PhysicalAddress.Parse("02AABBCCDD70") };
            var dev100 = new PC { Ip = IPAddress.Parse("192.168.1.100"), Mac = PhysicalAddress.Parse("020000000099") };

            var list = new System.Collections.Generic.List<PC> { gateway, dev100, local, dev77, dev64, dev70 };
            list.Sort(PC.CompareForDisplay);

            Assert.Equal("192.168.1.64", list[0].IpDisplay);
            Assert.Equal("192.168.1.70", list[1].IpDisplay);
            Assert.Equal("192.168.1.77", list[2].IpDisplay);
            Assert.Equal("192.168.1.100", list[3].IpDisplay);
            Assert.Equal("192.168.1.68", list[4].IpDisplay);
            Assert.Equal("192.168.1.1", list[5].IpDisplay);
        }
    }
}
