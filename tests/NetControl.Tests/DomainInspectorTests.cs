using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace NetControl.Tests
{
    public class DomainInspectorTests
    {
        [Fact]
        public void TryExtractTlsSni_ShouldExtractHostnameFromClientHello()
        {
            byte[] clientHello = BuildSyntheticTlsClientHello("www.youtube.com");

            bool ok = DomainInspector.TryExtractTlsSni(clientHello, 0, clientHello.Length, out string sni);

            Assert.True(ok);
            Assert.Equal("www.youtube.com", sni);
        }

        [Fact]
        public void TryExtractDnsQuery_ShouldExtractDomainFromDnsQuestion()
        {
            byte[] dnsQuery = BuildSyntheticDnsQuery("tiktok.com");

            bool ok = DomainInspector.TryExtractDnsQuery(dnsQuery, 0, out string domain);

            Assert.True(ok);
            Assert.Equal("tiktok.com", domain);
        }

        [Fact]
        public void TryExtractHttpHost_ShouldExtractHostHeader()
        {
            byte[] httpBytes = Encoding.ASCII.GetBytes("GET /index.html HTTP/1.1\r\nHost: example.com:80\r\nConnection: close\r\n\r\n");

            bool ok = DomainInspector.TryExtractHttpHost(httpBytes, 0, httpBytes.Length, out string host);

            Assert.True(ok);
            Assert.Equal("example.com", host);
        }

        [Fact]
        public void BlockedDomainStore_ShouldMatchSubdomainsAndCompanionDomains()
        {
            bool wasAlreadyBlocked = BlockedDomainStore.IsDomainBlocked("youtube.com");
            if (!wasAlreadyBlocked)
            {
                BlockedDomainStore.AddDomain("https://www.youtube.com/watch?v=123");
            }

            try
            {
                Assert.True(BlockedDomainStore.IsDomainBlocked("youtube.com"));
                Assert.True(BlockedDomainStore.IsDomainBlocked("m.youtube.com"));
                Assert.True(BlockedDomainStore.IsDomainBlocked("rr1---sn.googlevideo.com"));
                Assert.False(BlockedDomainStore.IsDomainBlocked("example.com"));
            }
            finally
            {
                if (!wasAlreadyBlocked)
                {
                    BlockedDomainStore.RemoveDomain("youtube.com");
                }
            }
        }

        [Fact]
        public void BuildTcpResetToClient_ShouldConstructValidRstAckFrame()
        {
            byte[] clientHello = BuildSyntheticTlsClientHello("www.youtube.com");
            byte[] pkt = WrapInEthernetIpv4Tcp(
                new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 },
                new byte[] { 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xFE },
                new byte[] { 192, 168, 1, 65 },
                new byte[] { 142, 250, 190, 78 },
                54321,
                443,
                clientHello);

            byte[] localMac = new byte[] { 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01 };
            byte[] rst = DomainInspector.BuildTcpResetToClient(pkt, localMac);

            Assert.NotNull(rst);
            Assert.Equal(54, rst.Length);
            Assert.Equal(0x14, rst[47]); // RST | ACK
            // Swapped IPs
            Assert.Equal(new byte[] { 142, 250, 190, 78 }, rst[26..30]);
            Assert.Equal(new byte[] { 192, 168, 1, 65 }, rst[30..34]);
        }

        [Fact]
        public void BuildDnsSinkholeReply_ShouldConstructNxdomainResponse()
        {
            byte[] dnsQuery = BuildSyntheticDnsQuery("tiktok.com");
            byte[] pkt = WrapInEthernetIpv4Udp(
                new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 },
                new byte[] { 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xFE },
                new byte[] { 192, 168, 1, 65 },
                new byte[] { 192, 168, 1, 254 },
                51234,
                53,
                dnsQuery);

            byte[] localMac = new byte[] { 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01 };
            byte[] reply = DomainInspector.BuildDnsSinkholeReply(pkt, localMac);

            Assert.NotNull(reply);
            Assert.Equal(0x85, reply[44]); // QR=1, AA=1, RD=1
            Assert.Equal(0x03, reply[45] & 0x0F); // NXDOMAIN
        }

        [Fact]
        public void TryExtractTlsSni_ShouldExtractSniFromContinuationSegmentViaPatternScan()
        {
            string host = "rr5---sn-ojnpo5-5q.googlevideo.com";
            byte[] hostBytes = Encoding.ASCII.GetBytes(host);
            var seg = new List<byte>
            {
                0xAA, 0xBB, 0xCC, 0xDD, // Arbitrary trailing bytes from previous TLS extension
                0x00, 0x00,             // server_name extension (0x0000)
                (byte)((5 + hostBytes.Length) >> 8), (byte)((5 + hostBytes.Length) & 0xFF),
                (byte)((3 + hostBytes.Length) >> 8), (byte)((3 + hostBytes.Length) & 0xFF),
                0x00,
                (byte)(hostBytes.Length >> 8), (byte)(hostBytes.Length & 0xFF)
            };
            seg.AddRange(hostBytes);

            bool ok = DomainInspector.TryExtractTlsSni(seg.ToArray(), 0, seg.Count, out string sni);

            Assert.True(ok);
            Assert.Equal(host, sni);
        }

        [Fact]
        public void TryMatchWellKnownAppIp_ShouldIdentifyTelegramDataCenterIp()
        {
            // 91.108.56.130 (Telegram DC5 Singapore)
            uint dc5Ip = (91u << 24) | (108u << 16) | (56u << 8) | 130u;

            bool matched = DomainInspector.TryMatchWellKnownAppIp(dc5Ip, out string domain, out string protocol);

            Assert.True(matched);
            Assert.Equal("telegram.org", domain);
            Assert.Equal("TELEGRAM", protocol);
        }

        [Fact]
        public void BlockedDomainStore_ShouldIsolatePerDeviceRulesByMacAddress()
        {
            const string macA = "02:00:00:00:00:01";
            const string macB = "02:00:00:00:00:02";
            const uint testYoutubeIp = 0x8EFABE4Eu; // 142.250.190.78

            bool globalWasBlocked = BlockedDomainStore.IsDomainBlocked("youtube.com");
            if (globalWasBlocked) return;

            bool addedForA = BlockedDomainStore.AddDomain("youtube.com", macA, "Test Device A");
            BlockedDomainStore.RegisterBlockedIp(testYoutubeIp, "www.youtube.com");

            try
            {
                Assert.True(BlockedDomainStore.IsDomainBlocked("www.youtube.com", macA));
                Assert.True(BlockedDomainStore.IsDomainBlocked("rr1---sn.googlevideo.com", macA));
                Assert.True(BlockedDomainStore.IsIpBlocked(testYoutubeIp, macA, out _));

                Assert.False(BlockedDomainStore.IsDomainBlocked("www.youtube.com", macB));
                Assert.False(BlockedDomainStore.IsDomainBlocked("rr1---sn.googlevideo.com", macB));
                Assert.False(BlockedDomainStore.IsIpBlocked(testYoutubeIp, macB, out _));
            }
            finally
            {
                if (addedForA)
                {
                    BlockedDomainStore.RemoveDomain("youtube.com", macA);
                }
            }
        }

        private static byte[] BuildSyntheticTlsClientHello(string host)
        {
            byte[] hostBytes = Encoding.ASCII.GetBytes(host);
            var ext = new List<byte>
            {
                0x00, 0x00, // server_name extension
                (byte)((5 + hostBytes.Length) >> 8), (byte)((5 + hostBytes.Length) & 0xFF),
                (byte)((3 + hostBytes.Length) >> 8), (byte)((3 + hostBytes.Length) & 0xFF),
                0x00, // host_name
                (byte)(hostBytes.Length >> 8), (byte)(hostBytes.Length & 0xFF)
            };
            ext.AddRange(hostBytes);

            var body = new List<byte>
            {
                0x03, 0x03 // TLS 1.2
            };
            body.AddRange(new byte[32]); // Random
            body.Add(0x00); // Session ID len = 0
            body.AddRange(new byte[] { 0x00, 0x02, 0x13, 0x01 }); // Cipher suites
            body.AddRange(new byte[] { 0x01, 0x00 }); // Compression
            body.Add((byte)(ext.Count >> 8));
            body.Add((byte)(ext.Count & 0xFF));
            body.AddRange(ext);

            var hs = new List<byte>
            {
                0x01, // ClientHello
                0x00, (byte)(body.Count >> 8), (byte)(body.Count & 0xFF)
            };
            hs.AddRange(body);

            var record = new List<byte>
            {
                0x16, 0x03, 0x01,
                (byte)(hs.Count >> 8), (byte)(hs.Count & 0xFF)
            };
            record.AddRange(hs);
            return record.ToArray();
        }

        private static byte[] BuildSyntheticDnsQuery(string domain)
        {
            var pkt = new List<byte>
            {
                0x12, 0x34, // Transaction ID
                0x01, 0x00, // Standard query
                0x00, 0x01, // QDCOUNT = 1
                0x00, 0x00, // ANCOUNT
                0x00, 0x00, // NSCOUNT
                0x00, 0x00  // ARCOUNT
            };
            foreach (string label in domain.Split('.'))
            {
                byte[] bytes = Encoding.ASCII.GetBytes(label);
                pkt.Add((byte)bytes.Length);
                pkt.AddRange(bytes);
            }
            pkt.Add(0x00);
            pkt.AddRange(new byte[] { 0x00, 0x01, 0x00, 0x01 }); // QTYPE A, QCLASS IN
            return pkt.ToArray();
        }

        private static byte[] WrapInEthernetIpv4Tcp(
            byte[] srcMac, byte[] dstMac, byte[] srcIp, byte[] dstIp, ushort srcPort, ushort dstPort, byte[] payload)
        {
            int ipLen = 20 + 20 + payload.Length;
            byte[] pkt = new byte[14 + ipLen];
            Array.Copy(dstMac, 0, pkt, 0, 6);
            Array.Copy(srcMac, 0, pkt, 6, 6);
            pkt[12] = 0x08; pkt[13] = 0x00;

            pkt[14] = 0x45;
            pkt[16] = (byte)(ipLen >> 8); pkt[17] = (byte)(ipLen & 0xFF);
            pkt[22] = 64;
            pkt[23] = 6; // TCP
            Array.Copy(srcIp, 0, pkt, 26, 4);
            Array.Copy(dstIp, 0, pkt, 30, 4);

            pkt[34] = (byte)(srcPort >> 8); pkt[35] = (byte)(srcPort & 0xFF);
            pkt[36] = (byte)(dstPort >> 8); pkt[37] = (byte)(dstPort & 0xFF);
            pkt[46] = 0x50;
            pkt[47] = 0x18; // PSH | ACK
            Array.Copy(payload, 0, pkt, 54, payload.Length);
            return pkt;
        }

        private static byte[] WrapInEthernetIpv4Udp(
            byte[] srcMac, byte[] dstMac, byte[] srcIp, byte[] dstIp, ushort srcPort, ushort dstPort, byte[] payload)
        {
            int udpLen = 8 + payload.Length;
            int ipLen = 20 + udpLen;
            byte[] pkt = new byte[14 + ipLen];
            Array.Copy(dstMac, 0, pkt, 0, 6);
            Array.Copy(srcMac, 0, pkt, 6, 6);
            pkt[12] = 0x08; pkt[13] = 0x00;

            pkt[14] = 0x45;
            pkt[16] = (byte)(ipLen >> 8); pkt[17] = (byte)(ipLen & 0xFF);
            pkt[22] = 64;
            pkt[23] = 17; // UDP
            Array.Copy(srcIp, 0, pkt, 26, 4);
            Array.Copy(dstIp, 0, pkt, 30, 4);

            pkt[34] = (byte)(srcPort >> 8); pkt[35] = (byte)(srcPort & 0xFF);
            pkt[36] = (byte)(dstPort >> 8); pkt[37] = (byte)(dstPort & 0xFF);
            pkt[38] = (byte)(udpLen >> 8); pkt[39] = (byte)(udpLen & 0xFF);
            Array.Copy(payload, 0, pkt, 42, payload.Length);
            return pkt;
        }
    }
}
