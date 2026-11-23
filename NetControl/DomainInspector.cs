using System;
using System.Collections.Concurrent;
using System.Net;
using System.Text;

namespace NetControl
{
    /// <summary>
    /// Menganalisis paket jaringan (TLS SNI HTTPS, DNS Query/Response, HTTP Host)
    /// serta membangun paket TCP RST, DNS Sinkhole, dan ICMP Port Unreachable untuk pemblokiran aktif.
    /// </summary>
    public static class DomainInspector
    {
        private static readonly ConcurrentDictionary<uint, string> _dnsIpToDomain = new();

        private static readonly (uint Network, uint Mask, string Domain, string Protocol)[] _wellKnownCidrs = new[]
        {
            (0x5B6C3800u, 0xFFFFFC00u, "telegram.org", "TELEGRAM"), // 91.108.56.0/22 (DC5 Singapore)
            (0x959AA000u, 0xFFFFF000u, "telegram.org", "TELEGRAM"), // 149.154.160.0/20 (DC2/DC4)
            (0x5B6C0400u, 0xFFFFFC00u, "telegram.org", "TELEGRAM"), // 91.108.4.0/22
            (0x5B6C0800u, 0xFFFFFC00u, "telegram.org", "TELEGRAM"), // 91.108.8.0/22
            (0x5B6C0C00u, 0xFFFFFC00u, "telegram.org", "TELEGRAM"), // 91.108.12.0/22
            (0x5B6C1000u, 0xFFFFFC00u, "telegram.org", "TELEGRAM"), // 91.108.16.0/22
            (0x5B6C1400u, 0xFFFFFC00u, "telegram.org", "TELEGRAM"), // 91.108.20.0/22
            (0x5B69C000u, 0xFFFFFE00u, "telegram.org", "TELEGRAM"), // 91.105.192.0/23
            (0xB94C9700u, 0xFFFFFF00u, "telegram.org", "TELEGRAM"), // 185.76.151.0/24
        };

        public static bool TryMatchWellKnownAppIp(uint ipUint, out string domain, out string protocol)
        {
            for (int i = 0; i < _wellKnownCidrs.Length; i++)
            {
                var entry = _wellKnownCidrs[i];
                if ((ipUint & entry.Mask) == entry.Network)
                {
                    domain = entry.Domain;
                    protocol = entry.Protocol;
                    return true;
                }
            }

            domain = null;
            protocol = null;
            return false;
        }

        public static bool TryInspectPacket(
            byte[] raw,
            out string domain,
            out string protocol,
            out uint srcIpUint,
            out uint dstIpUint)
        {
            domain = null;
            protocol = null;
            srcIpUint = 0;
            dstIpUint = 0;

            if (raw == null || raw.Length < 34) return false;
            if (raw[12] != 0x08 || raw[13] != 0x00) return false; // Bukan IPv4

            int ipHeaderLen = (raw[14] & 0x0F) * 4;
            if (ipHeaderLen < 20 || 14 + ipHeaderLen > raw.Length) return false;

            int ipTotalLen = ReadUInt16BE(raw, 16);
            int ipEnd = ipTotalLen >= ipHeaderLen ? Math.Min(raw.Length, 14 + ipTotalLen) : raw.Length;

            srcIpUint = ReadUInt32BE(raw, 26);
            dstIpUint = ReadUInt32BE(raw, 30);
            byte ipProto = raw[23];

            if (ipProto == 17) // UDP
            {
                int udpOffset = 14 + ipHeaderLen;
                if (udpOffset + 8 > ipEnd) return false;

                ushort srcPort = ReadUInt16BE(raw, udpOffset);
                ushort dstPort = ReadUInt16BE(raw, udpOffset + 2);
                int udpPayloadOffset = udpOffset + 8;

                if (dstPort == 53 && TryExtractDnsQuery(raw, udpPayloadOffset, out domain))
                {
                    protocol = "DNS";
                    return true;
                }

                if (srcPort == 53)
                {
                    TryExtractDnsAnswers(raw, udpPayloadOffset);
                    return false;
                }

                if (dstPort == 443 && _dnsIpToDomain.TryGetValue(dstIpUint, out domain))
                {
                    protocol = "QUIC";
                    return true;
                }

                if (TryMatchWellKnownAppIp(dstIpUint, out domain, out protocol))
                {
                    CacheIpDomain(dstIpUint, domain);
                    return true;
                }

                return false;
            }

            if (ipProto == 6) // TCP
            {
                int tcpOffset = 14 + ipHeaderLen;
                if (tcpOffset + 20 > ipEnd) return false;

                ushort dstPort = ReadUInt16BE(raw, tcpOffset + 2);
                int tcpHeaderLen = ((raw[tcpOffset + 12] >> 4) & 0x0F) * 4;
                if (tcpHeaderLen < 20 || tcpOffset + tcpHeaderLen > ipEnd) return false;

                int tcpPayloadOffset = tcpOffset + tcpHeaderLen;
                int tcpPayloadLen = ipEnd - tcpPayloadOffset;
                if (tcpPayloadLen > 5)
                {
                    if (TryExtractTlsSni(raw, tcpPayloadOffset, tcpPayloadLen, out domain))
                    {
                        CacheIpDomain(dstIpUint, domain);
                        protocol = "HTTPS";
                        return true;
                    }

                    if (TryExtractHttpHost(raw, tcpPayloadOffset, tcpPayloadLen, out domain))
                    {
                        CacheIpDomain(dstIpUint, domain);
                        protocol = "HTTP";
                        return true;
                    }
                }

                if ((dstPort == 443 || dstPort == 80) && _dnsIpToDomain.TryGetValue(dstIpUint, out domain))
                {
                    protocol = dstPort == 80 ? "HTTP" : "HTTPS";
                    return true;
                }

                if (TryMatchWellKnownAppIp(dstIpUint, out domain, out protocol))
                {
                    CacheIpDomain(dstIpUint, domain);
                    return true;
                }
            }

            return false;
        }

        private static void CacheIpDomain(uint ipUint, string domain)
        {
            if (ipUint == 0 || string.IsNullOrEmpty(domain)) return;
            if (_dnsIpToDomain.Count > 4096)
            {
                _dnsIpToDomain.Clear();
            }
            _dnsIpToDomain[ipUint] = domain;
        }

        public static bool TryExtractTlsSni(byte[] raw, int offset, int length, out string sni)
        {
            sni = null;
            if (raw == null || offset < 0 || length < 13 || offset + length > raw.Length)
            {
                return false;
            }

            // Standard TLS Record Header: ContentType 0x16 (Handshake), Version 0x03xx, Handshake Type 0x01 (ClientHello)
            if (length >= 44 && raw[offset] == 0x16 && raw[offset + 1] == 0x03 && raw[offset + 5] == 0x01)
            {
                int end = offset + length;
                // Skip Record(5) + HandshakeHeader(4) + ClientVersion(2) + Random(32) = 43 bytes
                int pos = offset + 43;
                if (pos < end)
                {
                    byte sessionIdLen = raw[pos++];
                    pos += sessionIdLen;
                    if (pos + 2 <= end)
                    {
                        ushort cipherLen = ReadUInt16BE(raw, pos);
                        pos += 2 + cipherLen;
                        if (pos + 1 <= end)
                        {
                            byte compLen = raw[pos++];
                            pos += compLen;
                            if (pos + 2 <= end)
                            {
                                ushort extTotalLen = ReadUInt16BE(raw, pos);
                                pos += 2;
                                int extEnd = Math.Min(end, pos + extTotalLen);

                                while (pos + 4 <= extEnd)
                                {
                                    ushort extType = ReadUInt16BE(raw, pos);
                                    ushort extLen = ReadUInt16BE(raw, pos + 2);
                                    pos += 4;

                                    if (pos + extLen > extEnd) break;

                                    // Extension 0x0000 = server_name (SNI)
                                    if (extType == 0x0000 && extLen >= 5)
                                    {
                                        int sniEnd = pos + extLen;
                                        int p = pos + 2; // Skip Server Name List Length
                                        while (p + 3 <= sniEnd)
                                        {
                                            byte nameType = raw[p];
                                            ushort nameLen = ReadUInt16BE(raw, p + 1);
                                            p += 3;

                                            if (p + nameLen > sniEnd) break;

                                            if (nameType == 0 && nameLen > 0)
                                            {
                                                string candidate = Encoding.ASCII.GetString(raw, p, nameLen).Trim().ToLowerInvariant();
                                                if (IsValidDomainName(candidate))
                                                {
                                                    sni = candidate;
                                                    return true;
                                                }
                                            }

                                            p += nameLen;
                                        }
                                    }

                                    pos += extLen;
                                }
                            }
                        }
                    }
                }
            }

            // Fallback for fragmented Post-Quantum TLS 1.3 ClientHello segments
            return TryScanTlsSniPattern(raw, offset, length, out sni);
        }

        private static bool TryScanTlsSniPattern(byte[] raw, int offset, int length, out string sni)
        {
            sni = null;
            int end = offset + length;
            for (int i = offset; i <= end - 13; i++)
            {
                if (raw[i] != 0x00 || raw[i + 1] != 0x00 || raw[i + 6] != 0x00) continue;

                ushort extLen = ReadUInt16BE(raw, i + 2);
                ushort listLen = ReadUInt16BE(raw, i + 4);
                ushort nameLen = ReadUInt16BE(raw, i + 7);

                if (nameLen >= 4 && nameLen <= 253 &&
                    listLen == nameLen + 3 &&
                    extLen == listLen + 2 &&
                    i + 9 + nameLen <= end)
                {
                    string candidate = Encoding.ASCII.GetString(raw, i + 9, nameLen).Trim().ToLowerInvariant();
                    if (IsValidDomainName(candidate))
                    {
                        sni = candidate;
                        return true;
                    }
                }
            }

            return false;
        }

        public static bool TryExtractDnsQuery(byte[] raw, int dnsOffset, out string domain)
        {
            domain = null;
            if (raw == null || dnsOffset < 0 || dnsOffset + 12 >= raw.Length) return false;

            // QR bit == 0 (Query), QDCOUNT > 0
            bool isQuery = (raw[dnsOffset + 2] & 0x80) == 0;
            int qdCount = ReadUInt16BE(raw, dnsOffset + 4);
            if (!isQuery || qdCount == 0) return false;

            int pos = dnsOffset + 12;
            string qname = ReadDnsLabels(raw, ref pos);
            if (string.IsNullOrEmpty(qname)) return false;

            qname = qname.Trim().ToLowerInvariant();
            if (!IsValidDomainName(qname)) return false;

            if (qname.EndsWith(".arpa", StringComparison.Ordinal) ||
                qname.EndsWith(".local", StringComparison.Ordinal) ||
                qname.EndsWith(".lan", StringComparison.Ordinal) ||
                qname.Equals("wpad", StringComparison.Ordinal) ||
                qname.StartsWith("wpad.", StringComparison.Ordinal) ||
                qname.Equals("isatap", StringComparison.Ordinal))
            {
                return false;
            }

            domain = qname;
            return true;
        }

        public static void TryExtractDnsAnswers(byte[] raw, int dnsOffset)
        {
            if (raw == null || dnsOffset < 0 || dnsOffset + 12 >= raw.Length) return;

            bool isResponse = (raw[dnsOffset + 2] & 0x80) != 0;
            if (!isResponse) return;

            int qdCount = ReadUInt16BE(raw, dnsOffset + 4);
            int anCount = ReadUInt16BE(raw, dnsOffset + 6);
            if (anCount == 0) return;

            int pos = dnsOffset + 12;
            string queriedDomain = null;

            for (int q = 0; q < qdCount && pos < raw.Length; q++)
            {
                string qName = ReadDnsNameAt(raw, dnsOffset, ref pos);
                if (q == 0) queriedDomain = qName;
                pos += 4; // QTYPE + QCLASS
            }

            for (int a = 0; a < anCount && pos + 10 <= raw.Length; a++)
            {
                string rrName = ReadDnsNameAt(raw, dnsOffset, ref pos);
                if (pos + 10 > raw.Length) break;

                ushort type = ReadUInt16BE(raw, pos);
                ushort rdLen = ReadUInt16BE(raw, pos + 8);
                pos += 10;

                if (pos + rdLen > raw.Length) break;

                if (type == 1 && rdLen == 4) // A record (IPv4)
                {
                    uint ipUint = ReadUInt32BE(raw, pos);
                    string targetDomain = !string.IsNullOrEmpty(queriedDomain) ? queriedDomain : rrName;
                    if (!string.IsNullOrEmpty(targetDomain) && IsValidDomainName(targetDomain))
                    {
                        if (_dnsIpToDomain.Count > 4096)
                        {
                            _dnsIpToDomain.Clear();
                        }
                        _dnsIpToDomain[ipUint] = targetDomain;

                        if (BlockedDomainStore.IsDomainBlocked(targetDomain) ||
                            (!string.IsNullOrEmpty(rrName) && BlockedDomainStore.IsDomainBlocked(rrName)))
                        {
                            BlockedDomainStore.RegisterBlockedIp(ipUint, targetDomain);
                        }
                    }
                }

                pos += rdLen;
            }
        }

        public static bool TryGetCachedIpDomain(uint ipUint, out string domain)
        {
            return _dnsIpToDomain.TryGetValue(ipUint, out domain);
        }

        public static bool TryExtractHttpHost(byte[] raw, int offset, int length, out string host)
        {
            host = null;
            if (raw == null || offset < 0 || length < 16 || offset + length > raw.Length)
            {
                return false;
            }

            int inspectLen = Math.Min(length, 1024);
            string text = Encoding.ASCII.GetString(raw, offset, inspectLen);

            if (!text.StartsWith("GET ", StringComparison.Ordinal) &&
                !text.StartsWith("POST ", StringComparison.Ordinal) &&
                !text.StartsWith("HEAD ", StringComparison.Ordinal) &&
                !text.StartsWith("PUT ", StringComparison.Ordinal) &&
                !text.StartsWith("OPTIONS ", StringComparison.Ordinal) &&
                !text.StartsWith("CONNECT ", StringComparison.Ordinal))
            {
                return false;
            }

            string[] lines = text.Split('\n');
            foreach (string rawLine in lines)
            {
                string line = rawLine.Trim();
                if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                {
                    string h = line.Substring(5).Trim().ToLowerInvariant();
                    int colonIdx = h.IndexOf(':');
                    if (colonIdx > 0) h = h.Substring(0, colonIdx);

                    if (IsValidDomainName(h))
                    {
                        host = h;
                        return true;
                    }
                }
            }

            return false;
        }

        // ──────────────────────────────────────────────
        //  Active Blocking Packet Builders
        // ──────────────────────────────────────────────

        public static byte[] BuildTcpResetToClient(byte[] rawPacket, byte[] localMac)
        {
            if (rawPacket == null || localMac == null || localMac.Length < 6 || rawPacket.Length < 54) return null;
            if (rawPacket[12] != 0x08 || rawPacket[13] != 0x00 || rawPacket[23] != 6) return null;

            int ipHeaderLen = (rawPacket[14] & 0x0F) * 4;
            int ipTotalLen = ReadUInt16BE(rawPacket, 16);
            int tcpOffset = 14 + ipHeaderLen;
            if (tcpOffset + 20 > rawPacket.Length) return null;

            int tcpHeaderLen = ((rawPacket[tcpOffset + 12] >> 4) & 0x0F) * 4;
            int payloadLen = Math.Max(0, ipTotalLen - ipHeaderLen - tcpHeaderLen);
            byte incomingFlags = rawPacket[tcpOffset + 13];
            uint incomingSeq = ReadUInt32BE(rawPacket, tcpOffset + 4);
            uint incomingAck = ReadUInt32BE(rawPacket, tcpOffset + 8);

            uint ackAdvance = payloadLen > 0 ? (uint)payloadLen : ((incomingFlags & 0x02) != 0 ? 1u : 0u);
            uint replySeq = incomingAck;
            uint replyAck = incomingSeq + ackAdvance;

            byte[] pkt = new byte[54]; // Eth(14) + IPv4(20) + TCP(20)
            Array.Copy(rawPacket, 6, pkt, 0, 6); // Eth dst = client srcMac
            Array.Copy(localMac, 0, pkt, 6, 6);  // Eth src = localMac
            pkt[12] = 0x08; pkt[13] = 0x00;

            // IPv4 Header (swap src & dst)
            pkt[14] = 0x45;
            pkt[15] = 0x00;
            WriteUInt16BE(pkt, 16, 40);
            WriteUInt16BE(pkt, 18, 0x1234);
            WriteUInt16BE(pkt, 20, 0x4000);
            pkt[22] = 64;
            pkt[23] = 6; // TCP
            Array.Copy(rawPacket, 30, pkt, 26, 4); // Src IP = original Dst IP
            Array.Copy(rawPacket, 26, pkt, 30, 4); // Dst IP = original Src IP
            WriteUInt16BE(pkt, 24, ComputeChecksum(pkt, 14, 20));

            // TCP Header (swap ports, RST+ACK = 0x14)
            Array.Copy(rawPacket, tcpOffset + 2, pkt, 34, 2); // SrcPort = original DstPort
            Array.Copy(rawPacket, tcpOffset, pkt, 36, 2);     // DstPort = original SrcPort
            WriteUInt32BE(pkt, 38, replySeq);
            WriteUInt32BE(pkt, 42, replyAck);
            pkt[46] = 0x50; // Header len = 20 bytes
            pkt[47] = 0x14; // RST | ACK
            WriteUInt16BE(pkt, 48, 0);
            WriteUInt16BE(pkt, 50, ComputeTcpChecksum(pkt, 26, 30, 34, 20));

            return pkt;
        }

        public static byte[] BuildTcpResetToServer(byte[] rawPacket, byte[] localMac, byte[] routerMac)
        {
            if (rawPacket == null || localMac == null || routerMac == null ||
                localMac.Length < 6 || routerMac.Length < 6 || rawPacket.Length < 54) return null;
            if (rawPacket[12] != 0x08 || rawPacket[13] != 0x00 || rawPacket[23] != 6) return null;

            int ipHeaderLen = (rawPacket[14] & 0x0F) * 4;
            int ipTotalLen = ReadUInt16BE(rawPacket, 16);
            int tcpOffset = 14 + ipHeaderLen;
            if (tcpOffset + 20 > rawPacket.Length) return null;

            int tcpHeaderLen = ((rawPacket[tcpOffset + 12] >> 4) & 0x0F) * 4;
            int payloadLen = Math.Max(0, ipTotalLen - ipHeaderLen - tcpHeaderLen);
            uint incomingSeq = ReadUInt32BE(rawPacket, tcpOffset + 4);

            byte[] pkt = new byte[54];
            Array.Copy(routerMac, 0, pkt, 0, 6);
            Array.Copy(localMac, 0, pkt, 6, 6);
            pkt[12] = 0x08; pkt[13] = 0x00;

            pkt[14] = 0x45;
            pkt[15] = 0x00;
            WriteUInt16BE(pkt, 16, 40);
            WriteUInt16BE(pkt, 18, 0x1235);
            WriteUInt16BE(pkt, 20, 0x4000);
            pkt[22] = 64;
            pkt[23] = 6;
            Array.Copy(rawPacket, 26, pkt, 26, 4);
            Array.Copy(rawPacket, 30, pkt, 30, 4);
            WriteUInt16BE(pkt, 24, ComputeChecksum(pkt, 14, 20));

            Array.Copy(rawPacket, tcpOffset, pkt, 34, 2);
            Array.Copy(rawPacket, tcpOffset + 2, pkt, 36, 2);
            WriteUInt32BE(pkt, 38, incomingSeq + (uint)payloadLen);
            WriteUInt32BE(pkt, 42, 0);
            pkt[46] = 0x50;
            pkt[47] = 0x04; // RST
            WriteUInt16BE(pkt, 48, 0);
            WriteUInt16BE(pkt, 50, ComputeTcpChecksum(pkt, 26, 30, 34, 20));

            return pkt;
        }

        public static byte[] BuildTcpResetFromServerPacket(byte[] rawDownloadPacket, byte[] localMac, byte[] clientMac)
        {
            if (rawDownloadPacket == null || localMac == null || clientMac == null ||
                localMac.Length < 6 || clientMac.Length < 6 || rawDownloadPacket.Length < 54) return null;
            if (rawDownloadPacket[12] != 0x08 || rawDownloadPacket[13] != 0x00 || rawDownloadPacket[23] != 6) return null;

            int ipHeaderLen = (rawDownloadPacket[14] & 0x0F) * 4;
            int tcpOffset = 14 + ipHeaderLen;
            if (ipHeaderLen < 20 || tcpOffset + 20 > rawDownloadPacket.Length) return null;

            uint incomingSeq = ReadUInt32BE(rawDownloadPacket, tcpOffset + 4);

            byte[] pkt = new byte[54];
            Array.Copy(clientMac, 0, pkt, 0, 6);
            Array.Copy(localMac, 0, pkt, 6, 6);
            pkt[12] = 0x08; pkt[13] = 0x00;

            pkt[14] = 0x45;
            pkt[15] = 0x00;
            WriteUInt16BE(pkt, 16, 40);
            WriteUInt16BE(pkt, 18, 0x1238);
            WriteUInt16BE(pkt, 20, 0x4000);
            pkt[22] = 64;
            pkt[23] = 6;
            Array.Copy(rawDownloadPacket, 26, pkt, 26, 4); // Preserve server Src IP
            Array.Copy(rawDownloadPacket, 30, pkt, 30, 4); // Preserve client Dst IP
            WriteUInt16BE(pkt, 24, ComputeChecksum(pkt, 14, 20));

            Array.Copy(rawDownloadPacket, tcpOffset, pkt, 34, 2);     // Preserve server Src Port
            Array.Copy(rawDownloadPacket, tcpOffset + 2, pkt, 36, 2); // Preserve client Dst Port
            WriteUInt32BE(pkt, 38, incomingSeq);
            WriteUInt32BE(pkt, 42, 0);
            pkt[46] = 0x50;
            pkt[47] = 0x04; // RST
            WriteUInt16BE(pkt, 48, 0);
            WriteUInt16BE(pkt, 50, ComputeTcpChecksum(pkt, 26, 30, 34, 20));

            return pkt;
        }

        public static byte[] BuildDnsSinkholeReply(byte[] rawPacket, byte[] localMac)
        {
            if (rawPacket == null || localMac == null || localMac.Length < 6 || rawPacket.Length < 55) return null;
            if (rawPacket[12] != 0x08 || rawPacket[13] != 0x00 || rawPacket[23] != 17) return null;

            int ipHeaderLen = (rawPacket[14] & 0x0F) * 4;
            int udpOffset = 14 + ipHeaderLen;
            int dnsOffset = udpOffset + 8;
            if (dnsOffset + 12 >= rawPacket.Length) return null;

            // Find end of first DNS question (QNAME + QTYPE(2) + QCLASS(2))
            int qPos = dnsOffset + 12;
            while (qPos < rawPacket.Length && rawPacket[qPos] != 0)
            {
                byte len = rawPacket[qPos];
                if ((len & 0xC0) == 0xC0)
                {
                    qPos += 2;
                    break;
                }
                qPos += 1 + len;
            }
            if (qPos < rawPacket.Length && rawPacket[qPos] == 0) qPos++;
            qPos += 4; // QTYPE + QCLASS
            if (qPos > rawPacket.Length) return null;

            int dnsLen = qPos - dnsOffset;
            int udpLen = 8 + dnsLen;
            int ipLen = 20 + udpLen;
            byte[] pkt = new byte[14 + ipLen];

            Array.Copy(rawPacket, 6, pkt, 0, 6);
            Array.Copy(localMac, 0, pkt, 6, 6);
            pkt[12] = 0x08; pkt[13] = 0x00;

            pkt[14] = 0x45;
            pkt[15] = 0x00;
            WriteUInt16BE(pkt, 16, (ushort)ipLen);
            WriteUInt16BE(pkt, 18, 0x1236);
            WriteUInt16BE(pkt, 20, 0x0000);
            pkt[22] = 64;
            pkt[23] = 17; // UDP
            Array.Copy(rawPacket, 30, pkt, 26, 4);
            Array.Copy(rawPacket, 26, pkt, 30, 4);
            WriteUInt16BE(pkt, 24, ComputeChecksum(pkt, 14, 20));

            // UDP header (swap ports)
            Array.Copy(rawPacket, udpOffset + 2, pkt, 34, 2);
            Array.Copy(rawPacket, udpOffset, pkt, 36, 2);
            WriteUInt16BE(pkt, 38, (ushort)udpLen);
            WriteUInt16BE(pkt, 40, 0); // Checksum optional for IPv4 UDP

            // DNS header + first Question
            Array.Copy(rawPacket, dnsOffset, pkt, 42, dnsLen);
            pkt[44] = 0x85; // QR=1, AA=1, RD=1
            pkt[45] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
            WriteUInt16BE(pkt, 46, 1); // QDCOUNT = 1
            WriteUInt16BE(pkt, 48, 0); // ANCOUNT = 0
            WriteUInt16BE(pkt, 50, 0); // NSCOUNT = 0
            WriteUInt16BE(pkt, 52, 0); // ARCOUNT = 0

            return pkt;
        }

        public static byte[] BuildIcmpPortUnreachable(byte[] rawPacket, byte[] localMac)
        {
            if (rawPacket == null || localMac == null || localMac.Length < 6 || rawPacket.Length < 42) return null;
            if (rawPacket[12] != 0x08 || rawPacket[13] != 0x00) return null;

            int origIpHeaderLen = (rawPacket[14] & 0x0F) * 4;
            int quotedLen = Math.Min(origIpHeaderLen + 8, rawPacket.Length - 14);
            if (quotedLen < 20) return null;

            int icmpLen = 8 + quotedLen;
            int ipLen = 20 + icmpLen;
            byte[] pkt = new byte[14 + ipLen];

            Array.Copy(rawPacket, 6, pkt, 0, 6);
            Array.Copy(localMac, 0, pkt, 6, 6);
            pkt[12] = 0x08; pkt[13] = 0x00;

            pkt[14] = 0x45;
            pkt[15] = 0x00;
            WriteUInt16BE(pkt, 16, (ushort)ipLen);
            WriteUInt16BE(pkt, 18, 0x1237);
            WriteUInt16BE(pkt, 20, 0x0000);
            pkt[22] = 64;
            pkt[23] = 1; // ICMP
            Array.Copy(rawPacket, 30, pkt, 26, 4);
            Array.Copy(rawPacket, 26, pkt, 30, 4);
            WriteUInt16BE(pkt, 24, ComputeChecksum(pkt, 14, 20));

            pkt[34] = 3; // Destination Unreachable
            pkt[35] = 3; // Port Unreachable
            WriteUInt16BE(pkt, 36, 0);
            WriteUInt32BE(pkt, 38, 0);
            Array.Copy(rawPacket, 14, pkt, 42, quotedLen);
            WriteUInt16BE(pkt, 36, ComputeChecksum(pkt, 34, icmpLen));

            return pkt;
        }

        // ──────────────────────────────────────────────
        //  Parsing & Checksum Helpers
        // ──────────────────────────────────────────────

        private static string ReadDnsLabels(byte[] data, ref int pos)
        {
            var sb = new StringBuilder(64);
            int safety = 0;

            while (pos < data.Length && safety++ < 40)
            {
                byte len = data[pos];
                if (len == 0)
                {
                    pos++;
                    break;
                }
                if ((len & 0xC0) == 0xC0)
                {
                    pos += 2;
                    break;
                }
                pos++;
                if (pos + len > data.Length) return null;

                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(data, pos, len));
                pos += len;
            }

            return sb.ToString();
        }

        private static string ReadDnsNameAt(byte[] data, int dnsOffset, ref int pos)
        {
            var sb = new StringBuilder(64);
            int cur = pos;
            bool jumped = false;
            int safety = 0;

            while (cur < data.Length && safety++ < 40)
            {
                byte len = data[cur];
                if (len == 0)
                {
                    if (!jumped) pos = cur + 1;
                    break;
                }

                if ((len & 0xC0) == 0xC0)
                {
                    if (cur + 1 >= data.Length) break;
                    if (!jumped) pos = cur + 2;
                    int relOffset = ((len & 0x3F) << 8) | data[cur + 1];
                    cur = dnsOffset + relOffset;
                    jumped = true;
                    continue;
                }

                cur++;
                if (cur + len > data.Length) break;

                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(data, cur, len));
                cur += len;
                if (!jumped) pos = cur;
            }

            return sb.ToString().ToLowerInvariant();
        }

        private static bool IsValidDomainName(string candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate) || candidate.Length > 253 ||
                !candidate.Contains('.') || candidate.StartsWith('.') || candidate.EndsWith('.'))
                return false;

            if (IPAddress.TryParse(candidate, out _))
                return false;

            bool hasLetter = false;
            foreach (char c in candidate)
            {
                if (char.IsLetter(c)) hasLetter = true;
                if (!(char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_'))
                    return false;
            }
            return hasLetter;
        }

        private static ushort ReadUInt16BE(byte[] data, int offset)
        {
            return (ushort)((data[offset] << 8) | data[offset + 1]);
        }

        private static uint ReadUInt32BE(byte[] data, int offset)
        {
            return (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);
        }

        private static void WriteUInt16BE(byte[] data, int offset, ushort value)
        {
            data[offset] = (byte)(value >> 8);
            data[offset + 1] = (byte)(value & 0xFF);
        }

        private static void WriteUInt32BE(byte[] data, int offset, uint value)
        {
            data[offset] = (byte)(value >> 24);
            data[offset + 1] = (byte)((value >> 16) & 0xFF);
            data[offset + 2] = (byte)((value >> 8) & 0xFF);
            data[offset + 3] = (byte)(value & 0xFF);
        }

        private static ushort ComputeChecksum(byte[] data, int offset, int length)
        {
            uint sum = 0;
            int i = offset;
            while (i + 1 < offset + length)
            {
                sum += (uint)((data[i] << 8) | data[i + 1]);
                i += 2;
            }
            if (i < offset + length)
            {
                sum += (uint)(data[i] << 8);
            }
            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            return (ushort)~sum;
        }

        private static ushort ComputeTcpChecksum(byte[] pkt, int srcIpOffset, int dstIpOffset, int tcpOffset, int tcpLength)
        {
            uint sum = 0;
            // Pseudo-header: Src IP (4) + Dst IP (4) + Protocol (6) + TCP Length
            sum += ReadUInt16BE(pkt, srcIpOffset);
            sum += ReadUInt16BE(pkt, srcIpOffset + 2);
            sum += ReadUInt16BE(pkt, dstIpOffset);
            sum += ReadUInt16BE(pkt, dstIpOffset + 2);
            sum += 6;
            sum += (uint)tcpLength;

            int i = tcpOffset;
            while (i + 1 < tcpOffset + tcpLength)
            {
                sum += (uint)((pkt[i] << 8) | pkt[i + 1]);
                i += 2;
            }
            if (i < tcpOffset + tcpLength)
            {
                sum += (uint)(pkt[i] << 8);
            }
            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            return (ushort)~sum;
        }
    }
}
