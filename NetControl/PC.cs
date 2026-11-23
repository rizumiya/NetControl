using System;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Threading;
using Avalonia.Threading;

namespace NetControl
{
    public class PC : INotifyPropertyChanged
    {
        // ── Display properties (XAML bindings) ──

        public string IpDisplay => Ip?.ToString() ?? "—";
        public string MacDisplay => Mac?.ToString() ?? "—";

        /// <summary>
        /// Formatted colon-delimited MAC address (e.g. "74:D8:3E:6E:1B:C6") for tabular readability.
        /// </summary>
        public string MacFormatted
        {
            get
            {
                if (Mac == null) return "—";
                string macStr = Mac.ToString();
                if (macStr.Length == 12)
                {
                    return $"{macStr[0..2]}:{macStr[2..4]}:{macStr[4..6]}:{macStr[6..8]}:{macStr[8..10]}:{macStr[10..12]}";
                }
                return macStr;
            }
        }

        // ── Core network properties ──

        private IPAddress _ip;
        public IPAddress Ip
        {
            get => _ip;
            set { if (_ip != value) { _ip = value; OnPropertyChanged(); OnPropertyChanged(nameof(IpDisplay)); } }
        }

        private PhysicalAddress _mac;
        public PhysicalAddress Mac
        {
            get => _mac;
            set { if (_mac != value) { _mac = value; OnPropertyChanged(); OnPropertyChanged(nameof(MacDisplay)); OnPropertyChanged(nameof(MacFormatted)); OnPropertyChanged(nameof(AutoDetectedLabel)); OnPropertyChanged(nameof(DeviceLabel)); OnPropertyChanged(nameof(DeviceTooltip)); } }
        }

        public string Name { get; set; } = "Unknown";

        // ── Device identification ──

        private string _vendor;
        public string Vendor
        {
            get => _vendor;
            set { if (_vendor != value) { _vendor = value; OnPropertyChanged(); OnPropertyChanged(nameof(AutoDetectedLabel)); OnPropertyChanged(nameof(DeviceLabel)); OnPropertyChanged(nameof(DeviceTooltip)); } }
        }

        private string _hostname;
        public string Hostname
        {
            get => _hostname;
            set { if (_hostname != value) { _hostname = value; OnPropertyChanged(); OnPropertyChanged(nameof(AutoDetectedLabel)); OnPropertyChanged(nameof(DeviceLabel)); OnPropertyChanged(nameof(DeviceTooltip)); } }
        }

        private DeviceType _deviceCategory = DeviceType.Unknown;
        public DeviceType DeviceCategory
        {
            get => _deviceCategory;
            set { if (_deviceCategory != value) { _deviceCategory = value; OnPropertyChanged(); OnPropertyChanged(nameof(AutoDetectedLabel)); OnPropertyChanged(nameof(DeviceLabel)); OnPropertyChanged(nameof(DeviceTooltip)); OnPropertyChanged(nameof(CategoryName)); } }
        }

        public string CategoryName => _deviceCategory != DeviceType.Unknown ? _deviceCategory.ToString() : "Device";

        private string _customLabel;
        public string CustomLabel
        {
            get => _customLabel;
            set
            {
                if (_customLabel != value)
                {
                    _customLabel = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(HasCustomLabel));
                    OnPropertyChanged(nameof(DeviceLabel));
                    OnPropertyChanged(nameof(DeviceTooltip));
                }
            }
        }

        public bool HasCustomLabel => !string.IsNullOrWhiteSpace(_customLabel);

        private bool _isEditingLabel;
        public bool IsEditingLabel
        {
            get => _isEditingLabel;
            set
            {
                if (_isEditingLabel != value)
                {
                    _isEditingLabel = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(IsNotEditingLabel));
                }
            }
        }

        public bool IsNotEditingLabel => !_isEditingLabel;

        private string _editLabelBuffer = string.Empty;
        public string EditLabelBuffer
        {
            get => _editLabelBuffer;
            set
            {
                if (_editLabelBuffer != value)
                {
                    _editLabelBuffer = value;
                    OnPropertyChanged();
                }
            }
        }

        public string DeviceLabel => HasCustomLabel ? TruncateWithEllipsis(_customLabel.Trim(), 55) : AutoDetectedLabel;

        public string DeviceTooltip => HasCustomLabel ? $"{_customLabel.Trim()} ({AutoDetectedLabel})" : AutoDetectedLabel;

        private string _lastDomain;
        public string LastDomain
        {
            get => _lastDomain;
            set
            {
                if (_lastDomain != value)
                {
                    _lastDomain = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(HasLastDomain));
                    OnPropertyChanged(nameof(LastDomainDisplay));
                }
            }
        }

        private bool _isLastDomainBlocked;
        public bool IsLastDomainBlocked
        {
            get => _isLastDomainBlocked;
            set
            {
                if (_isLastDomainBlocked != value)
                {
                    _isLastDomainBlocked = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(LastDomainDisplay));
                    OnPropertyChanged(nameof(LastDomainBrushHex));
                }
            }
        }

        public bool HasLastDomain => !string.IsNullOrEmpty(_lastDomain);
        public string LastDomainDisplay => HasLastDomain ? (IsLastDomainBlocked ? $"🚫 {_lastDomain}" : $"🌐 {_lastDomain}") : string.Empty;
        public string LastDomainBrushHex => IsLastDomainBlocked ? "#F85149" : "#58A6FF";

        private string _activeScheduleNote = string.Empty;
        public string ActiveScheduleNote
        {
            get => _activeScheduleNote;
            set
            {
                string val = value ?? string.Empty;
                if (!string.Equals(_activeScheduleNote, val, StringComparison.Ordinal))
                {
                    _activeScheduleNote = val;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(HasActiveScheduleNote));
                }
            }
        }

        public bool HasActiveScheduleNote => !string.IsNullOrEmpty(_activeScheduleNote);

        /// <summary>
        /// Computed display label for UI: combines device type, vendor, and hostname.
        /// Falls back to formatted MAC address when no identification is available.
        /// </summary>
        public string AutoDetectedLabel
        {
            get
            {
                if (IsLocalPc)
                {
                    string localHostName = !string.IsNullOrEmpty(_hostname) &&
                                          !_hostname.EndsWith(".arpa", StringComparison.OrdinalIgnoreCase) &&
                                          !IPAddress.TryParse(_hostname, out _)
                                          ? _hostname.Trim()
                                          : Environment.MachineName;

                    return TruncateWithEllipsis($"{localHostName} (Local Host)", 55);
                }

                string type = _deviceCategory != DeviceType.Unknown ? _deviceCategory.ToString() : null;
                string name = !string.IsNullOrEmpty(_hostname) && !_hostname.EndsWith(".arpa", StringComparison.OrdinalIgnoreCase) ? _hostname.Trim() : null;
                bool isRandomized = string.Equals(_vendor, "Randomized MAC", StringComparison.Ordinal);
                string vendor = !string.IsNullOrEmpty(_vendor) && !isRandomized ? _vendor.Trim() : null;

                bool vendorRedundant = false;
                if (name != null && vendor != null)
                {
                    if (name.Contains(vendor, StringComparison.OrdinalIgnoreCase) ||
                        vendor.Contains(name, StringComparison.OrdinalIgnoreCase))
                    {
                        vendorRedundant = true;
                    }
                    else
                    {
                        var tokens = vendor.Split(new[] { ' ', ',', '-', '.', '_' }, StringSplitOptions.RemoveEmptyEntries);
                        if (tokens.Length > 0 && tokens[0].Length >= 3 && name.Contains(tokens[0], StringComparison.OrdinalIgnoreCase))
                        {
                            vendorRedundant = true;
                        }
                    }
                }

                string rawLabel;
                if (type != null && name != null && vendor != null)
                {
                    if (vendorRedundant)
                        rawLabel = $"{type} — {name}";
                    else
                        rawLabel = $"{type} — {name} ({vendor})";
                }
                else if (type != null && name != null)
                {
                    rawLabel = $"{type} — {name}";
                }
                else if (type != null && vendor != null)
                {
                    rawLabel = $"{type} ({vendor})";
                }
                else if (name != null && vendor != null)
                {
                    if (vendorRedundant)
                        rawLabel = name;
                    else
                        rawLabel = $"{name} ({vendor})";
                }
                else if (name != null)
                {
                    rawLabel = name;
                }
                else if (vendor != null)
                {
                    rawLabel = vendor;
                }
                else if (Mac != null)
                {
                    string macStr = Mac.ToString();
                    if (macStr.Length == 12)
                    {
                        string prefix = isRandomized ? "Randomized " : "";
                        rawLabel = $"{prefix}{macStr[0..2]}:{macStr[2..4]}:{macStr[4..6]}:{macStr[6..8]}:{macStr[8..10]}:{macStr[10..12]}";
                    }
                    else
                    {
                        rawLabel = "Perangkat Tidak Dikenal";
                    }
                }
                else
                {
                    rawLabel = "Perangkat Tidak Dikenal";
                }

                return TruncateWithEllipsis(rawLabel, 55);
            }
        }

        private static string TruncateWithEllipsis(string value, int maxLen = 55)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLen) return value;
            return string.Concat(value.AsSpan(0, maxLen - 1), "…");
        }

        private bool _redirect = false;
        public bool Redirect
        {
            get => _redirect;
            set
            {
                if (CanControl && _redirect != value)
                {
                    _redirect = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(IsThrottlingEnabled));
                    if (_redirect && _block)
                    {
                        _block = false;
                        OnPropertyChanged(nameof(Block));
                    }
                    if (!_redirect)
                    {
                        IsLastDomainBlocked = false;
                        LastDomain = null;
                    }
                }
            }
        }

        private bool _block = false;
        public bool Block
        {
            get => _block;
            set
            {
                if (CanControl && _block != value)
                {
                    _block = value;
                    OnPropertyChanged();
                    if (_block && _redirect)
                    {
                        _redirect = false;
                        OnPropertyChanged(nameof(Redirect));
                        OnPropertyChanged(nameof(IsThrottlingEnabled));
                        IsLastDomainBlocked = false;
                        LastDomain = null;
                    }
                }
            }
        }

        private int _bandwidthLimitKb = 0;
        /// <summary>Allowed bandwidth limit in KB/s (0 = Unlimited).</summary>
        public int BandwidthLimitKb
        {
            get => _bandwidthLimitKb;
            set
            {
                int clamped = Math.Max(0, value);
                if (_bandwidthLimitKb != clamped)
                {
                    _bandwidthLimitKb = clamped;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(BandwidthLimitDisplay));
                }
            }
        }

        public string BandwidthLimitDisplay => _bandwidthLimitKb == 0 ? "Tanpa Batas" : $"{_bandwidthLimitKb} KB/s";

        private bool _isGateway;
        public bool IsGateway
        {
            get => _isGateway;
            set
            {
                if (_isGateway != value)
                {
                    _isGateway = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(CanControl));
                    OnPropertyChanged(nameof(IsThrottlingEnabled));
                    OnPropertyChanged(nameof(HasRoleBadge));
                    OnPropertyChanged(nameof(RoleBadgeText));
                }
            }
        }

        private bool _isLocalPc;
        public bool IsLocalPc
        {
            get => _isLocalPc;
            set
            {
                if (_isLocalPc != value)
                {
                    _isLocalPc = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(CanControl));
                    OnPropertyChanged(nameof(IsThrottlingEnabled));
                    OnPropertyChanged(nameof(HasRoleBadge));
                    OnPropertyChanged(nameof(RoleBadgeText));
                }
            }
        }

        public bool HasRoleBadge => IsLocalPc || IsGateway;
        public string RoleBadgeText => IsLocalPc ? "ANDA" : (IsGateway ? "GATEWAY" : "");

        public bool CanControl => !IsLocalPc && !IsGateway;

        public bool IsThrottlingEnabled => CanControl && _redirect;

        // ── Tracking ──

        public DateTime TimeSinceLastArp { get; set; }

        private long _bytesSent;
        private long _bytesReceived;
        private long _totalBytesSent;
        private long _totalBytesReceived;

        /// <summary>Bytes sent in current monitoring cycle.</summary>
        public long BytesSent
        {
            get => Interlocked.Read(ref _bytesSent);
            set => Interlocked.Exchange(ref _bytesSent, value);
        }

        /// <summary>Bytes received in current monitoring cycle.</summary>
        public long BytesReceived
        {
            get => Interlocked.Read(ref _bytesReceived);
            set => Interlocked.Exchange(ref _bytesReceived, value);
        }

        public long TotalBytesSent => Interlocked.Read(ref _totalBytesSent);
        public long TotalBytesReceived => Interlocked.Read(ref _totalBytesReceived);
        public long TotalBytesCombined => TotalBytesReceived + TotalBytesSent;

        public string TotalDownloadFormatted => FormatDataSize(TotalBytesReceived);
        public string TotalUploadFormatted => FormatDataSize(TotalBytesSent);
        public string TotalDataFormatted => FormatDataSize(TotalBytesCombined);

        private int _dataQuotaMb = 0;
        public int DataQuotaMb
        {
            get => _dataQuotaMb;
            set
            {
                int clamped = Math.Max(0, value);
                if (_dataQuotaMb != clamped)
                {
                    _dataQuotaMb = clamped;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(DataQuotaDisplay));
                    OnPropertyChanged(nameof(TotalDataLineDisplay));
                    OnPropertyChanged(nameof(TotalDataTooltip));
                    OnPropertyChanged(nameof(TotalDataBrushHex));
                    OnPropertyChanged(nameof(IsQuotaExceeded));
                }
            }
        }

        public string DataQuotaDisplay => _dataQuotaMb <= 0 ? "Tanpa Batas" : $"{_dataQuotaMb} MB";
        public bool IsQuotaExceeded => _dataQuotaMb > 0 && TotalBytesCombined >= (long)_dataQuotaMb * 1024L * 1024L;
        public string TotalDataLineDisplay => _dataQuotaMb > 0 ? $"{TotalDataFormatted} / {_dataQuotaMb} MB" : TotalDataFormatted;
        public string TotalDataTooltip => $"Total Unduh: {TotalDownloadFormatted} | Total Unggah: {TotalUploadFormatted} | Kuota: {DataQuotaDisplay}";
        public string TotalDataBrushHex => IsQuotaExceeded ? "#F85149" : (TotalBytesCombined > 0 ? "#8B949E" : "#6E7681");

        private string _lastReportedTotalDownText = "0 B";
        private string _lastReportedTotalUpText = "0 B";
        private string _lastReportedTotalCombinedText = "0 B";

        public void AddBytesSent(long count)
        {
            Interlocked.Add(ref _bytesSent, count);
            Interlocked.Add(ref _totalBytesSent, count);
        }

        public void AddBytesReceived(long count)
        {
            Interlocked.Add(ref _bytesReceived, count);
            Interlocked.Add(ref _totalBytesReceived, count);
        }

        public (long rx, long tx) ResetByteAccumulators()
        {
            long rx = Interlocked.Exchange(ref _bytesReceived, 0);
            long tx = Interlocked.Exchange(ref _bytesSent, 0);
            return (rx, tx);
        }

        public void ResetTotalData()
        {
            Interlocked.Exchange(ref _totalBytesReceived, 0);
            Interlocked.Exchange(ref _totalBytesSent, 0);
            _lastReportedTotalDownText = "0 B";
            _lastReportedTotalUpText = "0 B";
            _lastReportedTotalCombinedText = "0 B";
            OnPropertyChanged(nameof(TotalBytesReceived));
            OnPropertyChanged(nameof(TotalBytesSent));
            OnPropertyChanged(nameof(TotalBytesCombined));
            OnPropertyChanged(nameof(TotalDownloadFormatted));
            OnPropertyChanged(nameof(TotalUploadFormatted));
            OnPropertyChanged(nameof(TotalDataFormatted));
            OnPropertyChanged(nameof(TotalDataLineDisplay));
            OnPropertyChanged(nameof(TotalDataTooltip));
            OnPropertyChanged(nameof(TotalDataBrushHex));
            OnPropertyChanged(nameof(IsQuotaExceeded));
        }

        // ── Smoothed Rate Tracking Properties ──

        private double _downloadSpeedKbps = 0.0;
        public double DownloadSpeedKbps
        {
            get => _downloadSpeedKbps;
            set
            {
                if (Math.Abs(_downloadSpeedKbps - value) > 0.01)
                {
                    _downloadSpeedKbps = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(DownloadSpeedFormatted));
                    OnPropertyChanged(nameof(DownloadSpeed));
                    OnPropertyChanged(nameof(HasActiveTraffic));
                    OnPropertyChanged(nameof(HasActiveDownload));
                    OnPropertyChanged(nameof(DownloadTrafficBrushHex));
                    OnPropertyChanged(nameof(TrafficBrushHex));
                }
            }
        }

        private double _uploadSpeedKbps = 0.0;
        public double UploadSpeedKbps
        {
            get => _uploadSpeedKbps;
            set
            {
                if (Math.Abs(_uploadSpeedKbps - value) > 0.01)
                {
                    _uploadSpeedKbps = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(UploadSpeedFormatted));
                    OnPropertyChanged(nameof(DownloadSpeed));
                    OnPropertyChanged(nameof(HasActiveTraffic));
                    OnPropertyChanged(nameof(HasActiveUpload));
                    OnPropertyChanged(nameof(UploadTrafficBrushHex));
                    OnPropertyChanged(nameof(TrafficBrushHex));
                }
            }
        }

        public string DownloadSpeedFormatted => FormatSpeed(_downloadSpeedKbps);
        public string UploadSpeedFormatted => FormatSpeed(_uploadSpeedKbps);

        // ── Bindable download / combined speed ──

        private string _downloadSpeed = "—";
        public string DownloadSpeed
        {
            get => _downloadSpeed;
            set
            {
                if (_downloadSpeed != value)
                {
                    _downloadSpeed = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(HasActiveTraffic));
                    OnPropertyChanged(nameof(TrafficBrushHex));
                }
            }
        }

        public bool HasActiveTraffic => _downloadSpeedKbps >= 0.1 || _uploadSpeedKbps >= 0.1 || (!string.IsNullOrEmpty(_downloadSpeed) && _downloadSpeed != "—" && !_downloadSpeed.Contains("0 KB/s"));
        public bool HasActiveDownload => _downloadSpeedKbps >= 0.1;
        public bool HasActiveUpload => _uploadSpeedKbps >= 0.1;

        public string DownloadTrafficBrushHex => HasActiveDownload ? "#3FB950" : "#6E7681";
        public string UploadTrafficBrushHex => HasActiveUpload ? "#58A6FF" : "#6E7681";
        public string TrafficBrushHex => HasActiveTraffic ? "#3FB950" : "#6E7681";

        public void UpdateTransferRates(double downloadKbps, double uploadKbps)
        {
            double down = downloadKbps < 0.05 ? 0.0 : downloadKbps;
            double up = uploadKbps < 0.05 ? 0.0 : uploadKbps;

            string prevDownText = FormatSpeed(_downloadSpeedKbps);
            string prevUpText = FormatSpeed(_uploadSpeedKbps);
            string newDownText = FormatSpeed(down);
            string newUpText = FormatSpeed(up);

            bool textChanged = prevDownText != newDownText || prevUpText != newUpText;
            bool rateChanged = Math.Abs(_downloadSpeedKbps - down) > 0.05 || Math.Abs(_uploadSpeedKbps - up) > 0.05;

            if (textChanged || rateChanged)
            {
                _downloadSpeedKbps = down;
                _uploadSpeedKbps = up;
                _downloadSpeed = $"↓{newDownText} ↑{newUpText}";

                OnPropertyChanged(nameof(DownloadSpeedKbps));
                OnPropertyChanged(nameof(UploadSpeedKbps));
                OnPropertyChanged(nameof(DownloadSpeedFormatted));
                OnPropertyChanged(nameof(UploadSpeedFormatted));
                OnPropertyChanged(nameof(DownloadSpeed));
                OnPropertyChanged(nameof(HasActiveTraffic));
                OnPropertyChanged(nameof(HasActiveDownload));
                OnPropertyChanged(nameof(HasActiveUpload));
                OnPropertyChanged(nameof(DownloadTrafficBrushHex));
                OnPropertyChanged(nameof(UploadTrafficBrushHex));
                OnPropertyChanged(nameof(TrafficBrushHex));
            }

            string curTotalDown = TotalDownloadFormatted;
            string curTotalUp = TotalUploadFormatted;
            string curTotalCombined = TotalDataFormatted;
            if (curTotalDown != _lastReportedTotalDownText ||
                curTotalUp != _lastReportedTotalUpText ||
                curTotalCombined != _lastReportedTotalCombinedText)
            {
                _lastReportedTotalDownText = curTotalDown;
                _lastReportedTotalUpText = curTotalUp;
                _lastReportedTotalCombinedText = curTotalCombined;
                OnPropertyChanged(nameof(TotalBytesReceived));
                OnPropertyChanged(nameof(TotalBytesSent));
                OnPropertyChanged(nameof(TotalBytesCombined));
                OnPropertyChanged(nameof(TotalDownloadFormatted));
                OnPropertyChanged(nameof(TotalUploadFormatted));
                OnPropertyChanged(nameof(TotalDataFormatted));
                OnPropertyChanged(nameof(TotalDataLineDisplay));
                OnPropertyChanged(nameof(TotalDataTooltip));
                OnPropertyChanged(nameof(TotalDataBrushHex));
                OnPropertyChanged(nameof(IsQuotaExceeded));
            }
        }

        public static string FormatSpeed(double kbps)
        {
            if (kbps < 0.1) return "0 KB/s";
            if (kbps >= 1024.0) return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{kbps / 1024.0:F1} MB/s");
            return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{kbps:F1} KB/s");
        }

        public static string FormatDataSize(long bytes)
        {
            if (bytes <= 0) return "0 B";
            if (bytes < 1024) return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{bytes} B");
            if (bytes < 1024L * 1024L) return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{bytes / 1024.0:F1} KB");
            if (bytes < 1024L * 1024L * 1024L) return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{bytes / (1024.0 * 1024.0):F1} MB");
            return string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB");
        }

        /// <summary>
        /// Urutan tampilan tabel: perangkat target di atas (urut angka IPv4), lalu Local Host (ANDA), lalu Gateway paling bawah.
        /// </summary>
        public static int CompareForDisplay(PC a, PC b)
        {
            if (ReferenceEquals(a, b)) return 0;
            if (a == null) return 1;
            if (b == null) return -1;

            int rankCmp = GetDisplaySortRank(a).CompareTo(GetDisplaySortRank(b));
            if (rankCmp != 0) return rankCmp;

            int ipCmp = GetSortableIpv4(a.Ip).CompareTo(GetSortableIpv4(b.Ip));
            if (ipCmp != 0) return ipCmp;

            return string.Compare(a.MacFormatted, b.MacFormatted, StringComparison.OrdinalIgnoreCase);
        }

        private static int GetDisplaySortRank(PC pc)
        {
            if (pc.IsGateway) return 2;
            if (pc.IsLocalPc) return 1;
            return 0;
        }

        private static ulong GetSortableIpv4(IPAddress ip)
        {
            if (ip == null) return ulong.MaxValue;
            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                return ((ulong)bytes[0] << 24) | ((ulong)bytes[1] << 16) | ((ulong)bytes[2] << 8) | bytes[3];
            }
            return ulong.MaxValue - 1;
        }

        // ── INotifyPropertyChanged ──

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            var handler = PropertyChanged;
            if (handler == null) return;

            if (Dispatcher.UIThread != null && !Dispatcher.UIThread.CheckAccess())
            {
                try
                {
                    Dispatcher.UIThread.Post(() => handler(this, new PropertyChangedEventArgs(propertyName)), DispatcherPriority.Background);
                }
                catch
                {
                    handler(this, new PropertyChangedEventArgs(propertyName));
                }
            }
            else
            {
                handler(this, new PropertyChangedEventArgs(propertyName));
            }
        }
    }
}