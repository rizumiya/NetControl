using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform;
using Avalonia.Threading;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace NetControl
{
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        public sealed class BlockTargetOption
        {
            public string Mac { get; set; } = string.Empty;
            public string DisplayName { get; set; } = string.Empty;
            public override string ToString() => DisplayName;
        }

        private CArp _engine;
        private IDeviceIdentifierService _identifierService;
        private DispatcherTimer _maintenanceTimer;
        private TrayIcon _trayIcon;
        private readonly bool _isAutoStartLaunch;
        private bool _hasManualScanStarted;
        private bool _isClosingApp;
        private bool _isApplyingProgrammaticState;
        private bool _uiInitialized;
        private string _preferredInterfaceName = string.Empty;
        private double _savedWindowWidth;
        private double _savedWindowHeight;
        private bool _wasWindowMaximized;
        private bool _windowGeometryDirty;

        private readonly HashSet<string> _scheduleBlockedMacs = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, (bool Redirect, bool Block)> _preScheduleStates = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _quotaBlockedMacs = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, (bool Redirect, bool Block)> _preQuotaStates = new(StringComparer.OrdinalIgnoreCase);
        private int _lastActiveDomainScheduleCount = -1;

        public ObservableCollection<PC> DetectedPCs { get; set; }
        public ObservableCollection<DomainRequestEntry> RecentDomainRequests { get; } = new();
        public ObservableCollection<BlockedDomainRule> BlockedDomains { get; } = new();
        public ObservableCollection<BlockTargetOption> BlockTargetOptions { get; } = new();
        public ObservableCollection<BlockScheduleRule> BlockSchedules { get; } = new();
        public ObservableCollection<BlockTargetOption> ScheduleTargetOptions { get; } = new();
        public ObservableCollection<BlockTargetOption> QuotaTargetOptions { get; } = new();

        // ── Dashboard Metrics Properties ──

        private int _totalDevicesCount = 0;
        public int TotalDevicesCount
        {
            get => _totalDevicesCount;
            set
            {
                if (_totalDevicesCount != value)
                {
                    _totalDevicesCount = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(HasNoDevices));
                    OnPropertyChanged(nameof(HasDevices));
                }
            }
        }

        public bool HasNoDevices => _totalDevicesCount == 0;
        public bool HasDevices => _totalDevicesCount > 0;

        private int _spoofedCount = 0;
        public int SpoofedCount
        {
            get => _spoofedCount;
            set { if (_spoofedCount != value) { _spoofedCount = value; OnPropertyChanged(); } }
        }

        private int _blockedCount = 0;
        public int BlockedCount
        {
            get => _blockedCount;
            set { if (_blockedCount != value) { _blockedCount = value; OnPropertyChanged(); } }
        }

        private string _gatewayIpDisplay = "—";
        public string GatewayIpDisplay
        {
            get => _gatewayIpDisplay;
            set { if (_gatewayIpDisplay != value) { _gatewayIpDisplay = value; OnPropertyChanged(); } }
        }

        // ── Warning & Disclaimer Banner Properties ──

        private bool _isElevationWarningVisible;
        public bool IsElevationWarningVisible
        {
            get => _isElevationWarningVisible;
            set { if (_isElevationWarningVisible != value) { _isElevationWarningVisible = value; OnPropertyChanged(); } }
        }

        private string _elevationGuidance = string.Empty;
        public string ElevationGuidance
        {
            get => _elevationGuidance;
            set { if (_elevationGuidance != value) { _elevationGuidance = value; OnPropertyChanged(); } }
        }

        private bool _isDisclaimerVisible = true;
        public bool IsDisclaimerVisible
        {
            get => _isDisclaimerVisible;
            set { if (_isDisclaimerVisible != value) { _isDisclaimerVisible = value; OnPropertyChanged(); } }
        }

        private bool _minimizeToTray = true;
        public bool MinimizeToTray
        {
            get => _minimizeToTray;
            set
            {
                if (_minimizeToTray != value)
                {
                    _minimizeToTray = value;
                    OnPropertyChanged();
                    if (_uiInitialized)
                    {
                        SaveCurrentAppSettings();
                    }
                }
            }
        }

        private int _activeRightTab = 0;
        public bool IsDomainsTabActive => _activeRightTab == 0;
        public bool IsSchedulesTabActive => _activeRightTab == 1;
        public bool IsQuotaTabActive => _activeRightTab == 2;
        public bool IsAutostartTabActive => _activeRightTab == 3;

        private int _scheduleKindIndex = 0;
        public bool IsScheduleTimerMode => _scheduleKindIndex == 0;
        public bool IsScheduleDailyMode => _scheduleKindIndex == 1;

        private int _scheduleActionIndex = 0;
        public bool IsScheduleDomainAction => _scheduleActionIndex == 1;

        private string _scheduleTabTitle = "Jadwal & Timer";
        public string ScheduleTabTitle
        {
            get => _scheduleTabTitle;
            set { if (_scheduleTabTitle != value) { _scheduleTabTitle = value; OnPropertyChanged(); } }
        }

        // ── Autostart & Startup Automation Properties ──

        private bool _autoStartWithWindows;
        public bool AutoStartWithWindows
        {
            get => _autoStartWithWindows;
            set { if (_autoStartWithWindows != value) { _autoStartWithWindows = value; OnPropertyChanged(); } }
        }

        private bool _startMinimizedToTray = true;
        public bool StartMinimizedToTray
        {
            get => _startMinimizedToTray;
            set { if (_startMinimizedToTray != value) { _startMinimizedToTray = value; OnPropertyChanged(); } }
        }

        private bool _autoScanOnStartup;
        public bool AutoScanOnStartup
        {
            get => _autoScanOnStartup;
            set
            {
                if (_autoScanOnStartup != value)
                {
                    _autoScanOnStartup = value;
                    OnPropertyChanged();
                    if (!_autoScanOnStartup && _autoSpoofAfterScan)
                    {
                        _autoSpoofAfterScan = false;
                        OnPropertyChanged(nameof(AutoSpoofAfterScan));
                    }
                }
            }
        }

        private bool _autoSpoofAfterScan;
        public bool AutoSpoofAfterScan
        {
            get => _autoSpoofAfterScan;
            set { if (_autoSpoofAfterScan != value) { _autoSpoofAfterScan = value; OnPropertyChanged(); } }
        }

        private bool _onlyAutoSpoofOnHomeRouter = true;
        public bool OnlyAutoSpoofOnHomeRouter
        {
            get => _onlyAutoSpoofOnHomeRouter;
            set { if (_onlyAutoSpoofOnHomeRouter != value) { _onlyAutoSpoofOnHomeRouter = value; OnPropertyChanged(); } }
        }

        private string _homeRouterMac = string.Empty;
        private string _homeRouterLabel = string.Empty;
        public string HomeRouterDisplay => string.IsNullOrWhiteSpace(_homeRouterMac)
            ? "Belum diatur"
            : (!string.IsNullOrWhiteSpace(_homeRouterLabel) ? $"{_homeRouterLabel} ({_homeRouterMac})" : _homeRouterMac);

        private bool _isAutostartTaskRegistered;
        public string AutostartStatusBadge => _isAutostartTaskRegistered ? "TERDAFTAR" : "NONAKTIF";
        public string AutostartStatusBrushHex => _isAutostartTaskRegistered ? "#3FB950" : "#6E7681";

        public MainWindow() : this(false)
        {
        }

        public MainWindow(bool isAutoStartLaunch)
        {
            _isAutoStartLaunch = isAutoStartLaunch;

            var appSettings = AppSettingsStore.GetSettings();
            _minimizeToTray = appSettings.MinimizeToTray;
            _startMinimizedToTray = appSettings.StartMinimizedToTray;
            _autoScanOnStartup = appSettings.AutoScanOnStartup;
            _autoSpoofAfterScan = appSettings.AutoScanOnStartup && appSettings.AutoSpoofAfterScan;
            _onlyAutoSpoofOnHomeRouter = appSettings.OnlyAutoSpoofOnHomeRouter;
            _homeRouterMac = appSettings.HomeRouterMac;
            _homeRouterLabel = appSettings.HomeRouterLabel;
            _preferredInterfaceName = appSettings.PreferredInterfaceName;
            _savedWindowWidth = appSettings.WindowWidth;
            _savedWindowHeight = appSettings.WindowHeight;
            _wasWindowMaximized = appSettings.WindowMaximized;
            _isAutostartTaskRegistered = AutostartManager.IsAutostartRegistered();
            _autoStartWithWindows = (OperatingSystem.IsWindows() || OperatingSystem.IsLinux())
                ? _isAutostartTaskRegistered
                : appSettings.AutoStartWithWindows;

            InitializeComponent();
            if (AppSettingsStore.SanitizeWindowBounds(_savedWindowWidth, _savedWindowHeight, MinWidth, MinHeight, out double restoredW, out double restoredH))
            {
                Width = restoredW;
                Height = restoredH;
            }
            else
            {
                _savedWindowWidth = Width;
                _savedWindowHeight = Height;
            }

            if (_wasWindowMaximized && !(_isAutoStartLaunch && StartMinimizedToTray))
            {
                WindowState = WindowState.Maximized;
            }

            DataContext = this;
            _uiInitialized = true;

            // Proactively verify privileges and capabilities
            bool elevated = PrivilegeDetector.IsElevated();
            bool hasCaps = PrivilegeDetector.HasCaptureCapabilities();
            if (!elevated && !hasCaps)
            {
                IsElevationWarningVisible = true;
                ElevationGuidance = PrivilegeDetector.GetElevationGuidance();
            }

            DetectedPCs = new ObservableCollection<PC>();
            DetectedPCs.CollectionChanged += OnDetectedPcsCollectionChanged;

            var listBox = this.FindControl<ListBox>("PcListBox");
            if (listBox != null)
            {
                listBox.ItemsSource = DetectedPCs;
            }

            RefreshBlockedDomainsList();
            RefreshSchedulesList();

            var requestsListBox = this.FindControl<ListBox>("LiveRequestsListBox");
            if (requestsListBox != null)
            {
                requestsListBox.ItemsSource = RecentDomainRequests;
            }

            var blockedListBox = this.FindControl<ListBox>("BlockedDomainsListBox");
            if (blockedListBox != null)
            {
                blockedListBox.ItemsSource = BlockedDomains;
            }

            var blockTargetBox = this.FindControl<ComboBox>("BlockTargetComboBox");
            if (blockTargetBox != null)
            {
                blockTargetBox.ItemsSource = BlockTargetOptions;
            }

            var schedulesListBox = this.FindControl<ListBox>("SchedulesListBox");
            if (schedulesListBox != null)
            {
                schedulesListBox.ItemsSource = BlockSchedules;
            }

            var scheduleTargetBox = this.FindControl<ComboBox>("ScheduleTargetComboBox");
            if (scheduleTargetBox != null)
            {
                scheduleTargetBox.ItemsSource = ScheduleTargetOptions;
            }

            var quotaTargetBox = this.FindControl<ComboBox>("QuotaTargetComboBox");
            if (quotaTargetBox != null)
            {
                quotaTargetBox.ItemsSource = QuotaTargetOptions;
            }

            var dataUsageListBox = this.FindControl<ListBox>("DataUsageListBox");
            if (dataUsageListBox != null)
            {
                dataUsageListBox.ItemsSource = DetectedPCs;
            }

            var netCombo = this.FindControl<ComboBox>("NetInterfacesBox");
            if (netCombo != null)
            {
                netCombo.SelectionChanged += OnInterfaceSelectionChanged;
            }

            RefreshBlockTargetOptions();
            InitializeTrayIcon();

            AppDomain.CurrentDomain.ProcessExit += (s, e) => Cleanup();

            try
            {
                System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged += (s, e) =>
                {
                    Dispatcher.UIThread.InvokeAsync(LoadInterfaces);
                };
            }
            catch { }

            LoadInterfaces();

            _maintenanceTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _maintenanceTimer.Tick += (_, _) => EvaluateSchedulesAndQuotas();
            _maintenanceTimer.Start();

            this.Opened += OnMainWindowOpened;

            if (IsElevationWarningVisible)
            {
                SetStatus("Peringatan: Diperlukan hak akses superuser (root/admin) atau CAP_NET_RAW.", "warning");
            }
        }

        public void OnDismissDisclaimerClick(object sender, RoutedEventArgs e)
        {
            IsDisclaimerVisible = false;
        }

        public void OnEditLabelClick(object sender, RoutedEventArgs e)
        {
            if (sender is Control control && control.DataContext is PC pc)
            {
                pc.EditLabelBuffer = pc.HasCustomLabel ? pc.CustomLabel : string.Empty;
                pc.IsEditingLabel = true;
            }
        }

        public void OnSaveLabelClick(object sender, RoutedEventArgs e)
        {
            if (sender is Control control && control.DataContext is PC pc)
            {
                SaveDeviceLabel(pc);
            }
        }

        public void OnCancelLabelClick(object sender, RoutedEventArgs e)
        {
            if (sender is Control control && control.DataContext is PC pc)
            {
                pc.IsEditingLabel = false;
                pc.EditLabelBuffer = string.Empty;
            }
        }

        public void OnLabelTextBoxKeyDown(object sender, Avalonia.Input.KeyEventArgs e)
        {
            if (sender is Control control && control.DataContext is PC pc)
            {
                if (e.Key == Avalonia.Input.Key.Enter)
                {
                    SaveDeviceLabel(pc);
                    e.Handled = true;
                }
                else if (e.Key == Avalonia.Input.Key.Escape)
                {
                    pc.IsEditingLabel = false;
                    pc.EditLabelBuffer = string.Empty;
                    e.Handled = true;
                }
            }
        }

        private void SaveDeviceLabel(PC pc)
        {
            string trimmed = pc.EditLabelBuffer?.Trim();
            pc.CustomLabel = string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
            pc.IsEditingLabel = false;

            if (pc.Mac != null)
            {
                DeviceLabelStore.SetLabel(pc.MacFormatted, pc.CustomLabel);
                BlockedDomainStore.UpdateTargetLabel(pc.MacFormatted, pc.DeviceLabel);
                BlockScheduleStore.UpdateTargetLabel(pc.MacFormatted, pc.DeviceLabel);
                RefreshBlockedDomainsList();
                RefreshSchedulesList();
                RefreshBlockTargetOptions();
            }

            if (string.IsNullOrWhiteSpace(pc.CustomLabel))
            {
                SetStatus($"Label perangkat {pc.IpDisplay} direset ke deteksi otomatis.", "info");
            }
            else
            {
                SetStatus($"Label '{pc.CustomLabel}' disimpan untuk {pc.MacFormatted}.", "success");
            }
        }

        private void OnDetectedPcsCollectionChanged(object sender, NotifyCollectionChangedEventArgs e)
        {
            if (e.Action != NotifyCollectionChangedAction.Move)
            {
                if (e.NewItems != null)
                {
                    foreach (PC pc in e.NewItems)
                    {
                        pc.PropertyChanged += OnPcPropertyChanged;
                        if (pc.IsGateway && pc.Ip != null)
                        {
                            GatewayIpDisplay = pc.Ip.ToString();
                        }
                    }
                }

                if (e.OldItems != null)
                {
                    foreach (PC pc in e.OldItems)
                    {
                        pc.PropertyChanged -= OnPcPropertyChanged;
                    }
                }
            }

            RecalculateDashboardMetrics();
            RefreshBlockTargetOptions();
            UpdateTrayTooltip();
        }

        private void OnPcPropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(PC.Redirect) ||
                e.PropertyName == nameof(PC.Block) ||
                e.PropertyName == nameof(PC.IsGateway) ||
                e.PropertyName == nameof(PC.IsLocalPc))
            {
                if ((e.PropertyName == nameof(PC.IsGateway) || e.PropertyName == nameof(PC.IsLocalPc)) &&
                    sender is PC roleChangedPc)
                {
                    RepositionDeviceSorted(roleChangedPc);
                }
                RecalculateDashboardMetrics();
                UpdateTrayTooltip();
                if (e.PropertyName == nameof(PC.Redirect) || e.PropertyName == nameof(PC.Block))
                {
                    RefreshRequestStatuses();
                }
            }
            else if (e.PropertyName == nameof(PC.DeviceLabel) || e.PropertyName == nameof(PC.MacFormatted))
            {
                if (sender is PC changedPc && changedPc.CanControl && changedPc.Mac != null)
                {
                    BlockedDomainStore.UpdateTargetLabel(changedPc.MacFormatted, changedPc.DeviceLabel);
                    BlockScheduleStore.UpdateTargetLabel(changedPc.MacFormatted, changedPc.DeviceLabel);
                    RefreshBlockedDomainsList();
                    RefreshSchedulesList();
                }
                RefreshBlockTargetOptions();
            }

            if (!_isApplyingProgrammaticState &&
                sender is PC targetPc &&
                targetPc.CanControl &&
                targetPc.Mac != null &&
                (e.PropertyName == nameof(PC.BandwidthLimitKb) ||
                 e.PropertyName == nameof(PC.Redirect) ||
                 e.PropertyName == nameof(PC.Block) ||
                 e.PropertyName == nameof(PC.DataQuotaMb)))
            {
                PersistDeviceProfileFromUi(targetPc, e.PropertyName);
            }
        }

        private void PersistDeviceProfileFromUi(PC pc, string changedProperty)
        {
            string mac = pc.MacFormatted;
            bool saveRedirect = pc.Redirect;
            bool saveBlock = pc.Block;

            if (_scheduleBlockedMacs.Contains(mac) && _preScheduleStates.TryGetValue(mac, out var preSched))
            {
                if (changedProperty == nameof(PC.BandwidthLimitKb) || changedProperty == nameof(PC.DataQuotaMb))
                {
                    saveRedirect = preSched.Redirect;
                    saveBlock = preSched.Block;
                }
            }
            else if (_quotaBlockedMacs.Contains(mac))
            {
                if (changedProperty == nameof(PC.Block) && !pc.Block)
                {
                    _quotaBlockedMacs.Remove(mac);
                    _preQuotaStates.Remove(mac);
                    if (!string.IsNullOrEmpty(pc.ActiveScheduleNote) && pc.ActiveScheduleNote.Contains("Kuota", StringComparison.Ordinal))
                    {
                        pc.ActiveScheduleNote = string.Empty;
                    }
                }
                else if ((changedProperty == nameof(PC.BandwidthLimitKb) || changedProperty == nameof(PC.DataQuotaMb)) &&
                         _preQuotaStates.TryGetValue(mac, out var preQuota))
                {
                    saveRedirect = preQuota.Redirect;
                    saveBlock = preQuota.Block;
                }
            }

            DeviceSettingsStore.SaveProfile(mac, pc.BandwidthLimitKb, saveRedirect, saveBlock, pc.DataQuotaMb);
        }

        private void RecalculateDashboardMetrics()
        {
            TotalDevicesCount = DetectedPCs.Count;
            SpoofedCount = DetectedPCs.Count(p => p.Redirect);
            BlockedCount = DetectedPCs.Count(p => p.Block);

            var gateway = DetectedPCs.FirstOrDefault(p => p.IsGateway);
            if (gateway?.Ip != null)
            {
                GatewayIpDisplay = gateway.Ip.ToString();
            }
        }

        private void InsertDeviceSorted(PC newPc)
        {
            if (newPc == null) return;

            int insertIndex = DetectedPCs.Count;
            for (int i = 0; i < DetectedPCs.Count; i++)
            {
                if (PC.CompareForDisplay(newPc, DetectedPCs[i]) < 0)
                {
                    insertIndex = i;
                    break;
                }
            }

            DetectedPCs.Insert(insertIndex, newPc);
        }

        private void RepositionDeviceSorted(PC pc)
        {
            int oldIndex = DetectedPCs.IndexOf(pc);
            if (oldIndex < 0) return;

            int targetIndex = 0;
            for (int i = 0; i < DetectedPCs.Count; i++)
            {
                if (i == oldIndex) continue;
                if (PC.CompareForDisplay(DetectedPCs[i], pc) < 0)
                {
                    targetIndex++;
                }
            }

            if (targetIndex != oldIndex)
            {
                DetectedPCs.Move(oldIndex, targetIndex);
            }
        }

        private void OnInterfaceSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (sender is ComboBox combo)
            {
                var opt = combo.SelectedItem as NetworkInterfaceOption;
                ToolTip.SetTip(combo, opt?.TooltipText);
            }
        }

        private void LoadInterfaces()
        {
            try
            {
                var devices = SharpPcap.CaptureDeviceList.Instance;
                var validDevices = devices.OfType<LibPcapLiveDevice>().Where(d => d.Addresses.Any(a =>
                    a.Addr.ipAddress != null &&
                    a.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)).ToList();

                var options = NetworkInterfaceOption.BuildInterfaceOptions(validDevices);

                var combo = this.FindControl<ComboBox>("NetInterfacesBox");
                if (combo != null)
                {
                    string prevDeviceName = (combo.SelectedItem as NetworkInterfaceOption)?.DeviceName;
                    combo.ItemsSource = options;
                    combo.DisplayMemberBinding = new Avalonia.Data.Binding(nameof(NetworkInterfaceOption.DisplayName));

                    if (options.Any())
                    {
                        int idx = 0;
                        string lookupDeviceName = !string.IsNullOrEmpty(prevDeviceName) ? prevDeviceName : _preferredInterfaceName;
                        if (!string.IsNullOrEmpty(lookupDeviceName))
                        {
                            int found = options.FindIndex(o => string.Equals(o.DeviceName, lookupDeviceName, StringComparison.Ordinal));
                            if (found >= 0) idx = found;
                        }
                        combo.SelectedIndex = idx;
                        ToolTip.SetTip(combo, options[idx].TooltipText);
                        SetStatus($"{options.Count} antarmuka jaringan terdeteksi.", "success");
                    }
                    else
                    {
                        ToolTip.SetTip(combo, null);
                        SetStatus("Tidak ada antarmuka jaringan yang valid terdeteksi.", "warning");
                    }
                }
            }
            catch (Exception ex)
            {
                SetStatus($"Gagal memuat antarmuka: {ex.Message}", "error");
            }
        }

        private async void OnMainWindowOpened(object sender, EventArgs e)
        {
            this.Opened -= OnMainWindowOpened;

            if (_isAutoStartLaunch && StartMinimizedToTray && _trayIcon != null)
            {
                Dispatcher.UIThread.Post(HideToTray);
            }

            if (AutoScanOnStartup)
            {
                await RunStartupAutomationAsync();
            }
        }

        private async Task RunStartupAutomationAsync()
        {
            try
            {
                var combo = this.FindControl<ComboBox>("NetInterfacesBox");
                NetworkInterfaceOption readyOption = null;

                for (int attempt = 0; attempt < 15; attempt++)
                {
                    if (_isClosingApp || _hasManualScanStarted) return;

                    LoadInterfaces();
                    if (combo?.ItemsSource is IEnumerable<NetworkInterfaceOption> opts)
                    {
                        var list = opts.ToList();
                        readyOption = list.FirstOrDefault(o =>
                            !string.IsNullOrEmpty(_preferredInterfaceName) &&
                            string.Equals(o.DeviceName, _preferredInterfaceName, StringComparison.Ordinal) &&
                            o.HasGateway);

                        readyOption ??= list.FirstOrDefault(o => o.HasGateway);

                        if (readyOption != null)
                        {
                            int idx = list.IndexOf(readyOption);
                            if (idx >= 0) combo.SelectedIndex = idx;
                            break;
                        }
                    }

                    SetStatus("Auto-Scan: menunggu koneksi jaringan siap...", "info");
                    await Task.Delay(2000);
                }

                if (_isClosingApp || _hasManualScanStarted) return;

                if (readyOption == null)
                {
                    SetStatus("Auto-Scan: tidak ada antarmuka aktif dengan gateway.", "warning");
                    return;
                }

                bool scanStarted = await ExecuteScanAsync();
                if (!scanStarted || !AutoSpoofAfterScan || _isClosingApp) return;

                // Wait up to 8 seconds for router MAC to be discovered via ARP
                for (int i = 0; i < 16; i++)
                {
                    if (_isClosingApp) return;
                    if (_engine?.RouterMac != null) break;
                    await Task.Delay(500);
                }

                // Allow initial ARP cache + Pass 1 sweep to populate LAN devices & saved profiles
                await Task.Delay(2000);
                if (_isClosingApp || _engine == null || _engine.IsSpoofing) return;

                string detectedRouterMac = AppSettingsStore.FormatMacBytes(_engine.RouterMac);
                var currentSettings = AppSettingsStore.GetSettings();
                if (!AppSettingsStore.ShouldAllowAutoSpoof(currentSettings, detectedRouterMac, out string skipReason))
                {
                    SetStatus(skipReason, "warning");
                    return;
                }

                bool spoofStarted = await ExecuteStartSpoofAsync();
                if (spoofStarted)
                {
                    SetStatus("Auto-Spoof aktif pada jaringan rumah.", "error");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[AUTOSTART ERROR] {ex.Message}");
            }
        }

        public async void OnScanClick(object sender, RoutedEventArgs e)
        {
            _hasManualScanStarted = true;
            await ExecuteScanAsync();
        }

        private async Task<bool> ExecuteScanAsync()
        {
            var combo = this.FindControl<ComboBox>("NetInterfacesBox");
            var selectedOption = combo?.SelectedItem as NetworkInterfaceOption;
            var device = selectedOption?.Device;
            if (device == null)
            {
                SetStatus("Pilih antarmuka jaringan terlebih dahulu.", "warning");
                return false;
            }

            var btnScan = this.FindControl<Button>("BtnScan");
            var btnSpoof = this.FindControl<Button>("BtnSpoof");
            var spoofText = this.FindControl<TextBlock>("SpoofButtonText");
            var spoofIcon = this.FindControl<Avalonia.Controls.PathIcon>("SpoofButtonIcon");

            if (btnScan != null) btnScan.IsEnabled = false;
            if (btnSpoof != null) btnSpoof.IsEnabled = false;

            // If engine exists, stop previous operations asynchronously
            if (_engine != null || _identifierService != null)
            {
                SetStatus("Menghentikan pemindaian sebelumnya dan melepaskan sumber daya jaringan...", "warning");
                var oldEngine = _engine;
                var oldIdService = _identifierService;
                if (oldEngine != null)
                {
                    oldEngine.OnInterfaceDisconnected -= OnEngineInterfaceDisconnected;
                    oldEngine.OnDomainRequested -= OnEngineDomainRequested;
                }
                _engine = null;
                _identifierService = null;

                await Task.Run(() =>
                {
                    try
                    {
                        oldIdService?.StopMdnsListener();
                        oldIdService?.Dispose();
                        oldEngine?.StopArpListener();
                        oldEngine?.StopDiscovery();
                        oldEngine?.StopSpoofing();
                        oldEngine?.StopTrafficMonitor();
                        oldEngine?.Dispose();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[CLEANUP ERROR] {ex.Message}");
                    }
                });

                if (btnSpoof != null)
                {
                    btnSpoof.Classes.Clear();
                    btnSpoof.Classes.Add("danger");
                }
                if (spoofText != null) spoofText.Text = "MULAI ARP SPOOF";
                if (spoofIcon != null && Application.Current?.Resources.TryGetResource("IconZap", null, out var zapGeom) == true)
                {
                    spoofIcon.Data = zapGeom as Geometry;
                }
            }

            _scheduleBlockedMacs.Clear();
            _preScheduleStates.Clear();
            _quotaBlockedMacs.Clear();
            _preQuotaStates.Clear();
            DetectedPCs.Clear();
            GatewayIpDisplay = "—";

            try
            {
                SetStatus("Menginisialisasi pemindaian jaringan...", "info");

                var deviceList = new PcList();
                deviceList.SetOnDeviceAdded((newPc) =>
                {
                    Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        InsertDeviceSorted(newPc);
                        SetStatus($"{DetectedPCs.Count} perangkat terdeteksi di jaringan.", "success");
                    });
                });

                CArp newEngine = null;
                IDeviceIdentifierService newIdService = null;

                await Task.Run(() =>
                {
                    newEngine = new CArp(device, deviceList);
                    newIdService = new DeviceIdentifierService(device, deviceList);
                    deviceList.SetIdentifierService(newIdService);

                    newEngine.StartArpListener();
                    newEngine.StartArpDiscovery();
                    newEngine.StartTrafficMonitor();
                    newIdService.StartMdnsListener();
                });

                _engine = newEngine;
                _identifierService = newIdService;
                _engine.OnInterfaceDisconnected += OnEngineInterfaceDisconnected;
                _engine.OnDomainRequested += OnEngineDomainRequested;

                _preferredInterfaceName = selectedOption.DeviceName;
                SaveCurrentAppSettings();

                // Show detected network info in metadata footer
                string localIp = _engine.LocalIp != null ? new System.Net.IPAddress(_engine.LocalIp).ToString() : "N/A";
                string routerIp = _engine.RouterIp != null ? new System.Net.IPAddress(_engine.RouterIp).ToString() : "N/A";
                string subnet = _engine.SubnetMask != null ? new System.Net.IPAddress(_engine.SubnetMask).ToString() : "/24 (cadangan)";

                if (!string.IsNullOrEmpty(routerIp) && routerIp != "N/A")
                {
                    GatewayIpDisplay = routerIp;
                }

                var localIpText = this.FindControl<TextBlock>("LocalIpText");
                if (localIpText != null) localIpText.Text = $"Lokal: {localIp}";

                var subnetText = this.FindControl<TextBlock>("SubnetText");
                if (subnetText != null) subnetText.Text = $"Subnet: {subnet}";

                SetStatus($"Pemindaian aktif pada {selectedOption.DisplayName}", "info");
                UpdateTrayTooltip();
                return true;
            }
            catch (Exception ex)
            {
                SetStatus($"Gagal memulai pemindaian: {ex.Message}", "error");
                Console.WriteLine($"[SCAN ERROR] {ex}");
                return false;
            }
            finally
            {
                if (btnScan != null) btnScan.IsEnabled = true;
                if (btnSpoof != null) btnSpoof.IsEnabled = true;
            }
        }

        public async void OnSpoofClick(object sender, RoutedEventArgs e)
        {
            var spoofText = this.FindControl<TextBlock>("SpoofButtonText");
            bool isStarting = spoofText?.Text?.Contains("MULAI") == true || spoofText?.Text?.Contains("START") == true;

            if (isStarting)
            {
                await ExecuteStartSpoofAsync();
                return;
            }

            if (_engine == null)
            {
                SetStatus("Pindai jaringan terlebih dahulu sebelum memulai spoof.", "warning");
                return;
            }

            var btn = this.FindControl<Button>("BtnSpoof");
            var spoofIcon = this.FindControl<Avalonia.Controls.PathIcon>("SpoofButtonIcon");
            if (btn == null) return;
            btn.IsEnabled = false;

            try
            {
                SetStatus("Menghentikan spoof dan memulihkan tabel jaringan...", "warning");
                await Task.Run(() => _engine.StopSpoofing());

                btn.Classes.Clear();
                btn.Classes.Add("danger");
                if (spoofText != null) spoofText.Text = "MULAI ARP SPOOF";
                if (spoofIcon != null && Application.Current?.Resources.TryGetResource("IconZap", null, out var zapGeom) == true)
                {
                    spoofIcon.Data = zapGeom as Geometry;
                }

                SetStatus("Spoof dihentikan. Jaringan dipulihkan.", "success");
                UpdateTrayTooltip();
            }
            finally
            {
                btn.IsEnabled = true;
            }
        }

        private async Task<bool> ExecuteStartSpoofAsync()
        {
            if (!PrivilegeDetector.HasCaptureCapabilities())
            {
                SetStatus("Tidak dapat memulai spoof: diperlukan superuser (root/admin) atau CAP_NET_RAW.", "error");
                IsElevationWarningVisible = true;
                return false;
            }

            if (_engine == null)
            {
                SetStatus("Pindai jaringan terlebih dahulu sebelum memulai spoof.", "warning");
                return false;
            }

            var btn = this.FindControl<Button>("BtnSpoof");
            var spoofText = this.FindControl<TextBlock>("SpoofButtonText");
            var spoofIcon = this.FindControl<Avalonia.Controls.PathIcon>("SpoofButtonIcon");
            if (btn == null) return false;
            btn.IsEnabled = false;

            try
            {
                if (_engine.RouterMac == null)
                {
                    SetStatus("MAC Router tidak terdeteksi. Silakan pindai ulang.", "error");
                    return false;
                }

                await Task.Run(() => _engine.StartSpoofing());

                btn.Classes.Clear();
                btn.Classes.Add("active-stop");
                if (spoofText != null) spoofText.Text = "HENTIKAN SPOOF";
                if (spoofIcon != null && Application.Current?.Resources.TryGetResource("IconStopCircle", null, out var stopGeom) == true)
                {
                    spoofIcon.Data = stopGeom as Geometry;
                }

                SetStatus("ARP Spoof aktif — mengintersepsi lalu lintas.", "error");
                UpdateTrayTooltip();
                return true;
            }
            finally
            {
                btn.IsEnabled = true;
            }
        }

        /// <summary>
        /// Updates the status pill with a message and semantic level (success, info, warning, error).
        /// Thread-safe: can be called from any thread.
        /// </summary>
        private void SetStatus(string message, string level = "info")
        {
            if (Dispatcher.UIThread.CheckAccess())
            {
                var status = this.FindControl<TextBlock>("StatusText");
                var dot = this.FindControl<Avalonia.Controls.Shapes.Ellipse>("StatusDot");
                var border = this.FindControl<Border>("StatusPillBorder");

                if (status != null)
                {
                    status.Text = message;
                }

                Color dotColor;
                Color borderBg;

                switch (level.ToLowerInvariant())
                {
                    case "success":
                        dotColor = Color.Parse("#3FB950");
                        borderBg = Color.Parse("#161B22");
                        break;
                    case "warning":
                        dotColor = Color.Parse("#D29922");
                        borderBg = Color.Parse("#271E0B");
                        break;
                    case "error":
                        dotColor = Color.Parse("#F85149");
                        borderBg = Color.Parse("#261214");
                        break;
                    case "info":
                    default:
                        dotColor = Color.Parse("#58A6FF");
                        borderBg = Color.Parse("#161B22");
                        break;
                }

                if (dot != null)
                {
                    dot.Fill = new SolidColorBrush(dotColor);
                }
                if (border != null)
                {
                    border.Background = new SolidColorBrush(borderBg);
                }
            }
            else
            {
                Dispatcher.UIThread.InvokeAsync(() => SetStatus(message, level));
            }
        }

        private void OnEngineInterfaceDisconnected(string reason)
        {
            Dispatcher.UIThread.InvokeAsync(() =>
            {
                SetStatus($"Jaringan terputus: {reason}", "error");

                var btnSpoof = this.FindControl<Button>("BtnSpoof");
                var spoofText = this.FindControl<TextBlock>("SpoofButtonText");
                var spoofIcon = this.FindControl<Avalonia.Controls.PathIcon>("SpoofButtonIcon");

                if (btnSpoof != null)
                {
                    btnSpoof.Classes.Clear();
                    btnSpoof.Classes.Add("danger");
                    btnSpoof.IsEnabled = true;
                }
                if (spoofText != null) spoofText.Text = "MULAI ARP SPOOF";
                if (spoofIcon != null && Application.Current?.Resources.TryGetResource("IconZap", null, out var zapGeom) == true)
                {
                    spoofIcon.Data = zapGeom as Geometry;
                }

                LoadInterfaces();
                UpdateTrayTooltip();
            });
        }

        private void OnEngineDomainRequested(PC device, string domain, string protocol, bool isBlocked)
        {
            if (device == null || string.IsNullOrEmpty(domain)) return;

            Dispatcher.UIThread.InvokeAsync(() =>
            {
                var entry = new DomainRequestEntry
                {
                    Timestamp = DateTime.Now.ToString("HH:mm:ss"),
                    Device = device,
                    DeviceIp = device.IpDisplay,
                    DeviceName = device.DeviceLabel,
                    Protocol = protocol,
                    Domain = domain,
                    IsBlocked = isBlocked && device.Redirect && !device.IsLocalPc
                };

                RecentDomainRequests.Insert(0, entry);
                while (RecentDomainRequests.Count > 60)
                {
                    RecentDomainRequests.RemoveAt(RecentDomainRequests.Count - 1);
                }
            });
        }

        public void OnAddBlockedDomainClick(object sender, RoutedEventArgs e)
        {
            AddBlockedDomainsFromInput();
        }

        public void OnBlockDomainInputKeyDown(object sender, Avalonia.Input.KeyEventArgs e)
        {
            if (e.Key == Avalonia.Input.Key.Enter)
            {
                AddBlockedDomainsFromInput();
                e.Handled = true;
            }
        }

        private void AddBlockedDomainsFromInput()
        {
            var input = this.FindControl<TextBox>("BlockDomainInput");
            if (input == null || string.IsNullOrWhiteSpace(input.Text)) return;

            var targetBox = this.FindControl<ComboBox>("BlockTargetComboBox");
            var selectedTarget = targetBox?.SelectedItem as BlockTargetOption;
            string targetMac = selectedTarget?.Mac ?? string.Empty;
            string targetLabel = string.IsNullOrEmpty(targetMac) ? "Semua" : selectedTarget.DisplayName;

            string[] parts = input.Text.Split(new[] { ',', ';', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            int addedCount = 0;

            foreach (string raw in parts)
            {
                if (BlockedDomainStore.AddDomain(raw, targetMac, targetLabel))
                {
                    addedCount++;
                }
            }

            input.Text = string.Empty;
            RefreshBlockedDomainsList();
            RefreshRequestStatuses();

            if (addedCount > 0)
            {
                string scopeText = string.IsNullOrEmpty(targetMac) ? "semua perangkat yang di-Spoof" : targetLabel;
                SetStatus($"{addedCount} domain ditambahkan ke daftar blokir untuk {scopeText}.", "success");
            }
            else
            {
                SetStatus("Domain sudah ada untuk target ini atau format tidak valid.", "warning");
            }
        }

        public void OnRemoveBlockedDomainClick(object sender, RoutedEventArgs e)
        {
            if (sender is Control control && control.DataContext is BlockedDomainRule rule)
            {
                if (BlockedDomainStore.RemoveDomain(rule.Domain, rule.TargetMac))
                {
                    RefreshBlockedDomainsList();
                    RefreshRequestStatuses();
                    SetStatus($"Aturan '{rule.Domain}' ({rule.TargetBadgeText}) dihapus dari daftar blokir.", "info");
                }
            }
        }

        public void OnToggleBlockFromLogClick(object sender, RoutedEventArgs e)
        {
            if (sender is Control control && control.DataContext is DomainRequestEntry entry)
            {
                string targetMac = entry.Device?.MacFormatted ?? string.Empty;
                string targetLabel = entry.Device?.DeviceLabel ?? entry.DeviceName;

                if (BlockedDomainStore.IsDomainBlocked(entry.Domain, targetMac))
                {
                    var matched = BlockedDomainStore.GetMatchingRule(entry.Domain, targetMac);
                    if (matched != null)
                    {
                        BlockedDomainStore.RemoveDomain(matched.Domain, matched.TargetMac);
                        SetStatus($"Pemblokiran '{matched.Domain}' ({matched.TargetBadgeText}) dibuka.", "info");
                    }
                    else
                    {
                        SetStatus("Domain sedang diblokir oleh jadwal aktif (kelola melalui tab Jadwal & Timer).", "warning");
                    }
                }
                else
                {
                    BlockedDomainStore.AddDomain(entry.Domain, targetMac, targetLabel);
                    string scopeText = string.IsNullOrEmpty(targetMac) ? "Semua" : targetLabel;
                    SetStatus($"Domain '{BlockedDomainStore.NormalizeDomain(entry.Domain)}' diblokir khusus untuk {scopeText}.", "success");
                }

                RefreshBlockedDomainsList();
                RefreshRequestStatuses();
            }
        }

        public void OnClearRequestsClick(object sender, RoutedEventArgs e)
        {
            RecentDomainRequests.Clear();
        }

        // ── Tab Navigation (Right Bottom Panel) ──

        public void OnSelectDomainsTabClick(object sender, RoutedEventArgs e) => SetActiveRightTab(0);
        public void OnSelectSchedulesTabClick(object sender, RoutedEventArgs e) => SetActiveRightTab(1);
        public void OnSelectQuotaTabClick(object sender, RoutedEventArgs e) => SetActiveRightTab(2);
        public void OnSelectAutostartTabClick(object sender, RoutedEventArgs e) => SetActiveRightTab(3);

        private void SetActiveRightTab(int index)
        {
            _activeRightTab = index;
            OnPropertyChanged(nameof(IsDomainsTabActive));
            OnPropertyChanged(nameof(IsSchedulesTabActive));
            OnPropertyChanged(nameof(IsQuotaTabActive));
            OnPropertyChanged(nameof(IsAutostartTabActive));

            UpdateTabButtonClass("BtnTabDomains", index == 0);
            UpdateTabButtonClass("BtnTabSchedules", index == 1);
            UpdateTabButtonClass("BtnTabQuota", index == 2);
            UpdateTabButtonClass("BtnTabAutostart", index == 3);

            if (index == 1)
            {
                RefreshSchedulesList();
                RefreshScheduleTargetOptions();
            }
            else if (index == 2)
            {
                SyncQuotaInputFromSelectedDevice();
            }
            else if (index == 3)
            {
                RefreshAutostartStatusBadge();
            }
        }

        private void UpdateTabButtonClass(string name, bool isActive)
        {
            var btn = this.FindControl<Button>(name);
            if (btn == null) return;

            btn.Classes.Clear();
            btn.Classes.Add("panel-tab");
            if (isActive)
            {
                btn.Classes.Add("active");
            }
        }

        // ── Jadwal & Timer Handlers ──

        public void OnScheduleFormChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_uiInitialized) return;

            var kindBox = this.FindControl<ComboBox>("ScheduleKindComboBox");
            var actionBox = this.FindControl<ComboBox>("ScheduleActionComboBox");

            int newKind = kindBox?.SelectedIndex ?? 0;
            int newAction = actionBox?.SelectedIndex ?? 0;

            if (_scheduleKindIndex != newKind)
            {
                _scheduleKindIndex = newKind;
                OnPropertyChanged(nameof(IsScheduleTimerMode));
                OnPropertyChanged(nameof(IsScheduleDailyMode));
            }

            if (_scheduleActionIndex != newAction)
            {
                _scheduleActionIndex = newAction;
                OnPropertyChanged(nameof(IsScheduleDomainAction));
                RefreshScheduleTargetOptions();
            }
        }

        public void OnAddScheduleClick(object sender, RoutedEventArgs e)
        {
            var targetBox = this.FindControl<ComboBox>("ScheduleTargetComboBox");
            var selectedTarget = targetBox?.SelectedItem as BlockTargetOption;
            var actionType = IsScheduleDomainAction ? ScheduleActionType.BlockDomain : ScheduleActionType.BlockInternet;

            if (selectedTarget == null || (actionType == ScheduleActionType.BlockInternet && string.IsNullOrEmpty(selectedTarget.Mac)))
            {
                SetStatus("Pilih perangkat target terlebih dahulu (pindai jaringan jika daftar kosong).", "warning");
                return;
            }

            string domainText = this.FindControl<TextBox>("ScheduleDomainInput")?.Text;
            BlockScheduleRule added;

            if (IsScheduleTimerMode)
            {
                var minInput = this.FindControl<NumericUpDown>("ScheduleMinutesInput");
                int minutes = Math.Max(1, (int)(minInput?.Value ?? 30));
                added = BlockScheduleStore.AddTimerRule(
                    actionType,
                    selectedTarget.Mac,
                    selectedTarget.DisplayName,
                    domainText,
                    minutes);
            }
            else
            {
                string startText = this.FindControl<TextBox>("ScheduleStartInput")?.Text;
                string endText = this.FindControl<TextBox>("ScheduleEndInput")?.Text;
                added = BlockScheduleStore.AddDailyRule(
                    actionType,
                    selectedTarget.Mac,
                    selectedTarget.DisplayName,
                    domainText,
                    startText,
                    endText);
            }

            if (added == null)
            {
                if (actionType == ScheduleActionType.BlockDomain)
                {
                    SetStatus("Format domain tidak valid (mis. youtube.com atau roblox.com).", "warning");
                }
                else
                {
                    SetStatus("Format jam tidak valid. Gunakan format 24 jam HH:mm (mis. 19:00 dan 21:00).", "warning");
                }
                return;
            }

            var domainBox = this.FindControl<TextBox>("ScheduleDomainInput");
            if (domainBox != null) domainBox.Text = string.Empty;

            RefreshSchedulesList();
            EvaluateSchedulesAndQuotas();

            string spoofReminder = (_engine == null || !_engine.IsSpoofing)
                ? " (aktifkan MULAI ARP SPOOF agar blokir bekerja)"
                : string.Empty;
            SetStatus($"Jadwal '{added.ActionSummary}' untuk {added.TargetDisplay} ditambahkan.{spoofReminder}", "success");
        }

        public void OnRemoveScheduleClick(object sender, RoutedEventArgs e)
        {
            if (sender is Control control && control.DataContext is BlockScheduleRule rule)
            {
                if (BlockScheduleStore.RemoveRule(rule.Id))
                {
                    RefreshSchedulesList();
                    EvaluateSchedulesAndQuotas();
                    SetStatus($"Jadwal '{rule.ActionSummary}' ({rule.TargetDisplay}) dihapus.", "info");
                }
            }
        }

        private void RefreshSchedulesList(IReadOnlyList<BlockScheduleRule> rules = null)
        {
            var list = rules ?? BlockScheduleStore.GetRules();
            BlockSchedules.Clear();
            foreach (var r in list)
            {
                BlockSchedules.Add(r);
            }
        }

        private void EvaluateSchedulesAndQuotas()
        {
            DateTime now = DateTime.Now;
            var expired = BlockScheduleStore.PurgeExpiredTimers(now);
            bool domainRefreshNeeded = false;

            if (expired.Count > 0)
            {
                domainRefreshNeeded = expired.Any(r => r.ActionType == ScheduleActionType.BlockDomain);
                SetStatus($"Timer blokir selesai ({expired[0].ActionSummary} — {expired[0].TargetDisplay}).", "info");
            }

            BlockScheduleStore.GetActiveInternetBlockedMacs(now, out var macReasons);

            var allSchedules = BlockScheduleStore.GetRules();
            int activeCount = 0;
            int activeDomainCount = 0;
            foreach (var r in allSchedules)
            {
                if (BlockScheduleStore.IsRuleActiveAt(r, now))
                {
                    activeCount++;
                    if (r.ActionType == ScheduleActionType.BlockDomain)
                    {
                        activeDomainCount++;
                    }
                }
            }

            if (activeDomainCount != _lastActiveDomainScheduleCount)
            {
                _lastActiveDomainScheduleCount = activeDomainCount;
                domainRefreshNeeded = true;
            }

            ScheduleTabTitle = activeCount > 0 ? $"Jadwal ({activeCount})" : "Jadwal & Timer";

            if (IsSchedulesTabActive || expired.Count > 0)
            {
                RefreshSchedulesList(allSchedules);
            }

            foreach (var pc in DetectedPCs)
            {
                if (!pc.CanControl || pc.Mac == null) continue;
                string mac = pc.MacFormatted;

                if (macReasons.TryGetValue(mac, out string schedReason))
                {
                    if (_scheduleBlockedMacs.Add(mac))
                    {
                        _preScheduleStates[mac] = (pc.Redirect, pc.Block);
                        SetStatus($"Jadwal aktif: {pc.DeviceLabel} diblokir ({schedReason}).", "warning");
                    }

                    if (!pc.Block || !string.Equals(pc.ActiveScheduleNote, schedReason, StringComparison.Ordinal))
                    {
                        _isApplyingProgrammaticState = true;
                        try
                        {
                            if (!pc.Block) pc.Block = true;
                            pc.ActiveScheduleNote = schedReason;
                        }
                        finally
                        {
                            _isApplyingProgrammaticState = false;
                        }
                    }
                    continue;
                }

                if (_scheduleBlockedMacs.Remove(mac))
                {
                    _isApplyingProgrammaticState = true;
                    try
                    {
                        if (_preScheduleStates.TryGetValue(mac, out var prev))
                        {
                            _preScheduleStates.Remove(mac);
                            if (prev.Block)
                            {
                                pc.Block = true;
                            }
                            else
                            {
                                pc.Block = false;
                                if (prev.Redirect) pc.Redirect = true;
                            }
                        }
                        else
                        {
                            pc.Block = false;
                        }

                        if (!pc.IsQuotaExceeded)
                        {
                            pc.ActiveScheduleNote = string.Empty;
                        }
                    }
                    finally
                    {
                        _isApplyingProgrammaticState = false;
                    }
                }

                if (pc.IsQuotaExceeded)
                {
                    string quotaReason = $"⚠ Kuota {pc.DataQuotaMb} MB tercapai";
                    if (_quotaBlockedMacs.Add(mac))
                    {
                        _preQuotaStates[mac] = (pc.Redirect, pc.Block);
                        _isApplyingProgrammaticState = true;
                        try
                        {
                            if (!pc.Block) pc.Block = true;
                            pc.ActiveScheduleNote = quotaReason;
                        }
                        finally
                        {
                            _isApplyingProgrammaticState = false;
                        }
                        SetStatus($"Kuota data {pc.DataQuotaMb} MB untuk {pc.DeviceLabel} tercapai — perangkat diblokir.", "warning");
                    }
                    else if (!string.Equals(pc.ActiveScheduleNote, quotaReason, StringComparison.Ordinal))
                    {
                        pc.ActiveScheduleNote = quotaReason;
                    }
                }
                else if (_quotaBlockedMacs.Remove(mac))
                {
                    _isApplyingProgrammaticState = true;
                    try
                    {
                        if (_preQuotaStates.TryGetValue(mac, out var prevQuota))
                        {
                            _preQuotaStates.Remove(mac);
                            if (prevQuota.Block)
                            {
                                pc.Block = true;
                            }
                            else
                            {
                                pc.Block = false;
                                if (prevQuota.Redirect) pc.Redirect = true;
                            }
                        }
                        else
                        {
                            pc.Block = false;
                        }
                        pc.ActiveScheduleNote = string.Empty;
                    }
                    finally
                    {
                        _isApplyingProgrammaticState = false;
                    }
                }
            }

            if (domainRefreshNeeded)
            {
                RefreshRequestStatuses();
            }

            if (_windowGeometryDirty)
            {
                _windowGeometryDirty = false;
                SaveCurrentAppSettings();
            }

            UpdateTrayTooltip();
        }

        // ── Kuota & Total Data Handlers ──

        public void OnQuotaTargetSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!_uiInitialized) return;
            SyncQuotaInputFromSelectedDevice();
        }

        private void SyncQuotaInputFromSelectedDevice()
        {
            var quotaBox = this.FindControl<ComboBox>("QuotaTargetComboBox");
            var quotaInput = this.FindControl<NumericUpDown>("QuotaMbInput");
            if (quotaInput == null) return;

            var selected = quotaBox?.SelectedItem as BlockTargetOption;
            if (selected == null || string.IsNullOrEmpty(selected.Mac))
            {
                quotaInput.Value = 0;
                return;
            }

            var pc = DetectedPCs.FirstOrDefault(p => p.CanControl && string.Equals(p.MacFormatted, selected.Mac, StringComparison.OrdinalIgnoreCase));
            quotaInput.Value = pc?.DataQuotaMb ?? 0;
        }

        public void OnSaveQuotaClick(object sender, RoutedEventArgs e)
        {
            var quotaBox = this.FindControl<ComboBox>("QuotaTargetComboBox");
            var quotaInput = this.FindControl<NumericUpDown>("QuotaMbInput");
            var selected = quotaBox?.SelectedItem as BlockTargetOption;

            if (selected == null || string.IsNullOrEmpty(selected.Mac))
            {
                SetStatus("Pilih perangkat target terlebih dahulu pada tab Kuota & Data.", "warning");
                return;
            }

            var pc = DetectedPCs.FirstOrDefault(p => p.CanControl && string.Equals(p.MacFormatted, selected.Mac, StringComparison.OrdinalIgnoreCase));
            if (pc == null) return;

            int quotaMb = Math.Max(0, (int)(quotaInput?.Value ?? 0));
            pc.DataQuotaMb = quotaMb;
            EvaluateSchedulesAndQuotas();

            string msg = quotaMb == 0
                ? $"Kuota data untuk {pc.DeviceLabel} diubah ke Tanpa Batas."
                : $"Batas kuota {quotaMb} MB disimpan untuk {pc.DeviceLabel}.";
            SetStatus(msg, "success");
        }

        public void OnResetDataUsageClick(object sender, RoutedEventArgs e)
        {
            foreach (var pc in DetectedPCs)
            {
                pc.ResetTotalData();
            }

            EvaluateSchedulesAndQuotas();
            SetStatus("Total pemakaian data semua perangkat direset ke 0 B.", "info");
        }

        // ── Autostart & Startup Automation Handlers ──

        public void OnUseCurrentRouterClick(object sender, RoutedEventArgs e)
        {
            if (TryCaptureCurrentGateway(out string mac, out string label))
            {
                _homeRouterMac = mac;
                _homeRouterLabel = label;
                OnPropertyChanged(nameof(HomeRouterDisplay));
                SaveCurrentAppSettings();
                SetStatus($"Router rumah disimpan: {HomeRouterDisplay}.", "success");
            }
            else
            {
                SetStatus("Pindai jaringan terlebih dahulu agar MAC Router terdeteksi.", "warning");
            }
        }

        public void OnSaveAutostartSettingsClick(object sender, RoutedEventArgs e)
        {
            if (AutoSpoofAfterScan &&
                OnlyAutoSpoofOnHomeRouter &&
                string.IsNullOrWhiteSpace(_homeRouterMac) &&
                TryCaptureCurrentGateway(out string mac, out string label))
            {
                _homeRouterMac = mac;
                _homeRouterLabel = label;
                OnPropertyChanged(nameof(HomeRouterDisplay));
            }

            string regMsg = string.Empty;
            if (AutoStartWithWindows || _isAutostartTaskRegistered)
            {
                var (ok, msg) = AutostartManager.SetAutostart(AutoStartWithWindows);
                RefreshAutostartStatusBadge();

                if (!ok)
                {
                    AutoStartWithWindows = _isAutostartTaskRegistered;
                    SaveCurrentAppSettings();
                    SetStatus(msg, "error");
                    return;
                }

                regMsg = $" {msg}";
            }

            SaveCurrentAppSettings();

            if (AutoSpoofAfterScan && OnlyAutoSpoofOnHomeRouter && string.IsNullOrWhiteSpace(_homeRouterMac))
            {
                SetStatus($"Pengaturan disimpan.{regMsg} Pindai jaringan & klik 'Pakai Router Ini' agar Auto-Spoof dapat aktif.", "warning");
                return;
            }

            SetStatus($"Pengaturan Autostart berhasil disimpan.{regMsg}", "success");
        }

        private bool TryCaptureCurrentGateway(out string mac, out string label)
        {
            var gateway = DetectedPCs.FirstOrDefault(p => p.IsGateway);
            mac = gateway?.Mac != null
                ? AppSettingsStore.NormalizeMac(gateway.MacFormatted)
                : AppSettingsStore.FormatMacBytes(_engine?.RouterMac);

            if (string.IsNullOrWhiteSpace(mac))
            {
                label = string.Empty;
                return false;
            }

            label = gateway?.DeviceLabel ?? string.Empty;
            return true;
        }

        private void RefreshAutostartStatusBadge()
        {
            _isAutostartTaskRegistered = AutostartManager.IsAutostartRegistered();
            OnPropertyChanged(nameof(AutostartStatusBadge));
            OnPropertyChanged(nameof(AutostartStatusBrushHex));
        }

        private void SaveCurrentAppSettings()
        {
            AppSettingsStore.SaveSettings(new AppSettings
            {
                AutoStartWithWindows = AutoStartWithWindows,
                StartMinimizedToTray = StartMinimizedToTray,
                MinimizeToTray = MinimizeToTray,
                AutoScanOnStartup = AutoScanOnStartup,
                AutoSpoofAfterScan = AutoScanOnStartup && AutoSpoofAfterScan,
                OnlyAutoSpoofOnHomeRouter = OnlyAutoSpoofOnHomeRouter,
                HomeRouterMac = _homeRouterMac,
                HomeRouterLabel = _homeRouterLabel,
                PreferredInterfaceName = _preferredInterfaceName,
                WindowWidth = _savedWindowWidth,
                WindowHeight = _savedWindowHeight,
                WindowMaximized = _wasWindowMaximized
            });
        }

        // ── Blocked Domains Helpers ──

        private void RefreshBlockedDomainsList()
        {
            BlockedDomains.Clear();
            foreach (var rule in BlockedDomainStore.GetBlockedRules())
            {
                BlockedDomains.Add(rule);
            }
        }

        private void RefreshBlockTargetOptions()
        {
            var targetBox = this.FindControl<ComboBox>("BlockTargetComboBox");
            string prevBlockMac = (targetBox?.SelectedItem as BlockTargetOption)?.Mac ?? string.Empty;

            var quotaBox = this.FindControl<ComboBox>("QuotaTargetComboBox");
            string prevQuotaMac = (quotaBox?.SelectedItem as BlockTargetOption)?.Mac ?? string.Empty;

            BlockTargetOptions.Clear();
            BlockTargetOptions.Add(new BlockTargetOption { Mac = string.Empty, DisplayName = "Semua (Di-Spoof)" });

            QuotaTargetOptions.Clear();

            foreach (var pc in DetectedPCs)
            {
                if (pc.CanControl && pc.Mac != null)
                {
                    BlockTargetOptions.Add(new BlockTargetOption
                    {
                        Mac = pc.MacFormatted,
                        DisplayName = pc.DeviceLabel
                    });
                    QuotaTargetOptions.Add(new BlockTargetOption
                    {
                        Mac = pc.MacFormatted,
                        DisplayName = pc.DeviceLabel
                    });
                }
            }

            RestoreComboSelection(targetBox, BlockTargetOptions, prevBlockMac);
            RestoreComboSelection(quotaBox, QuotaTargetOptions, prevQuotaMac);
            SyncQuotaInputFromSelectedDevice();
            RefreshScheduleTargetOptions();
        }

        private void RefreshScheduleTargetOptions()
        {
            var schedBox = this.FindControl<ComboBox>("ScheduleTargetComboBox");
            string prevMac = (schedBox?.SelectedItem as BlockTargetOption)?.Mac ?? string.Empty;

            ScheduleTargetOptions.Clear();
            if (IsScheduleDomainAction)
            {
                ScheduleTargetOptions.Add(new BlockTargetOption { Mac = string.Empty, DisplayName = "Semua (Di-Spoof)" });
            }

            foreach (var pc in DetectedPCs)
            {
                if (pc.CanControl && pc.Mac != null)
                {
                    ScheduleTargetOptions.Add(new BlockTargetOption
                    {
                        Mac = pc.MacFormatted,
                        DisplayName = pc.DeviceLabel
                    });
                }
            }

            RestoreComboSelection(schedBox, ScheduleTargetOptions, prevMac);
        }

        private static void RestoreComboSelection(ComboBox combo, ObservableCollection<BlockTargetOption> items, string preferredMac)
        {
            if (combo == null) return;
            if (items.Count == 0)
            {
                combo.SelectedIndex = -1;
                return;
            }

            int idx = 0;
            if (!string.IsNullOrEmpty(preferredMac))
            {
                for (int i = 0; i < items.Count; i++)
                {
                    if (string.Equals(items[i].Mac, preferredMac, StringComparison.OrdinalIgnoreCase))
                    {
                        idx = i;
                        break;
                    }
                }
            }
            combo.SelectedIndex = idx;
        }

        private void RefreshRequestStatuses()
        {
            foreach (var entry in RecentDomainRequests)
            {
                bool targetEligible = entry.Device == null || (entry.Device.Redirect && !entry.Device.IsLocalPc);
                entry.IsBlocked = targetEligible && BlockedDomainStore.IsDomainBlocked(entry.Domain, entry.Device?.MacFormatted);
            }

            foreach (var pc in DetectedPCs)
            {
                pc.IsLastDomainBlocked = pc.Redirect && !pc.IsLocalPc &&
                                         !string.IsNullOrEmpty(pc.LastDomain) &&
                                         BlockedDomainStore.IsDomainBlocked(pc.LastDomain, pc.MacFormatted);
            }
        }

        // ── System Tray Lifecycle ──

        private void InitializeTrayIcon()
        {
            try
            {
                WindowIcon icon = null;
                try
                {
                    using var stream = AssetLoader.Open(new Uri("avares://NetControl/Assets/app_icon.ico"));
                    icon = new WindowIcon(stream);
                }
                catch
                {
                    icon = this.Icon;
                }

                var openItem = new NativeMenuItem("Buka NetControl");
                openItem.Click += (_, _) => Dispatcher.UIThread.Post(RestoreFromTray);

                var exitItem = new NativeMenuItem("Keluar & Pulihkan Jaringan");
                exitItem.Click += (_, _) => Dispatcher.UIThread.Post(ExitApplicationFromTray);

                var menu = new NativeMenu();
                menu.Items.Add(openItem);
                menu.Items.Add(new NativeMenuItemSeparator());
                menu.Items.Add(exitItem);

                _trayIcon = new TrayIcon
                {
                    Icon = icon,
                    ToolTipText = "NetControl — Siap",
                    IsVisible = true,
                    Menu = menu
                };
                _trayIcon.Clicked += (_, _) => Dispatcher.UIThread.Post(RestoreFromTray);

                if (Application.Current != null)
                {
                    TrayIcon.SetIcons(Application.Current, new TrayIcons { _trayIcon });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TRAY] Gagal menginisialisasi ikon system tray: {ex.Message}");
            }
        }

        public void OnHideToTrayClick(object sender, RoutedEventArgs e)
        {
            HideToTray();
        }

        private void HideToTray()
        {
            if (_isClosingApp) return;
            FlushWindowGeometry();
            ShowInTaskbar = false;
            Hide();
            UpdateTrayTooltip();
        }

        private void RestoreFromTray()
        {
            if (_isClosingApp) return;
            ShowInTaskbar = true;
            Show();
            WindowState = _wasWindowMaximized ? WindowState.Maximized : WindowState.Normal;
            Activate();
        }

        private void FlushWindowGeometry()
        {
            if (_windowGeometryDirty)
            {
                _windowGeometryDirty = false;
                SaveCurrentAppSettings();
            }
        }

        private void ExitApplicationFromTray()
        {
            _isClosingApp = true;
            Close();
            if (Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.Shutdown();
            }
        }

        private void UpdateTrayTooltip()
        {
            if (_trayIcon == null) return;
            string spoofState = _engine?.IsSpoofing == true ? "Spoof Aktif" : "Siap";
            _trayIcon.ToolTipText = $"NetControl — {spoofState} | Intersepsi: {SpoofedCount} | Blokir: {BlockedCount}";
        }

        private void DisposeTrayIcon()
        {
            try
            {
                if (_trayIcon != null)
                {
                    _trayIcon.IsVisible = false;
                    _trayIcon.Dispose();
                    _trayIcon = null;
                }
                if (Application.Current != null)
                {
                    TrayIcon.SetIcons(Application.Current, new TrayIcons());
                }
            }
            catch { }
        }

        protected override void OnClosing(WindowClosingEventArgs e)
        {
            if (!_isClosingApp &&
                MinimizeToTray &&
                _trayIcon != null &&
                e.CloseReason != WindowCloseReason.ApplicationShutdown &&
                e.CloseReason != WindowCloseReason.OSShutdown)
            {
                e.Cancel = true;
                Dispatcher.UIThread.Post(HideToTray);
                return;
            }

            base.OnClosing(e);
        }

        protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
        {
            base.OnPropertyChanged(change);

            if (_uiInitialized && !_isClosingApp)
            {
                if (change.Property == ClientSizeProperty && WindowState == WindowState.Normal && IsVisible)
                {
                    Size sz = ClientSize;
                    if (sz.Width >= MinWidth && sz.Height >= MinHeight &&
                        (Math.Abs(sz.Width - _savedWindowWidth) >= 1.0 || Math.Abs(sz.Height - _savedWindowHeight) >= 1.0))
                    {
                        _savedWindowWidth = Math.Round(sz.Width);
                        _savedWindowHeight = Math.Round(sz.Height);
                        _windowGeometryDirty = true;
                    }
                }
                else if (change.Property == WindowStateProperty)
                {
                    var newState = change.GetNewValue<WindowState>();
                    if (newState == WindowState.Normal || newState == WindowState.Maximized)
                    {
                        bool isMax = newState == WindowState.Maximized;
                        if (_wasWindowMaximized != isMax)
                        {
                            _wasWindowMaximized = isMax;
                            _windowGeometryDirty = true;
                        }
                    }
                    else if (newState == WindowState.Minimized && MinimizeToTray && _trayIcon != null)
                    {
                        Dispatcher.UIThread.Post(HideToTray);
                    }
                }
            }
        }

        private void Cleanup()
        {
            try
            {
                _maintenanceTimer?.Stop();
                if (_engine != null)
                {
                    _engine.OnInterfaceDisconnected -= OnEngineInterfaceDisconnected;
                    _engine.OnDomainRequested -= OnEngineDomainRequested;
                }
                _identifierService?.StopMdnsListener();
                _identifierService?.Dispose();
                _identifierService = null;
                _engine?.Dispose();
                _engine = null;
            }
            catch { }
        }

        protected override void OnClosed(EventArgs e)
        {
            _isClosingApp = true;
            FlushWindowGeometry();
            DisposeTrayIcon();
            Cleanup();
            base.OnClosed(e);
        }

        // ── INotifyPropertyChanged ──

        public new event PropertyChangedEventHandler PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}