using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;

namespace NetControl
{
    /// <summary>Callback when a device is detected or removed.</summary>
    public delegate void OnDeviceEvent(PC pc);

    public class PcList : IDisposable
    {
        private OnDeviceEvent _onDeviceAdded;
        private OnDeviceEvent _onDeviceRemoved;
        private IDeviceIdentifierService _identifierService;

        private readonly object _syncLock = new();
        private readonly List<PC> _devices = new();

        /// <summary>
        /// Returns a thread-safe snapshot (array copy) for external iteration.
        /// </summary>
        public IReadOnlyList<PC> Devices
        {
            get
            {
                lock (_syncLock)
                {
                    return _devices.ToArray();
                }
            }
        }

        public bool AddDevice(PC pc)
        {
            if (pc?.Ip == null) return false;

            if (pc.Mac != null && string.IsNullOrWhiteSpace(pc.CustomLabel))
            {
                string savedLabel = DeviceLabelStore.GetLabel(pc.MacFormatted);
                if (!string.IsNullOrWhiteSpace(savedLabel))
                {
                    pc.CustomLabel = savedLabel;
                }
            }

            if (pc.Mac != null && pc.CanControl)
            {
                ApplySavedProfile(pc);
            }

            bool isNew = false;
            PC macUpdatedItem = null;
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    if (item.Ip != null && item.Ip.Equals(pc.Ip))
                    {
                        item.TimeSinceLastArp = DateTime.Now;
                        // Update MAC if changed or newly detected
                        if (pc.Mac != null && (item.Mac == null || !item.Mac.Equals(pc.Mac)))
                        {
                            item.Mac = pc.Mac;
                            if (string.IsNullOrWhiteSpace(item.CustomLabel))
                            {
                                string savedLabel = DeviceLabelStore.GetLabel(item.MacFormatted);
                                if (!string.IsNullOrWhiteSpace(savedLabel))
                                {
                                    item.CustomLabel = savedLabel;
                                }
                            }
                            macUpdatedItem = item;
                        }
                        if (pc.IsGateway && !item.IsGateway) item.IsGateway = true;
                        if (pc.IsLocalPc && !item.IsLocalPc) item.IsLocalPc = true;
                        break;
                    }
                }
                if (macUpdatedItem == null)
                {
                    // Check again whether loop exited on existing IP without MAC update
                    bool exists = false;
                    foreach (PC item in _devices)
                    {
                        if (item.Ip != null && item.Ip.Equals(pc.Ip))
                        {
                            exists = true;
                            break;
                        }
                    }
                    if (!exists)
                    {
                        _devices.Add(pc);
                        isNew = true;
                    }
                }
            }

            if (macUpdatedItem != null &&
                macUpdatedItem.CanControl &&
                !macUpdatedItem.Redirect &&
                !macUpdatedItem.Block &&
                macUpdatedItem.BandwidthLimitKb == 0 &&
                macUpdatedItem.DataQuotaMb == 0)
            {
                ApplySavedProfile(macUpdatedItem);
            }

            if (isNew)
            {
                // Invoke callback outside lock to prevent UI thread deadlocks
                _onDeviceAdded?.Invoke(pc);

                // Fire-and-forget device identification (OUI + DNS + heuristic)
                if (_identifierService != null)
                {
                    _ = _identifierService.IdentifyDeviceAsync(pc, CancellationToken.None);
                }
            }

            return isNew;
        }

        private static void ApplySavedProfile(PC pc)
        {
            if (pc?.Mac == null || !pc.CanControl) return;

            var profile = DeviceSettingsStore.GetProfile(pc.MacFormatted);
            if (profile == null) return;

            pc.BandwidthLimitKb = profile.BandwidthLimitKb;
            pc.DataQuotaMb = profile.DataQuotaMb;
            if (profile.Block)
            {
                pc.Block = true;
            }
            else if (profile.Redirect)
            {
                pc.Redirect = true;
            }
        }

        public bool RemoveDevice(PC pc)
        {
            if (pc?.Ip == null) return false;
            PC found = null;
            lock (_syncLock)
            {
                for (int i = 0; i < _devices.Count; i++)
                {
                    if (_devices[i].Ip != null && _devices[i].Ip.Equals(pc.Ip))
                    {
                        found = _devices[i];
                        _devices.RemoveAt(i);
                        break;
                    }
                }
            }

            if (found != null)
            {
                _onDeviceRemoved?.Invoke(found);
                return true;
            }
            return false;
        }

        public PC GetRouter()
        {
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    if (item.IsGateway) return item;
                }
            }
            return null;
        }

        public PC GetLocalPC()
        {
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    if (item.IsLocalPc) return item;
                }
            }
            return null;
        }

        public PC GetDeviceByIp(IPAddress ip)
        {
            if (ip == null) return null;
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    if (item.Ip != null && item.Ip.Equals(ip))
                        return item;
                }
            }
            return null;
        }

        public PC GetDeviceByIp(byte[] ip)
        {
            if (ip == null) return null;
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    if (item.Ip != null && Tools.AreValuesEqual(item.Ip.GetAddressBytes(), ip))
                        return item;
                }
            }
            return null;
        }

        public PC GetDeviceByMac(byte[] mac)
        {
            if (mac == null) return null;
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    if (item.Mac != null && Tools.AreValuesEqual(item.Mac.GetAddressBytes(), mac))
                        return item;
                }
            }
            return null;
        }

        public void ResetAllPacketCounts()
        {
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    item.BytesReceived = 0;
                    item.BytesSent = 0;
                }
            }
        }

        public void SetOnDeviceAdded(OnDeviceEvent callback)
        {
            _onDeviceAdded += callback;
        }

        public void SetOnDeviceRemoved(OnDeviceEvent callback)
        {
            _onDeviceRemoved += callback;
        }

        public void SetIdentifierService(IDeviceIdentifierService service)
        {
            _identifierService = service;
        }

        public void Clear()
        {
            lock (_syncLock)
            {
                _devices.Clear();
            }
        }

        public void Dispose()
        {
            Clear();
            GC.SuppressFinalize(this);
        }
    }
}
