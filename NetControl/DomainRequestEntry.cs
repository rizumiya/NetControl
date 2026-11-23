using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace NetControl
{
    /// <summary>
    /// Entri log permintaan domain secara real-time untuk panel Monitor Request Live.
    /// </summary>
    public class DomainRequestEntry : INotifyPropertyChanged
    {
        public string Timestamp { get; set; } = DateTime.Now.ToString("HH:mm:ss");
        public PC Device { get; set; }
        public string DeviceIp { get; set; } = string.Empty;
        public string DeviceName { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;

        private bool _isBlocked;
        public bool IsBlocked
        {
            get => _isBlocked;
            set
            {
                if (_isBlocked != value)
                {
                    _isBlocked = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(StatusText));
                    OnPropertyChanged(nameof(StatusBrushHex));
                    OnPropertyChanged(nameof(ActionButtonText));
                }
            }
        }

        public string StatusText => IsBlocked ? "DIBLOKIR" : "DIAKSES";
        public string StatusBrushHex => IsBlocked ? "#F85149" : "#3FB950";
        public string ActionButtonText => IsBlocked ? "Buka" : "Blokir";

        public event PropertyChangedEventHandler PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
