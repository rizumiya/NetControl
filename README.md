# NetControl (Edisi Bahasa Indonesia)

Alat diagnostik bandwidth jaringan lokal, penemuan perangkat, pengontrol lalu lintas ARP, pemantau aktivitas domain *real-time*, serta penjadwalan akses jaringan lintas platform berbasis **.NET 8.0** dan **Avalonia UI** (penerus modern dari SelfishNet).

> [!NOTE]
> **Repositori:** Repositori ini (`https://github.com/rizumiya/NetControl`) merupakan pengembangan edisi Bahasa Indonesia yang dibangun di atas proyek sumber terbuka `nov0caina/NetControl` dengan berbagai peningkatan fitur, perbaikan keandalan jaringan, dan antarmuka pengelolaan perangkat rumahan/lab.

> [!IMPORTANT]
> **Penggunaan Etis dan Resmi:** NetControl dirancang khusus untuk diagnostik jaringan yang sah, pengelolaan bandwidth jaringan pribadi/keluarga, dan penelitian edukasi di lingkungan laboratorium yang terkontrol. Melakukan pengalihan cache ARP atau intersepsi paket pada jaringan milik pihak lain tanpa izin eksplisit adalah tindakan ilegal dan tidak etis.

---

## Fitur Utama & Peningkatan Baru

### 1. Antarmuka & Skrip Peluncur Bahasa Indonesia Penuh
- Seluruh UI aplikasi (*toolbar*, kartu KPI, tabel perangkat, panel kontrol, tooltip, dan pesan status) tersedia lengkap dalam **Bahasa Indonesia**.
- Dilengkapi skrip instalasi & peluncur praktis:
  - Windows: [install_windows.bat](install_windows.bat) dan [start_windows.bat](start_windows.bat) (dukungan UTF-8 `chcp 65001`, otomatis meminta hak Administrator UAC, dan otomatis menutup jendela CMD setelah membuka aplikasi).
  - Linux & macOS: [install_linux.sh](install_linux.sh), [start_linux.sh](start_linux.sh), [install_mac.sh](install_mac.sh), [start_mac.sh](start_mac.sh), serta [netcontrol.desktop](netcontrol.desktop).

### 2. Pemindaian Jaringan Andal & Pengurutan Tabel Rapi
- **Nama Adapter Ramah Pengguna:** Dropdown `Antarmuka:` menampilkan nama adapter yang mudah dikenali seperti `Wi-Fi — 192.168.1.68` atau `Ethernet — 192.168.1.xx` (bukan ID teknis `\Device\NPF_{...}`) dengan urutan adapter aktif ber-gateway di posisi teratas.
- **Pemindaian 2 Putaran + Cache OS:** Membaca *ARP cache* sistem operasi (`arp -a` / `/proc/net/arp` / `arp -an`) dan mengirim *ARP sweep* 2 putaran agar perangkat Wi-Fi dalam mode hemat daya tetap terdeteksi.
- **Identifikasi Perangkat & Filter ARP Probe:** Mendukung lookup vendor OUI, mDNS (dengan penyaringan *query* agar tidak salah mengenali Google Cast), DHCP Option 12, serta filter `0.0.0.0` (*ARP Probe* RFC 5227) agar tidak menimbulkan baris duplikat.
- **Pengurutan Tabel Otomatis:** Perangkat target selalu ditempatkan di urutan atas (diurutkan secara numerik berdasarkan IPv4), diikuti `ANDA` (perangkat lokal), lalu `GATEWAY` (router) di baris paling bawah.

### 3. Kontrol Lalu Lintas Akurat (`Spoof`, `Blokir`, & `Batas KB/s`)
- **User-Space Layer-2 Relay:** Paket perangkat yang di-**`Spoof`** diteruskan, dibatasi, dan difilter langsung oleh NetControl di *user-space* (dengan IP Forwarding kernel Windows tetap nonaktif), sehingga pembatasan bandwidth dan pemblokiran domain berjalan konsisten.
- **Metode ARP Ganda (`Spoof` & `Blokir` Mandiri):** Menggunakan pengiriman ganda (*ARP Reply* + *unicast ARP Request*) agar bekerja andal di perangkat Android dan router Wi-Fi modern, termasuk mode **`Blokir`** tanpa perlu mencentang **`Spoof`**, dilengkapi pemutusan koneksi instan (`TCP RST` dan `ICMP Port Unreachable` untuk QUIC UDP 443).
- **Pembatas Bandwidth Presisi:** Menggunakan `TokenBucketThrottler` untuk kolom **`Batas (KB/s)`** (`0` = Tanpa Batas), dilengkapi tombol spinner panah vertikal yang ringkas agar kolom input angka lebih luas.

### 4. Monitor Request Live & Pemblokir Website/Aplikasi Per Perangkat
- **Monitor Request / Domain Live:** Memantau domain yang diakses perangkat yang di-**`Spoof`** secara langsung melalui inspeksi **TLS SNI** (termasuk segmen lanjutan TLS 1.3 *Post-Quantum*), **DNS**, **HTTP Host**, serta deteksi IP **Telegram MTProto**.
- **Tolak QUIC UDP 443:** Mengarahkan trafik aplikasi/browser ke HTTPS TCP agar inspeksi SNI dan pemblokiran berjalan optimal.
- **Aturan Blokir Global atau Per MAC Address:** Bisa diterapkan ke **`Semua (Di-Spoof)`** atau spesifik ke satu perangkat saja, lewat input manual maupun klik **`Blokir` / `Buka`** langsung dari log live.
- **Ekspansi Domain Pendamping Otomatis:** Memblokir domain utama (misalnya `youtube.com`, `roblox.com`, `tiktok.com`, `instagram.com`, `facebook.com`, `twitter.com`/`x.com`, `netflix.com`, `telegram.org`/`t.me`, `whatsapp.com`) otomatis ikut memblokir domain CDN/API terkaitnya (`googlevideo.com`, `ytimg.com`, `rbxcdn.com`, dll.).

### 5. Jadwal & Timer Blokir (`Jadwal & Timer`)
- Tersedia mode **Timer** (hitungan mundur dalam menit) dan **Harian** (rentang jam berulang setiap hari, termasuk lintas tengah malam seperti `22:00–06:00`).
- Mendukung aksi **Blokir Internet** (per perangkat) maupun **Blokir Domain** (per perangkat atau semua).
- Status sisa waktu/jadwal tampil langsung di baris perangkat dan memulihkan kondisi sebelumnya secara otomatis saat jadwal berakhir.

### 6. Total Pemakaian Data & Kuota Otomatis (`Kuota & Data`)
- Menampilkan **total pemakaian data kumulatif** (`B` / `KB` / `MB` / `GB`) di bawah kecepatan Unduh/Unggah masing-masing perangkat.
- Panel **`Kuota & Data`** memungkinkan pengaturan batas kuota dalam **`MB`** per perangkat (`0` = Tanpa Batas); saat kuota tercapai, perangkat otomatis diblokir hingga kuota dinaikkan atau tombol **`Reset`** ditekan.

### 7. Label Kustom & Penyimpanan Otomatis Permanen
- Nama label kustom per MAC Address dapat diedit langsung dari tabel.
- Pengaturan **`Batas (KB/s)`**, status **`Spoof`**, **`Blokir`**, batas **`Kuota (MB)`**, serta **ukuran & status Maximize jendela** tersimpan otomatis dan dipulihkan saat NetControl dibuka ulang.

### 8. System Tray & Konfigurasi Autostart Gaya XAMPP (`Autostart`)
- Dikompilasi sebagai aplikasi GUI murni (`WinExe`) tanpa memunculkan jendela konsol hitam saat *startup*.
- Klik **`—` (Minimize)**, **`X` (Silang)**, atau tombol **`Ke Tray`** akan menyembunyikan NetControl ke System Tray; keluar penuh dan pemulihan ARP dilakukan lewat klik kanan ikon tray → **`Keluar & Pulihkan Jaringan`**.
- Tab **`Autostart`** menyediakan opsi:
  - **Jalankan saat Windows login (Admin)** via Windows Task Scheduler (`NetControl_Autostart`, hak *HighestAvailable* tanpa popup UAC, aktif di daya baterai).
  - **Mulai tersembunyi di System Tray** saat diluncurkan via Autostart.
  - **Otomatis Pindai Jaringan** (menunggu koneksi Wi-Fi/LAN siap maksimal 30 detik sebelum memindai).
  - **Otomatis nyalakan ARP Spoof setelah pindai** dengan pengaman **Khusus Router Rumah** (mencocokkan MAC Router tersimpan via **`Pakai Router Ini`** agar *Auto-Spoof* dilewati saat berada di jaringan publik).

---

## Arsitektur Modern & Dukungan Lintas Platform

| Komponen | SelfishNet Lama (Legacy) | NetControl |
| :--- | :--- | :--- |
| **Framework Runtime** | .NET Framework 3.5 (Hanya Windows) | **.NET 8.0 (LTS)** |
| **Antarmuka Pengguna** | Windows Forms (WinForms) | **Avalonia UI 11** (XAML Lintas Platform) |
| **Mesin Penangkap Paket** | PcapNet / WinPcap | **SharpPcap** (di atas `libpcap` / `Npcap` asli) |
| **Penerusan & Pembatasan** | Hook Windows Native | **User-Space Layer-2 Relay + `TokenBucketThrottler`** |
| **Sistem Operasi** | Windows XP / 7 / 8 / 10 | **Windows (x64), Linux (x64), macOS (arm64 & x64)** |
| **Pemaketan** | Pemasang manual | **Biner mandiri satu berkas (*Single-file self-contained*)** |

---

## Lokasi Berkas Konfigurasi Lokal

NetControl menyimpan seluruh konfigurasi secara lokal di `%LocalAppData%\NetControl\` (Windows) agar aturan tidak hilang saat aplikasi ditutup atau diperbarui:

| Berkas | Fungsi |
| :--- | :--- |
| `app_settings.json` | Opsi Autostart, interface pilihan, MAC Router Rumah, System Tray, ukuran jendela |
| `device_labels.json` | Nama label kustom perangkat berdasarkan MAC Address |
| `device_settings.json` | Profil permanen `Batas (KB/s)`, `Spoof`, `Blokir`, dan `Kuota (MB)` per MAC |
| `blocked_domains.json` | Daftar blokir domain/website (global dan per perangkat) |
| `block_schedules.json` | Aturan jadwal harian dan timer blokir aktif |

---

## Paket Rilis Mandiri (Standalone)

Arsip rilis pada halaman [Releases](https://github.com/rizumiya/NetControl/releases) **tidak memerlukan .NET SDK/Runtime** terpasang karena seluruh dependensi sudah dibundel di dalamnya.

### 1. Windows (`x86_64`)
- **Paket:** `NetControl-windows-x64.zip`
- **Prasyarat:**
  - Pasang **Npcap** dari [npcap.com](https://npcap.com).
  - **PENTING:** Saat instalasi Npcap, **wajib centang opsi `"Install Npcap in WinPcap API-compatible Mode"`** agar `wpcap.dll` dan `packet.dll` dapat diakses oleh SharpPcap.
- **Eksekusi:**
  1. Ekstrak `NetControl-windows-x64.zip`.
  2. Klik kanan `NetControl.exe` → **"Run as administrator"** (wajib izin Administrator untuk akses adapter jaringan & pendaftaran Task Scheduler Autostart).

### 2. Linux (`x86_64`)
- **Paket:** `NetControl-linux-x64.tar.gz`
- **Prasyarat:** Runtime `libpcap` (Ubuntu/Debian: `sudo apt install libpcap0.8` atau `libpcap-dev`).
- **Eksekusi:**
  ```bash
  pkexec ./NetControl
  # atau
  sudo -E ./NetControl
  ```
  Untuk menjalankan tanpa `sudo` setiap kali dibuka:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip ./NetControl
  ./NetControl
  ```

### 3. macOS (`Apple Silicon arm64` & `Intel x64`)
- **Paket:** `NetControl-macos-arm64.tar.gz` (M1–M4) / `NetControl-macos-x64.tar.gz` (Intel)
- **Prasyarat:** macOS 11.0 (Big Sur) atau lebih baru.
- **Eksekusi:**
  ```bash
  tar -xzf NetControl-macos-arm64.tar.gz
  xattr -d com.apple.quarantine ./NetControl
  chmod +x ./NetControl
  sudo ./NetControl
  ```

### Verifikasi Integritas Kriptografi
Verifikasi keaslian berkas rilis menggunakan berkas `SHA256SUMS`:
- **Windows (PowerShell):**
  ```powershell
  Get-FileHash .\NetControl-windows-x64.zip -Algorithm SHA256
  ```
- **Linux / macOS:**
  ```bash
  sha256sum -c SHA256SUMS
  ```

---

## Kompilasi dari Kode Sumber

### Prasyarat
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Driver penangkap paket platform (`Npcap` WinPcap-compatible mode di Windows, `libpcap-dev` di Linux)

### 1. Kloning Repositori
```bash
git clone https://github.com/rizumiya/NetControl.git
cd NetControl
```

### 2. Instalasi & Jalankan (Cara Cepat Windows)
- Jalankan **`install_windows.bat`** untuk memeriksa .NET 8 SDK, memulihkan paket, dan membangun build *Release*.
- Jalankan **`start_windows.bat`** untuk membuka NetControl sebagai Administrator.

### 3. Build, Jalankan, & Uji Otomatis via CLI
Proyek ini dilengkapi **52 unit test** (perhitungan subnet, akurasi rate, identifikasi OUI, isolasi aturan blokir domain, TLS SNI/DNS parser, jadwal/timer, kuota data, filter ARP Probe, dan validasi konfigurasi Autostart):

```bash
# Bangun seluruh solusi dalam mode Release
dotnet build NetControl.sln -c Release

# Jalankan seluruh 52 unit test
dotnet test NetControl.sln -c Release

# Jalankan aplikasi (memerlukan hak Administrator / root)
dotnet run --project NetControl/NetControl.csproj -c Release
```

### 4. Publikasi Biner Mandiri (Standalone)
```bash
# Windows x64
dotnet publish NetControl/NetControl.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o dist/win-x64

# Linux x64
dotnet publish NetControl/NetControl.csproj -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o dist/linux-x64

# macOS Apple Silicon (arm64)
dotnet publish NetControl/NetControl.csproj -c Release -r osx-arm64 --self-contained -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o dist/osx-arm64

# macOS Intel (x64)
dotnet publish NetControl/NetControl.csproj -c Release -r osx-x64 --self-contained -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o dist/osx-x64
```

---

## Lisensi

Proyek ini dilisensikan di bawah Lisensi MIT. Lihat berkas [LICENSE](LICENSE) untuk detail selengkapnya.
