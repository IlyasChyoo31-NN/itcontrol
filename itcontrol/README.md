# IT Operation Control Tower (Django + Tabler.io Edition)

Sistem **Remote Monitoring & Management (RMM)** berbasis **Python (Django)** dengan antarmuka enterprise modern menggunakan template **Tabler.io** (Bootstrap 5 Admin + Tabler Icons).

---

## 1. Arsitektur & Teknologi

- **Backend**: Python 3.10+ dengan **Django 5.x**, database **SQLite3** (`it_operation.db`).
  - `itops_tower/`: Konfigurasi project Django (`settings.py`, `urls.py`, `wsgi.py`, `asgi.py`).
  - `control_tower/`: Core RMM app (`models.py`, `views.py`, `urls.py`, `admin.py`).
- **Frontend UI**: Template enterprise **Tabler.io** (responsive, dark/light mode toggle, status badges, metrics, modal viewer).
- **Client Agent**: `agent.py` berbasis `psutil` dan Windows Management Instrumentation/Registry untuk memonitor laptop target tanpa dependensi GUI.
- **Port**: Default berjalan pada port `5000` (`0.0.0.0:5000`).

---

## 2. Fitur Utama

- **Live Fleet Monitoring**: Heartbeat telemetri CPU, RAM, Disk partitions, Network interfaces, dan uptime.
- **Debounced Threshold Alerts**: Peringatan bertingkat (Warning / Critical) untuk CPU > 80%/95%, RAM > 85%/95%, Disk > 85%/95%, dan bandwidth jika kapasitas diatur.
- **Software Inventory & WinGet**: Katalog software lengkap dari registry dan integrasi pencarian paket WinGet untuk deployment jarak jauh.
- **Application Control**: Penghentian proses (`taskkill`), serta pencegahan aplikasi via AppLocker.
- **Active App Usage Tracker**: Pelacakan aplikasi foreground dan durasi pemakaian per pengguna.
- **Security & Defender**: Pemantauan status antivirus Windows Defender dan firewall profile.
- **Django Admin Portal**: Manajemen data langsung melalui `/admin/`.

---

## 3. Panduan Penggunaan

### A. Menjalankan Dashboard Server
Cukup klik dua kali file:
```bat
START_DASHBOARD.bat
```
Atau via terminal:
```bash
.venv\Scripts\python manage.py migrate
.venv\Scripts\python manage.py runserver 0.0.0.0:5000
```
Dashboard dapat dibuka di browser: `http://localhost:5000`.

### B. Membuat Superuser Django Admin (Opsional)
```bash
.venv\Scripts\python manage.py createsuperuser
```
Portal admin dapat diakses di: `http://localhost:5000/admin/`.

### C. Memasang Agent pada Laptop Target
1. Buka `agent_config.json` dan sesuaikan `server_url` dengan IP laptop/server IT (contoh: `http://192.168.1.100:5000/api/heartbeat`).
2. Klik kanan `INSTALL_AGENT.bat` -> pilih **Run as Administrator**.
3. Agent otomatis berjalan senyap di background dan didaftarkan ke Windows Task Scheduler agar selalu aktif saat laptop menyala.
4. Untuk menghapus agent, jalankan `UNINSTALL_AGENT.bat` sebagai Administrator.
