# SIEMbarangan — Security Information and Event Management Dashboard

**Kelompok 4 — Network and Cloud Computing (NCC) Final Project**

| Nama                       | NRP        |
| -------------------------- | ---------- |
| Reza Afzaal Faizullah Taqy | 5025241051 |
| Uwais Achmad               | 5025241103 |
| Mayandra Suhaira Frisiandi | 5025241240 |

SIEMbarangan adalah sistem SIEM berbasis web yang mengumpulkan, menganalisis, dan memvisualisasikan log keamanan secara real-time.

---

## 1. Arsitektur Sistem

```
┌────────────────────────────────────────────────────────┐
│                    VPS (157.245.145.87)                │
│                                                        │
│  ┌─────────────┐    ┌──────────────────────────────┐   │
│  │   Browser   │    │      Docker: fp-siem         │   │
│  │  (Frontend) │◄──►│  FastAPI + Static Files      │   │
│  └─────────────┘    │  Port 8000                   │   │
│         WebSocket   │                              │   │
│                     │  ┌──────────────────────┐    │   │
│                     │  │   Log Pipeline       │    │   │
│                     │  │  Collector → Parser  │    │   │
│                     │  │  → Rule Engine →     │    │   │
│                     │  │  MySQL → WebSocket   │    │   │
│                     │  └──────────────────────┘    │   │
│                     └──────────────┬───────────────┘   │
│                                    │ /metrics          │
│  ┌─────────────────────────────────▼──────────────┐    │
│  │         Docker: monitoring_default network     │    │
│  │  ┌────────────┐  ┌───────────┐  ┌───────────┐  │    │
│  │  │ Prometheus │  │  Grafana  │  │  Node     │  │    │
│  │  │ Port 9090  │  │ Port 3000 │  │  Exporter │  │    │
│  │  └────────────┘  └───────────┘  └───────────┘  │    │
│  └────────────────────────────────────────────────┘    │
│                                                        │
│  ┌──────────────────┐   ┌────────────────────────┐     │
│  │ Jenkins (CI/CD)  │   │  SonarQube (QA Gate)   │     │
│  │ Port 8080        │   │  Port 9000             │     │
│  └──────────────────┘   └────────────────────────┘     │
└────────────────────────────────────────────────────────┘
```

**Alur Data:**

1. Log collector membaca file log atau log generator menghasilkan event simulasi
2. Setiap event di-parse menjadi `LogEvent` terstruktur
3. Rule engine mengevaluasi event terhadap semua rule deteksi
4. Event disimpan ke MySQL dan di-broadcast ke semua klien WebSocket
5. Prometheus mengambil metrics dari endpoint `/metrics` setiap 15 detik
6. Grafana memvisualisasikan metrics dari Prometheus

---

## 2. Fitur Utama

### Fitur Wajib

| Fitur                        | Status | Keterangan                              |
| ---------------------------- | ------ | --------------------------------------- |
| Pengumpulan Log Multi-sumber | Done   | Auth, Access, Firewall, Syslog, FIM     |
| Parsing & Normalisasi Log    | Done   | Log parser per source type              |
| Rule-based Threat Detection  | Done   | 20 rules dengan MITRE ATT&CK mapping    |
| Penyimpanan ke Database      | Done   | MySQL dengan connection pool            |
| Real-time Dashboard          | Done   | WebSocket, Chart.js                     |
| Visualisasi Statistik        | Done   | Severity distribution, Events over time |
| Filter & Live Event Table    | Done   | Filter by severity dan source           |

### Fitur Tambahan (Bonus)

| Fitur                    | Status | Keterangan                                         |
| ------------------------ | ------ | -------------------------------------------------- |
| Log Simulasi (Generator) | Done   | Menghasilkan event realistis secara otomatis       |
| Runtime Log Path Update  | Done   | Ganti path log file tanpa restart via UI           |
| Discord Webhook Alerting | Done   | Kirim alert Discord saat event CRITICAL terdeteksi |
| Prometheus Metrics       | Done   | 3 custom metrics dengan label                      |
| Grafana Dashboard SIEM   | Done   | 7 panel monitoring SIEM metrics                    |
| Grafana Dashboard System | Done   | 8 panel monitoring server resources                |
| Node Exporter            | Done   | CPU, Memory, Disk, Network dari host               |
| CI/CD Pipeline           | Done   | Jenkins: Test → SonarQube → Deploy                 |
| Quality Gate SonarQube   | Done   | Coverage ≥80%, 0 new issues                        |
| Pan/Zoom pada Chart      | Done   | chartjs-plugin-zoom pada timeline chart            |

---

## 3. Tech Stack

| Kategori         | Teknologi                       |
| ---------------- | ------------------------------- |
| Backend          | FastAPI                         |
| Runtime          | Python                          |
| Database         | MySQL                           |
| Async DB Driver  | aiomysql                        |
| File I/O         | aiofiles                        |
| WSGI/ASGI        | Uvicorn                         |
| Frontend         | Vanilla JS + Chart.js           |
| Chart Zoom       | chartjs-plugin-zoom + hammer.js |
| Metrics          | prometheus-client               |
| Monitoring       | Prometheus + Grafana            |
| System Metrics   | Node Exporter                   |
| CI/CD            | Jenkins (Blue Ocean)            |
| Code Analysis    | SonarQube                       |
| Containerization | Docker + Docker Compose         |
| Cloud            | DigitalOcean VPS                |

---

## 4. Struktur Proyek

```
final_project/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes.py          # REST API endpoints
│   │   │   └── websocket.py       # WebSocket connection manager
│   │   ├── core/
│   │   │   ├── log_collector.py   # File tail & generator orchestrator
│   │   │   ├── log_generator.py   # Simulasi log event
│   │   │   ├── log_parser.py      # Parser per log source
│   │   │   └── rule_engine.py     # Evaluasi rule deteksi ancaman
│   │   ├── db/
│   │   │   └── database.py        # MySQL connection pool & queries
│   │   ├── models/
│   │   │   └── log_event.py       # Dataclass LogEvent
│   │   ├── services/
│   │   │   └── discord_webhook.py # Discord webhook alerting
│   │   ├── config.py              # Environment variable config
│   │   ├── main.py                # FastAPI app & lifespan pipeline
│   │   └── metrics.py             # Prometheus metrics definitions
│   ├── rules/
│   │   └── default_rules.json     # Rule definitions (20 rules)
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_log_event.py
│   │   ├── test_log_generator.py
│   │   ├── test_log_parser.py
│   │   ├── test_rule_engine.py
│   │   ├── test_metrics.py
│   │   └── test_discord_webhook.py
│   └── requirements.txt
├── frontend/
│   ├── index.html                 # Halaman utama dashboard
│   ├── css/
│   │   └── style.css              # Dark theme styling
│   └── js/
│       ├── charts.js              # Chart.js setup (severity + timeline)
│       ├── websocket.js           # WebSocket client & reconnect logic
│       └── dashboard.js           # UI logic, filter, log path update
├── monitoring/
│   └── grafana/
│       └── dashboards/
│           ├── siem.json          # Grafana dashboard SIEM metrics
│           └── system.json        # Grafana dashboard system resources
├── Dockerfile
|
├── docker-compose.yml
├── Jenkinsfile
├── sonar-project.properties
└── README.md
```

---

## 5. Log Sources

Sistem mendukung 5 jenis sumber log. Setiap source memiliki parser dan generator sendiri.

### Auth Log (`/var/log/auth.log`)

Log autentikasi SSH dari OpenSSH. Mendeteksi:

- **failed_login** — Password salah saat SSH
- **login** — Login SSH berhasil
- **invalid_user** — Percobaan login dengan username tidak dikenal

```
May 23 14:32:01 server sshd[2345]: Failed password for admin from 45.33.32.156 port 22
May 23 14:32:02 server sshd[2346]: Accepted password for ubuntu from 192.168.1.10 port 22
```

### Access Log (`/var/log/nginx/access.log`)

Log HTTP dari Nginx/Apache. Mendeteksi:

- **GET/POST/PUT/DELETE** — Request HTTP normal
- **sql_injection** — Pola SQL injection di URL
- **xss_attempt** — Pola XSS di URL
- **web_shell** — Akses ke path web shell (c99.php, r57.php, dll)

```
45.33.32.156 - - [23/May/2026:14:32:01 +0000] "GET /api/users?id=1'+OR+'1'='1 HTTP/1.1" 200 1024
```

### Firewall Log (`/var/log/ufw.log` / iptables)

Log UFW/iptables. Mendeteksi:

- **DROP** — Koneksi ditolak firewall
- **ACCEPT** — Koneksi diterima
- Arah koneksi: **inbound** / **outbound**

```
May 23 14:32:01 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=192.168.1.1 PROTO=TCP SPT=52341 DPT=4444
```

### Syslog (`/var/log/syslog`)

Log sistem umum. Mendeteksi:

- **sudo_command** — Eksekusi perintah via sudo
- **sudo_failed** — Gagal autentikasi sudo
- **service_stopped** / **service_started** — Perubahan status service
- **user_added** — Penambahan akun user baru

```
May 23 14:32:01 server sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/cat /etc/shadow
```

### FIM Log — File Integrity Monitoring

Event perubahan file sistem. Mendeteksi:

- **modified** — File dimodifikasi
- **created** — File baru dibuat
- **deleted** — File dihapus
- **attributes_changed** — Atribut file berubah

```
2026-05-23T14:32:01 fim: action=modified path=/etc/passwd uid=0 gid=0 md5=abc123 sha256=def456
```

---

## 6. Rule Engine & Deteksi Ancaman

Rule engine membaca `backend/rules/default_rules.json` dan mengevaluasi setiap event masuk terhadap semua rule secara berurutan. Jika sebuah rule match, field `rule_triggered` dan `severity` pada event diperbarui.

### Jenis Kondisi Rule

| Kondisi      | Keterangan                                        |
| ------------ | ------------------------------------------------- |
| `source`     | Jenis log (auth, access, firewall, syslog, fim)   |
| `action`     | Aksi spesifik (failed_login, DROP, modified, dll) |
| `status`     | Status event (FAILED, 200, 404, dll)              |
| `user`       | Username spesifik (misal: root)                   |
| `direction`  | Arah koneksi untuk firewall (inbound/outbound)    |
| `path_match` | Prefix/exact path untuk FIM events                |
| `time_range` | Rentang jam terjadinya event                      |
| `rate`       | N event dari IP yang sama dalam M detik           |

### Daftar Semua Rule (20 Rules)

| Rule ID | Nama                           | Severity | MITRE ID  | Taktik               |
| ------- | ------------------------------ | -------- | --------- | -------------------- |
| 5710    | ssh_brute_force                | CRITICAL | T1110     | Credential Access    |
| 5711    | invalid_user_attempt           | WARNING  | T1078     | Initial Access       |
| 5712    | root_login_success             | WARNING  | T1078.003 | Privilege Escalation |
| 5720    | ssh_login_outside_hours        | WARNING  | T1078     | Initial Access       |
| 31100   | http_server_error              | CRITICAL | T1499     | Impact               |
| 31101   | http_not_found_scan            | WARNING  | T1595     | Reconnaissance       |
| 31103   | sql_injection_attempt          | CRITICAL | T1190     | Initial Access       |
| 31104   | xss_attempt                    | CRITICAL | T1189     | Initial Access       |
| 31105   | web_shell_access               | CRITICAL | T1505.003 | Persistence          |
| 31110   | http_dos_flood                 | CRITICAL | T1498     | Impact               |
| 4100    | firewall_drop_flood            | CRITICAL | T1046     | Discovery            |
| 4101    | firewall_drop_single           | INFO     | T1046     | Discovery            |
| 4102    | firewall_outbound_unusual_port | WARNING  | T1571     | Command and Control  |
| 550     | fim_critical_file_modified     | CRITICAL | T1222     | Defense Evasion      |
| 551     | fim_file_deleted               | WARNING  | T1070.004 | Defense Evasion      |
| 552     | fim_binary_modified            | CRITICAL | T1554     | Persistence          |
| 5500    | privilege_escalation_sudo      | INFO     | T1548.003 | Privilege Escalation |
| 5501    | sudo_failed                    | WARNING  | T1548.003 | Privilege Escalation |
| 5502    | service_stopped                | WARNING  | T1489     | Impact               |
| 5503    | user_added                     | WARNING  | T1136     | Persistence          |

### Contoh Rule dengan Rate Detection (ssh_brute_force)

```json
{
  "rule_id": 5710,
  "name": "ssh_brute_force",
  "severity": "CRITICAL",
  "mitre_id": "T1110",
  "conditions": {
    "source": "auth",
    "action": "failed_login",
    "status": "FAILED",
    "rate": {
      "threshold": 5,
      "window_seconds": 60
    }
  }
}
```

Rule ini trigger jika ada ≥5 failed login dari IP yang sama dalam 60 detik. Rate tracking menggunakan `deque` per `rule_name:ip_address`.

---

## 7. API Endpoints

Base URL: `http://157.245.145.87:8000/api`

| Method | Endpoint               | Keterangan                                                      |
| ------ | ---------------------- | --------------------------------------------------------------- |
| `GET`  | `/api/events`          | Ambil daftar event. Query params: `limit`, `severity`, `source` |
| `GET`  | `/api/stats`           | Statistik total event per severity                              |
| `POST` | `/api/rules/reload`    | Reload rule dari file JSON tanpa restart                        |
| `POST` | `/api/config/log-path` | Update path file log saat runtime                               |
| `GET`  | `/metrics`             | Prometheus metrics (text format)                                |
| `WS`   | `/ws`                  | WebSocket — event baru di-push ke klien                         |

### Contoh Request

**GET /api/events**

```
GET /api/events?limit=50&severity=CRITICAL&source=auth
```

**POST /api/config/log-path**

```json
{
  "source": "auth",
  "path": "/var/log/auth.log"
}
```

**Response LogEvent:**

```json
{
  "timestamp": "2026-05-23T14:32:01.123456",
  "source": "auth",
  "raw": "May 23 14:32:01 server sshd[2345]: Failed password for admin from 45.33.32.156 port 22",
  "ip": "45.33.32.156",
  "user": "admin",
  "action": "failed_login",
  "status": "FAILED",
  "severity": "CRITICAL",
  "rule_triggered": "ssh_brute_force",
  "extra": {}
}
```

<img width="1916" height="940" alt="image" src="https://github.com/user-attachments/assets/47b08244-3b2f-47d2-bcb0-8399c37fb7f5" />

---

## 8. Prometheus Metrics

Didefinisikan di `backend/app/metrics.py`. Tersedia di `GET /metrics`.

| Metric Name                         | Type    | Labels               | Keterangan                                    |
| ----------------------------------- | ------- | -------------------- | --------------------------------------------- |
| `siem_events_total`                 | Counter | `severity`, `source` | Total event diproses, per severity dan source |
| `siem_rules_triggered_total`        | Counter | `rule`               | Total rule yang trigger, per rule name        |
| `siem_active_websocket_connections` | Gauge   | —                    | Jumlah klien WebSocket aktif                  |

### Contoh PromQL Query

```promql
# Event rate per severity (5 menit)
sum by (severity) (rate(siem_events_total[5m]))

# Rule yang paling sering trigger
topk(5, sum by (rule) (rate(siem_rules_triggered_total[5m])))

# WebSocket connections aktif
siem_active_websocket_connections
```

---

## 9. Monitoring — Prometheus & Grafana

### Infrastruktur Monitoring

| Service       | Port | Container     | Network            |
| ------------- | ---- | ------------- | ------------------ |
| SIEM App      | 8000 | fp-siem       | fp_default         |
| Prometheus    | 9090 | prometheus    | monitoring_default |
| Grafana       | 3000 | grafana       | monitoring_default |
| Node Exporter | 9100 | node-exporter | monitoring_default |

Prometheus mengambil metrics SIEM via public IP (`157.245.145.87:8000/metrics`) karena container SIEM berada di network berbeda (`fp_default`).

### Konfigurasi Prometheus (`prometheus.yml`)

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "siem-backend"
    metrics_path: "/metrics"
    static_configs:
      - targets: ["157.245.145.87:8000"]
  - job_name: "node-exporter"
    static_configs:
      - targets: ["node-exporter:9100"]
```

### Grafana Dashboard — SIEM Metrics (`monitoring/grafana/dashboards/siem.json`)

7 panel monitoring event SIEM:

| Panel                        | Tipe       | PromQL                                                 |
| ---------------------------- | ---------- | ------------------------------------------------------ |
| Event Rate by Severity       | Timeseries | `sum by (severity) (rate(siem_events_total[1m]))`      |
| Event Rate by Source         | Timeseries | `sum by (source) (rate(siem_events_total[1m]))`        |
| Rules Triggered Rate         | Timeseries | `sum by (rule) (rate(siem_rules_triggered_total[1m]))` |
| Active WebSocket Connections | Timeseries | `siem_active_websocket_connections`                    |
| Total Events                 | Stat       | `sum(siem_events_total)`                               |
| CRITICAL Events              | Stat       | `sum(siem_events_total{severity="CRITICAL"})`          |
| WARNING Events               | Stat       | `sum(siem_events_total{severity="WARNING"})`           |

<img width="1918" height="948" alt="image" src="https://github.com/user-attachments/assets/d23df6cc-ef21-4db6-af23-ca3ab1e47b19" />


### Grafana Dashboard — System Resources (`monitoring/grafana/dashboards/system.json`)

8 panel monitoring server (via Node Exporter):

| Panel         | Tipe       | Metric                                                                        |
| ------------- | ---------- | ----------------------------------------------------------------------------- |
| System Uptime | Stat       | `node_time_seconds - node_boot_time_seconds`                                  |
| CPU Cores     | Stat       | `count(node_cpu_seconds_total{mode="idle"})`                                  |
| Total RAM     | Stat       | `node_memory_MemTotal_bytes`                                                  |
| Total Disk    | Stat       | `node_filesystem_size_bytes{mountpoint="/"}`                                  |
| CPU Usage %   | Timeseries | `100 - (avg by(instance)(rate(node_cpu_seconds_total{mode="idle"}[1m]))*100)` |
| Memory Usage  | Timeseries | `node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes`                 |
| Disk Usage %  | Timeseries | `(1 - node_filesystem_avail_bytes/node_filesystem_size_bytes)*100`            |
| Network I/O   | Timeseries | `rate(node_network_receive_bytes_total[1m])`                                  |

<img width="1919" height="940" alt="image" src="https://github.com/user-attachments/assets/af404e4b-36d2-4360-acf3-913ebb42f7f0" />

---

## 10. CI/CD Pipeline — Jenkins

Pipeline otomatis dijalankan setiap kali ada push ke GitHub (via GitHub webhook).

### Stages Pipeline

```
Checkout → Debug Workspace → Setup → Install & Test → SonarQube Analysis → Quality Gate → Build Docker Image → Deploy
```

| Stage                  | Keterangan                                                         |
| ---------------------- | ------------------------------------------------------------------ |
| **Checkout**           | Clone repository dari GitHub                                       |
| **Debug Workspace**    | List file untuk verifikasi struktur                                |
| **Setup**              | Konfigurasi git safe.directory, cek Docker                         |
| **Install & Test**     | Jalankan test di container Python 3.11-slim, generate coverage.xml |
| **SonarQube Analysis** | Upload hasil analisis ke SonarQube server                          |
| **Quality Gate**       | Tunggu keputusan Quality Gate (timeout 20 menit)                   |
| **Build Docker Image** | Build image dengan tag BUILD_NUMBER dan latest                     |
| **Deploy**             | Inject .env, down container lama, up container baru                |

### Catatan Deploy

Deploy menggunakan `docker compose up -d --build`. Sebelumnya selalu di-cleanup terlebih dahulu:

```sh
docker compose down || true
docker rm -f fp-siem || true  # Mencegah container name conflict
docker compose up -d --build
```

### Credentials Jenkins

- **`env file`** — Secret file berisi environment variables produksi (.env), di-inject saat stage Deploy

<img width="1919" height="946" alt="image" src="https://github.com/user-attachments/assets/baf9135b-63ef-406c-a409-d30daa79de8b" />

---

## 11. Kualitas Kode — SonarQube

### Konfigurasi (`sonar-project.properties`)

```properties
sonar.projectKey=siem-dashboard
sonar.projectName=SIEM Dashboard

sonar.sources=backend/app
sonar.tests=backend/tests
sonar.python.version=3.11
sonar.python.coverage.reportPaths=coverage.xml
```

### Quality Gate Requirements

- New code coverage ≥ **80%**
- New issues = **0**

### Coverage Exclusions

File berikut dikecualikan dari perhitungan coverage (sulit/tidak mungkin di-unit-test):

| File                                | Alasan Dikecualikan                          |
| ----------------------------------- | -------------------------------------------- |
| `backend/app/main.py`               | Entrypoint aplikasi, butuh integrasi penuh   |
| `backend/app/db/database.py`        | Butuh koneksi MySQL nyata                    |
| `backend/app/core/log_collector.py` | Async file I/O, infinite loop                |
| `backend/app/core/log_generator.py` | Tidak di-analyze (dikecualikan dari sources) |
| `backend/app/api/websocket.py`      | Butuh WebSocket client nyata                 |
| `backend/app/api/routes.py`         | Butuh full FastAPI integration               |

### Issue Suppressions

Beberapa rule SonarQube yang menghasilkan false positive pada kode ini:

| Rule                           | File               | Alasan                                               |
| ------------------------------ | ------------------ | ---------------------------------------------------- |
| `python:S7484` (sleep in loop) | `log_collector.py` | File polling genuinely memerlukan sleep              |
| `python:S2245` (weak crypto)   | `log_generator.py` | `random` dipakai untuk data simulasi, bukan keamanan |
| `python:S1313` (hardcoded IP)  | `log_generator.py` | IP adalah data demo intentional                      |
| `python:S1313` (hardcoded IP)  | `log_parser.py`    | IP dalam komentar/pattern sampel                     |

---

### File Test

| File                      | Yang Ditest                                                            |
| -----------------------   | ---------------------------------------------------------------------- |
| `test_log_event.py`       | `LogEvent` dataclass, `to_dict()`                                      |
| `test_log_generator.py`   | Semua generator (\_random_auth, \_access, \_firewall, \_syslog, \_fim) |
| `test_log_parser.py`      | Parser untuk setiap log format                                         |
| `test_rule_engine.py`     | Evaluasi rule, rate detection, kondisi time_range, path_match          |
| `test_metrics.py`         | Prometheus Counter dan Gauge                                           |
| `test_discord_webhook.py` | Discord alert                                                          |

### Coverage Target

SonarQube Quality Gate mewajibkan **coverage ≥ 80%** pada new code. File infrastruktur (database, websocket, main, routes) dikecualikan dari coverage via `sonar.coverage.exclusions`.

<img width="1919" height="885" alt="image" src="https://github.com/user-attachments/assets/c2f00c01-4c4e-4dfb-9913-0ee703113d60" />


---
