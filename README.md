# SIEMalaman

| Nama | NRP |
|---- |--- |
|Reza Afzaal Faizullah Taqy|5025241051|
|Uwais Achmad|5025241103|
|Mayandra Suhaira Frisiandi|5025241240|

## Deskripsi Singkat

SIEMalaman merupakan sistem SIEM (Security Information and Event Management) sederhana yang bertujuan untuk mengumpulkan, memproses, dan memonitor log sistem secara real-time. Sistem ini juga dilengkapi dengan fitur alerting dan dashboard monitoring untuk membantu analisis keamanan dan aktivitas sistem.

## Arsitektur Sistem

Sistem dibangun menggunakan pendekatan berbasis container menggunakan Docker dengan beberapa komponen utama:
- Backend SIEM (FastAPI)
- Frontend dashboard (web UI custom)
- Prometheus (metrics collector)
- Node Exporter (system metrics)
- Grafana (visualisasi & alerting)

Alur Data:
1. Log dikumpulkan oleh log collector
2. Log diparse oleh log parser
3. Rule engine mengevaluasi event
4. Event disimpan ke database
5. Event dikirim ke frontend via WebSocket (real-time)
6. Metrics diekspos ke Prometheus
7. Grafana membaca metrics dari Prometheus
8. Alert dikirim jika threshold tercapai

## Fitur Utama

### 1. Pengumpulan log
Sistem mengumpulkan log dari file seperti `access.log` dan `auth.log`. Proses dilakukan oleh modul `log_collector.py`

### 2. Log Parsing
Log diproses untuk mengekstrak informasi penting menggunakan modul `log_parser.py` seperti:
- User
- Ip
- Action
- Status
- Severity
- Timestamp

### 3. Rule Engine
Sistem memiliki rule engine berbasis JSON `default_rules.json` dengan modul `rule_engine.py` untuk mendeteksi kondisi tertentu seperti:
- SSH brute force 
- HTTP ERROR
- Failed Login

### 4. Dashboard Monitoring

A. Custom SIEM Dashboard
- Backend menggunakan WebSocket `websocket.py` untuk live log streaming dan update dashboard tanpa refresh.
- Frontend menggunakan HTML/JS untuk menampilkan total event serta chart Severity Distribution dan Events over Time

<img width="1916" height="940" alt="image" src="https://github.com/user-attachments/assets/47b08244-3b2f-47d2-bcb0-8399c37fb7f5" />

B. Grafana Dashboard
Menampilkan data dari Prometheus + Node exporter

<img width="1919" height="944" alt="image" src="https://github.com/user-attachments/assets/b1fde765-142e-47cf-bd75-f6a363508cde" />

### 5. Containerization
Semua service dijalankan menggunakan docker

### 6. CI/CD
Pipeline CI/CD dengan file `JenkinsFile` digunakan untuk:
- Build project
- Run tests
- Deployment Otomatis

<img width="1868" height="919" alt="image" src="https://github.com/user-attachments/assets/b86a695a-063a-4148-b335-818335e2afeb" />

### 7. Quality Check 
Project dianalisis menggunakan SonarQube dengan file `sonar-project.properties` untuk bug detection, code smell, dan maintainability

<img width="1892" height="868" alt="image" src="https://github.com/user-attachments/assets/16db275f-f9e7-48cd-9c33-c3fe66a09dc3" />


### 8. Deployment
Project di deploy menggunakan docker compose sesuai pipeline pada JenkinsFile






