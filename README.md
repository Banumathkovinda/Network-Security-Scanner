# 🔍 Network Security Scanner

A lightweight, browser-based **Network Security Scanner** built with Python and Flask. Perform real-time port scanning, host discovery, service fingerprinting, and vulnerability checks — all from a clean web UI.

---

## 🚀 Features

- **Network Discovery** — Ping sweep a CIDR range to find live hosts
- **Port Scanner** — Scan custom or preset port ranges via TCP connection probing
- **Quick Scan** — Instantly check the 17 most common ports
- **Service Fingerprinting** — Detect service names and versions (HTTP, SSH, FTP, MySQL, SMTP, etc.)
- **Vulnerability Check** — Flag insecure services (Telnet, plain FTP, unencrypted SSH)
- **Confidence Scoring** — Each open port comes with a verification confidence score (0–100%)
- **No dependencies on nmap** — Pure Python socket-based scanning, no external tools required

---

## 🖥️ Tech Stack

| Layer     | Technology              |
|-----------|-------------------------|
| Backend   | Python 3, Flask         |
| Frontend  | HTML, CSS, JavaScript   |
| Scanning  | Python `socket` module  |
| UI Style  | Vanilla CSS (dark theme)|

---

## ⚡ Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/Banumathkovinda/Network-Security-Scanner.git
cd Network-Security-Scanner
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the app
```bash
python simple_scanner.py
```

### 4. Open in browser
```
http://127.0.0.1:8080
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan/network` | Discover live hosts in a network range |
| `POST` | `/api/scan/host` | Full port scan on a specific host |
| `POST` | `/api/scan/quick` | Quick scan of common ports |
| `POST` | `/api/vulnerability/check` | Analyze open ports for vulnerabilities |
| `GET` | `/api/nmap/status` | Check if Nmap is installed |
| `POST` | `/api/scan/nmap` | Port scan using Nmap (-sV) |
| `POST` | `/api/cve/lookup` | CVE search by product + version (NIST NVD) |
| `POST` | `/api/cve/lookup-scan` | CVE lookup from port scan results |
| `GET/POST/DELETE` | `/api/schedules` | Scheduled scans + email alerts |

---

## Advanced features

### Nmap integration
Install [Nmap](https://nmap.org/download.html) and ensure `nmap` is on your PATH. Use **Nmap Scan** in the UI or pass `"use_nmap": true` in scan API requests.

### CVE lookup
Uses the [NIST NVD API 2.0](https://nvd.nist.gov/developers). Optional: set `NVD_API_KEY` in `.env` for higher rate limits.

### Scheduled scans + email
1. Copy `.env.example` to `.env`
2. Set `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `ALERT_EMAIL_TO`
3. Add schedules in the UI (**Advanced → Scheduled scans**)

### Scan history & compare
Scans save automatically under **History**. **Compare** shows added/removed/changed ports or hosts between two runs.

### Network map
Run **Network discovery**, then open the **Network map** tab for a visual graph of live hosts.

### Docker
```bash
cp .env.example .env   # optional
docker compose up --build
```
Open http://localhost:8080

### Login / API key (public deploy)
Set in `.env`:
- `SCANNER_PASSWORD` — web login
- `SCANNER_API_KEY` — login or `X-API-Key` header on API calls
- `SECRET_KEY` — session signing (use a long random string)

If neither password nor API key is set, the app runs in open **local mode**.

---

## 🛡️ Example Use Cases

- Audit your **home or lab network** for open/exposed services
- Check which ports are open on a **local server** before deployment
- Learn how **TCP port scanning** and **service fingerprinting** work under the hood
- Understand common **network vulnerabilities** like exposed Telnet or FTP

---

## ⚠️ Disclaimer

> This tool is intended for **educational purposes** and authorized network auditing only.  
> Do **not** use it to scan networks or systems you do not own or have explicit permission to test.  
> The author is not responsible for any misuse.

---

## 📁 Project Structure

```
network-security-scanner/
├── simple_scanner.py     # Flask web server & API routes
├── scanner_lib.py        # Core scanning & fingerprinting logic
├── nmap_scanner.py       # Optional Nmap integration
├── cve_lookup.py         # NVD CVE lookup
├── scheduler_service.py  # Scheduled scans + SMTP alerts
├── index.html            # Frontend UI
├── requirements.txt      # Python dependencies
├── .env.example          # SMTP / NVD config template
└── README.md
```

---

## 👩‍💻 Author

**Banumathkovinda**  
[GitHub](https://github.com/Banumathkovinda) · [LinkedIn](https://www.linkedin.com/in/banumathkovinda)
