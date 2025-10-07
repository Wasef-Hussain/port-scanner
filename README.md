# ⚡ Port Scanner & Banner Grabber

A fast multi-threaded Python tool that:
- Scans given hosts or IP ranges for **open TCP ports**
- Detects **running services**
- Performs **banner grabbing** for version identification
- Exports reports to **CSV**, **JSON**, and **PDF**

### 🔧 Usage
```bash
python -m scanner.main -t 192.168.31.128 -p 1-1000 -T 3.0 -w 100 -v -o report_name


✨ Example Output
[OPEN] 192.168.31.128:22  OpenSSH banner='SSH-2.0-OpenSSH_10.0p2 Debian-8'
[OPEN] 192.168.31.128:80  Apache/2.4.65 (Debian)


📦 Output

Generates:

    report_name.csv

    report_name.json

    report_name.pdf


Made by Wasef Hussain 🛠️
Port scanner for network and security analysis.
