# scanner/ports.py
import re

DEFAULT_TIMEOUT = 3.0
DEFAULT_WORKERS = 100
MAX_BANNER_BYTES = 2048

PORT_PROBES = {
    80: b"HEAD / HTTP/1.0\r\nHost: example\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\nHost: example\r\n\r\n",
    21: b"QUIT\r\n",
    22: b"\r\n",
    25: b"EHLO example.com\r\n",
    110: b"USER test\r\n",
    143: b"\r\n",
    3306: b"\x00",
    445: b"\x00",
    5900: b"",
    6379: b"PING\r\n",
    11211: b"version\r\n",
}

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 3306: "mysql", 3389: "rdp", 5900: "vnc"
}

FINGERPRINTS = [
    (re.compile(r"^SSH-([\d\.]+)"), "OpenSSH"),
    (re.compile(r"^220.*VMware Authentication Daemon", re.I), "VMware Auth"),
    (re.compile(r"^RFB\s+(\d+\.\d+)", re.I), "VNC/RFB"),
    (re.compile(r"^HTTP/1\.[01]\s+(\d+)", re.I), "HTTP"),
    (re.compile(r"nginx/?\s*([\d\.]+)?", re.I), "nginx"),
    (re.compile(r"Apache/?\s*([\d\.]+)?", re.I), "Apache"),
    (re.compile(r"^\+PONG", re.I), "Redis"),
    (re.compile(r"^VERSION\s+([\S]+)", re.I), "Memcached"),
    (re.compile(r"mysql", re.I), "MySQL"),
    (re.compile(r"^220.*FTP", re.I), "FTP"),
    (re.compile(r"^220.*SMTP", re.I), "SMTP"),
]
