# scanner/ports.py
import re

DEFAULT_TIMEOUT = 3.0
DEFAULT_WORKERS = 100
MAX_BANNER_BYTES = 2048

# Note: HTTPS ports need an SSL/TLS handshake to retrieve certs (see grab_tls_cert()).
PORT_PROBES = {
    20: b"",  # ftp-data (no banner)
    21: b"USER anonymous\r\n",
    22: b"\r\n",
    23: b"\r\n",
    25: b"EHLO example.com\r\n",
    53: b"\x00",  # simple DNS TCP probe (rare)
    80: b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n",
    110: b"USER test\r\n",
    143: b"01 CAPABILITY\r\n",
    # LDAP: avoid complex BER unless you parse results — keep empty to only connect
    389: b"",
    443: b"",  # TLS - use SSL handshake instead of raw HEAD
    445: b"\x00",
    465: b"EHLO example.com\r\n",
    587: b"EHLO example.com\r\n",
    993: b"",  # IMAPS - TLS handshake
    995: b"USER test\r\n",
    135: b"",  # msrpc - usually silent until protocol speak
    139: b"",  # netbios - often silent
    1433: b"\x12\x01\x00\x25\x00\x00\x00\x00",
    1521: b"",  # Oracle - skip aggressive probe
    3306: b"\x00",
    3389: b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00",
    5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
    5900: b"",  # VNC often sends "RFB" banner on connect
    6379: b"PING\r\n",
    7001: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n",
    8443: b"",  # TLS - use SSL handshake
    9200: b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
    11211: b"version\r\n",
    27017: b"",  # MongoDB - avoid naive probe
    2375: b"",  # docker API (insecure) - be cautious
    2376: b"",  # docker TLS - use TLS handshake
    5672: b"",  # AMQP (RabbitMQ) - protocol handshake needed for detail
    15672: b"GET / HTTP/1.0\r\n\r\n",  # RabbitMQ management
    5000: b"GET / HTTP/1.0\r\n\r\n",
    9000: b"GET / HTTP/1.0\r\n\r\n",
    1099: b"",  # RMI registry often silent until java client
}


COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 135: "msrpc", 139: "netbios-ssn",
    389: "ldap", 443: "https", 445: "microsoft-ds", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    11211: "memcached", 27017: "mongodb", 8080: "http-proxy", 8443: "https-alt",
    15672: "rabbitmq-management", 5672: "amqp", 2375: "docker", 2376: "docker-tls",
    9200: "elasticsearch", 1099: "rmi", 5000: "http-dev", 9000: "http-alt"
}


# Fingerprint regexes & binary signature checks (textual first)
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
    # Binary sign / substring checks are handled in net.py (e.g. SMB signatures)
]
