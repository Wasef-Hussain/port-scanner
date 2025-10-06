# scanner/net.py
import socket, threading, re
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

from .ports import PORT_PROBES, COMMON_PORTS, FINGERPRINTS, DEFAULT_TIMEOUT, MAX_BANNER_BYTES

def _recv_banner(sock: socket.socket, timeout: float = DEFAULT_TIMEOUT, max_bytes: int = MAX_BANNER_BYTES) -> str:
    try:
        sock.settimeout(timeout)
        data = sock.recv(max_bytes)
        return data.decode(errors="replace").strip() if data else ""
    except Exception:
        return ""

def scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT, verbose: bool = False) -> Optional[Dict]:
    result = {
        "ip": ip, "port": port, "open": False, "service": None,
        "banner": "", "timestamp": datetime.now(timezone.utc).isoformat()
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) != 0:
            sock.close()
            return None
        result["open"] = True

        # read initial banner
        banner = _recv_banner(sock, timeout * 0.6)

        if not banner and port in PORT_PROBES:
            try:
                sock.sendall(PORT_PROBES[port])
                banner = _recv_banner(sock, timeout * 0.8)
            except Exception:
                pass
        result["banner"] = banner or ""
        b_text = result["banner"].strip()

        # fingerprint match
        identified = False
        for pat, product in FINGERPRINTS:
            m = pat.search(b_text)
            if m:
                result["service"] = product
                if m.groups():
                    result["version"] = m.group(1)
                identified = True
                break

        if not identified and b_text:
            low = b_text.lower()
            if "ssh" in low: result["service"] = "ssh"
            elif "http" in low: result["service"] = "http"
            elif "smtp" in low: result["service"] = "smtp"
            elif "ftp" in low: result["service"] = "ftp"
            elif "mysql" in low: result["service"] = "mysql"
            else: result["service"] = COMMON_PORTS.get(port, "unknown")
        elif not identified:
            result["service"] = COMMON_PORTS.get(port, "unknown")

        sock.close()
        if verbose:
            print(f"[OPEN] {ip}:{port} {result['service']} banner='{result['banner'][:80]}'")
        return result
    except Exception as e:
        if verbose: print(f"[ERROR] {ip}:{port} -> {e}")
        return None

def run_scan(targets: List[str], ports: List[int], workers: int, timeout: float, verbose: bool) -> List[Dict]:
    results: List[Dict] = []
    lock = threading.Lock()
    total, done = len(targets) * len(ports), 0

    def task(ip, port):
        nonlocal done
        res = scan_port(ip, port, timeout=timeout, verbose=verbose)
        with lock:
            done += 1
            if not verbose: print(f"\rScanned {done}/{total}", end="", flush=True)
        return res

    with ThreadPoolExecutor(max_workers=workers) as exe:
        futures = [exe.submit(task, ip, p) for ip in targets for p in ports]
        for f in as_completed(futures):
            r = f.result()
            if r: results.append(r)

    if not verbose: print()
    return results
