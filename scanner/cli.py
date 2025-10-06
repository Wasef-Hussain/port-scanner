# scanner/cli.py
import argparse
from .ports import DEFAULT_TIMEOUT, DEFAULT_WORKERS

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Debug-friendly TCP connect scanner + banner grabber")
    p.add_argument("-t", "--target", required=True, help="Target IP/host, CIDR, or range (192.168.1.1-50)")
    p.add_argument("-p", "--ports", default="1-1024", help="Ports (e.g. 22,80,443 or 1-1024)")
    p.add_argument("-o", "--output", default="scan_report", help="Output filename prefix")
    p.add_argument("-T", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout")
    p.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help="Thread pool size")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    return p
