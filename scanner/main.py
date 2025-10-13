# scanner/main.py
import signal
import sys

from pathlib import Path
from datetime import datetime, timezone
from .cli import build_parser
from .utils import parse_ports, expand_targets
from .net import run_scan
from .report import export_csv, export_json, export_pdf

# package metadata
__tool_name__ = "PyPortScanner"
__tagline__ = "TCP connect scanner · banner grabber · reporter"
__version__ = "0.1.0"
__author__ = "Wasef Hussain"


def handle_sigint(sig, frame):
    print("\n[!] Scan interrupted by user. Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

def _print_header(targets, ports, workers, timeout, output_prefix, verbose):
  
    tstamp = datetime.now(timezone.utc).astimezone().isoformat()
   
    logo_lines = [
        "╔════════════════════════════════════════════════════════════════════╗",
        f"  Wasef Hussain — PyPortScanner",
        "  Scans | Banner Grab | Service Detection | CSV/JSON/PDF Report",
        "╚════════════════════════════════════════════════════════════════════╝",
    ]
    for ln in logo_lines:
        print(ln)
    print(f"Tool:  {__tool_name__}    Version: {__version__}")
    print(f"Author: {__author__}    Contact: hussainwasef18@gmail.com")
    print(f"Run date: {tstamp}")
    print("-" * 72)
   
    print(f"Targets: {len(targets)}   Ports: {len(ports)}   Workers: {workers}   Timeout: {timeout}s")
    print(f"Output prefix: {output_prefix}   Verbose: {'on' if verbose else 'off'}")
    print("-" * 72)

def _print_footer(results_sorted, out_prefix):
    
    total_open = len(results_sorted)
    ips = sorted({r["ip"] for r in results_sorted})
    print()
    print("=" * 72)
    print(f"Scan complete — Open ports found: {total_open}")
    if total_open:
        print("Hosts with open ports:", ", ".join(ips))
    else:
        print("No open ports found (or reachable).")
    csv_file = str(out_prefix.with_suffix(".csv"))
    json_file = str(out_prefix.with_suffix(".json"))
    pdf_file = str(out_prefix.with_suffix(".pdf"))
    print()
    print("Reports:")
    print(f"  CSV : {csv_file}")
    print(f"  JSON: {json_file}")
    print(f"  PDF : {pdf_file} (may be skipped if reportlab missing)")
    print("=" * 72)

def main(argv=None):
    parser = build_parser()
    parser.add_argument("--version", action="version", version=f"{__tool_name__} {__version__}")
    args = parser.parse_args(argv)

    ports = parse_ports(args.ports)
    targets = expand_targets(args.target)

    _print_header(targets, ports, args.workers, args.timeout, args.output, args.verbose)

    try:
        results = run_scan(targets, ports, args.workers, args.timeout, args.verbose)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error during scan: {e}")

        results = []

    results_sorted = sorted(results, key=lambda r: (r["ip"], r["port"]))
    out_prefix = Path(args.output)
    csv_path = out_prefix.with_suffix(".csv")
    json_path = out_prefix.with_suffix(".json")
    pdf_path = out_prefix.with_suffix(".pdf")

    if results_sorted:
        export_csv(results_sorted, str(csv_path))
        export_json(results_sorted, str(json_path))
        export_pdf(results_sorted, str(pdf_path))
    _print_footer(results_sorted, out_prefix)

if __name__ == "__main__":
    main()
