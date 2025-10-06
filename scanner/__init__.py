"""
scanner package - TCP port scanner and banner grabber

Expose a small, useful public API:
  - parse_ports, expand_targets (input helpers)
  - run_scan, scan_port (core functions)
  - export helpers are available from scanner.report
"""

__version__ = "0.1.0"

# Lightweight re-exports for convenience
from .utils import parse_ports, expand_targets   # convenience helpers
from .net import run_scan, scan_port            # core scanner functions

__all__ = ["parse_ports", "expand_targets", "run_scan", "scan_port", "__version__"]
