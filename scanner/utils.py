# scanner/utils.py
import ipaddress
from typing import List

def parse_ports(ports_str: str) -> List[int]:
    out = set()
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return sorted(p for p in out if 1 <= p <= 65535)

def expand_targets(target: str) -> List[str]:
    target = target.strip()
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    if "-" in target and target.count(".") == 3:
        base, rng = target.rsplit(".", 1)
        if "-" in rng:
            a, b = rng.split("-", 1)
            return [f"{base}.{i}" for i in range(int(a), int(b) + 1)]
    return [target]
