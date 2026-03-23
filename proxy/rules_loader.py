import ipaddress
from pathlib import Path

import yaml


def load_domain_whitelist(path: Path) -> set[str]:
    lines = path.read_text().splitlines()
    return {
        s.lower()
        for line in lines
        if (s := line.strip()) and not s.startswith("#")
    }


def load_c2_blocklist(path: Path) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    lines = path.read_text().splitlines()
    networks = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return networks


def load_rules(path: Path) -> dict:
    return yaml.safe_load(path.read_text())
