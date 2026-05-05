"""
Target parsing — converts user input into a list of IPs to scan.

Supports:
- Single IP:        192.168.1.1
- Hostname:         example.com
- CIDR:             192.168.1.0/24
- IP range:         192.168.1.1-192.168.1.50  or  192.168.1.1-50
- Comma-separated:  192.168.1.1, 192.168.1.5, 10.0.0.0/30

We resolve hostnames eagerly so the user gets immediate feedback on bad input.
"""

import ipaddress
import socket
from typing import List, Iterator


class TargetParseError(ValueError):
    """Raised when target input cannot be parsed."""
    pass


def parse_targets(target_string: str) -> List[str]:
    """
    Parse a user-supplied target string into a deduplicated list of IPs.

    Raises TargetParseError on any unparseable token — fail loud, don't silently
    drop bad input. Half-working scans are worse than no scan.
    """
    if not target_string or not target_string.strip():
        raise TargetParseError("Empty target string.")

    tokens = [t.strip() for t in target_string.split(",") if t.strip()]
    ips: List[str] = []
    seen = set()

    for token in tokens:
        for ip in _expand_token(token):
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)

    if not ips:
        raise TargetParseError(f"No valid targets found in: {target_string!r}")

    return ips


def _expand_token(token: str) -> Iterator[str]:
    """Expand a single token to one or more IPs."""
    # CIDR
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError as e:
            raise TargetParseError(f"Invalid CIDR {token!r}: {e}") from e
        # Cap at /16 to prevent accidental "scan the entire internet" mishaps.
        if net.num_addresses > 65536:
            raise TargetParseError(
                f"CIDR {token} expands to {net.num_addresses} hosts. "
                "Refusing for safety — use a smaller range."
            )
        for ip in net.hosts() if net.num_addresses > 2 else net:
            yield str(ip)
        return

    # IP range: 192.168.1.1-192.168.1.50 OR 192.168.1.1-50
    if "-" in token and not _looks_like_ipv6(token):
        yield from _expand_range(token)
        return

    # Single IP or hostname
    yield from _resolve_single(token)


def _looks_like_ipv6(token: str) -> bool:
    """Cheap check — IPv6 contains colons, hyphens are valid for ranges of v4."""
    return ":" in token


def _expand_range(token: str) -> Iterator[str]:
    """Expand 'a.b.c.d-e.f.g.h' or 'a.b.c.d-N' notation."""
    left, right = token.split("-", 1)
    left = left.strip()
    right = right.strip()

    try:
        start_ip = ipaddress.IPv4Address(left)
    except ValueError as e:
        raise TargetParseError(f"Invalid range start {left!r}: {e}") from e

    # Right side: full IP or just last octet?
    if "." in right:
        try:
            end_ip = ipaddress.IPv4Address(right)
        except ValueError as e:
            raise TargetParseError(f"Invalid range end {right!r}: {e}") from e
    else:
        try:
            last_octet = int(right)
            if not 0 <= last_octet <= 255:
                raise ValueError("octet out of range")
            base = str(start_ip).rsplit(".", 1)[0]
            end_ip = ipaddress.IPv4Address(f"{base}.{last_octet}")
        except ValueError as e:
            raise TargetParseError(f"Invalid range end {right!r}: {e}") from e

    if int(end_ip) < int(start_ip):
        raise TargetParseError(f"Range end before start: {token}")

    span = int(end_ip) - int(start_ip) + 1
    if span > 65536:
        raise TargetParseError(f"Range too large ({span} hosts). Use a smaller one.")

    for i in range(int(start_ip), int(end_ip) + 1):
        yield str(ipaddress.IPv4Address(i))


def _resolve_single(token: str) -> Iterator[str]:
    """Resolve a single IP or hostname."""
    # Try as IP first (cheap, no network call)
    try:
        ipaddress.ip_address(token)
        yield token
        return
    except ValueError:
        pass

    # Treat as hostname
    try:
        addrs = socket.getaddrinfo(token, None, socket.AF_INET)
    except socket.gaierror as e:
        raise TargetParseError(f"Cannot resolve hostname {token!r}: {e}") from e

    seen = set()
    for entry in addrs:
        ip = entry[4][0]
        if ip not in seen:
            seen.add(ip)
            yield ip


def parse_ports(port_string: str) -> List[int]:
    """
    Parse a port specification into a sorted, deduplicated list.

    Supports: '80', '1-1024', '22,80,443', '1-100,8080,9000-9010'
    """
    if not port_string or not port_string.strip():
        raise TargetParseError("Empty port specification.")

    ports = set()
    tokens = [t.strip() for t in port_string.split(",") if t.strip()]

    for token in tokens:
        if "-" in token:
            try:
                lo_s, hi_s = token.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
            except ValueError as e:
                raise TargetParseError(f"Invalid port range {token!r}: {e}") from e
            if not (1 <= lo <= 65535) or not (1 <= hi <= 65535):
                raise TargetParseError(f"Port out of range in {token!r} (must be 1-65535)")
            if lo > hi:
                raise TargetParseError(f"Range start > end in {token!r}")
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(token)
            except ValueError as e:
                raise TargetParseError(f"Invalid port {token!r}: {e}") from e
            if not 1 <= p <= 65535:
                raise TargetParseError(f"Port out of range: {p} (must be 1-65535)")
            ports.add(p)

    return sorted(ports)


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private/reserved space — used for the external-target warning."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False
