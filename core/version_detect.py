"""
Service version detection — extracts product/version info from banners.

Approach: regex patterns inspired by nmap-service-probes. Each pattern has:
  - A regex to match the banner
  - The product name
  - A function to extract the version string from match groups

This is intentionally conservative: we only emit a version when we're
confident from the pattern. False positives are worse than no detection,
because they cause analysts to chase the wrong CVEs.

Adding patterns: append to PATTERNS list. Order matters — first match wins.
More specific patterns should come before generic ones.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Pattern, Callable


@dataclass(frozen=True)
class VersionInfo:
    """Result of version detection on a banner."""
    product: str = ""           # e.g. "OpenSSH", "Apache httpd", "nginx"
    version: str = ""           # e.g. "8.2p1", "2.4.41", "1.18.0"
    extra: str = ""             # e.g. "Ubuntu", "FreeBSD"
    confidence: str = "high"    # "high" | "medium" | "low"

    @property
    def is_known(self) -> bool:
        return bool(self.product)

    def to_string(self) -> str:
        """Format as: 'Product Version (extra)' — empty if unknown."""
        if not self.product:
            return ""
        parts = [self.product]
        if self.version:
            parts.append(self.version)
        s = " ".join(parts)
        if self.extra:
            s += f" ({self.extra})"
        return s

    def to_dict(self) -> dict:
        return {
            "product": self.product,
            "version": self.version,
            "extra": self.extra,
            "confidence": self.confidence,
        }


# Type alias for clarity
_PatternEntry = tuple[Pattern[str], Callable[[re.Match[str]], VersionInfo]]


def _compile_patterns() -> list[_PatternEntry]:
    """Build the pattern list. Each entry: (regex, extractor)."""
    P: list[_PatternEntry] = []

    # ---- SSH ---- #
    # SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
    P.append((
        re.compile(r"^SSH-(?P<proto>\d+\.\d+)-OpenSSH[_-](?P<ver>[\w.\-]+)(?:\s+(?P<extra>.+?))?\s*$",
                   re.MULTILINE),
        lambda m: VersionInfo(
            product="OpenSSH",
            version=m.group("ver"),
            extra=(m.group("extra") or "").strip(),
        ),
    ))
    # Generic SSH-x.y-Product
    P.append((
        re.compile(r"^SSH-(?P<proto>\d+\.\d+)-(?P<prod>[\w.\-]+)(?:\s+(?P<extra>.+?))?\s*$",
                   re.MULTILINE),
        lambda m: VersionInfo(
            product=f"SSH ({m.group('prod')})",
            version="",
            extra=f"protocol {m.group('proto')}",
            confidence="medium",
        ),
    ))

    # ---- HTTP — Server header ---- #
    # Server: nginx/1.18.0 (Ubuntu)
    P.append((
        re.compile(r"Server:\s*nginx/(?P<ver>[\w.]+)(?:\s*\((?P<extra>[^)]+)\))?", re.IGNORECASE),
        lambda m: VersionInfo(product="nginx", version=m.group("ver"),
                              extra=(m.group("extra") or "")),
    ))
    # Server: Apache/2.4.41 (Ubuntu)
    P.append((
        re.compile(r"Server:\s*Apache/(?P<ver>[\w.]+)(?:\s*\((?P<extra>[^)]+)\))?", re.IGNORECASE),
        lambda m: VersionInfo(product="Apache httpd", version=m.group("ver"),
                              extra=(m.group("extra") or "")),
    ))
    # Server: Microsoft-IIS/10.0
    P.append((
        re.compile(r"Server:\s*Microsoft-IIS/(?P<ver>[\w.]+)", re.IGNORECASE),
        lambda m: VersionInfo(product="Microsoft IIS", version=m.group("ver")),
    ))
    # Server: lighttpd/1.4.55
    P.append((
        re.compile(r"Server:\s*lighttpd/(?P<ver>[\w.]+)", re.IGNORECASE),
        lambda m: VersionInfo(product="lighttpd", version=m.group("ver")),
    ))
    # Server: Caddy
    P.append((
        re.compile(r"Server:\s*Caddy(?:/(?P<ver>[\w.]+))?", re.IGNORECASE),
        lambda m: VersionInfo(product="Caddy", version=m.group("ver") or ""),
    ))
    # Server: gunicorn/20.0.4
    P.append((
        re.compile(r"Server:\s*gunicorn/(?P<ver>[\w.]+)", re.IGNORECASE),
        lambda m: VersionInfo(product="gunicorn", version=m.group("ver")),
    ))
    # X-Powered-By: PHP/7.4.3
    P.append((
        re.compile(r"X-Powered-By:\s*PHP/(?P<ver>[\w.]+)", re.IGNORECASE),
        lambda m: VersionInfo(product="PHP", version=m.group("ver"),
                              extra="server-side", confidence="medium"),
    ))
    # Generic Server: Foo/X.Y
    P.append((
        re.compile(r"Server:\s*(?P<prod>[\w\-]+)/(?P<ver>[\w.]+)", re.IGNORECASE),
        lambda m: VersionInfo(product=m.group("prod"), version=m.group("ver"),
                              confidence="medium"),
    ))

    # ---- FTP ---- #
    # 220 ProFTPD 1.3.5e Server
    P.append((
        re.compile(r"^220.*ProFTPD\s+(?P<ver>[\w.\-]+)", re.IGNORECASE | re.MULTILINE),
        lambda m: VersionInfo(product="ProFTPD", version=m.group("ver")),
    ))
    # 220 (vsFTPd 3.0.3)
    P.append((
        re.compile(r"^220.*vsFTPd\s+(?P<ver>[\w.\-]+)", re.IGNORECASE | re.MULTILINE),
        lambda m: VersionInfo(product="vsftpd", version=m.group("ver")),
    ))
    # 220 Microsoft FTP Service
    P.append((
        re.compile(r"^220.*Microsoft\s+FTP\s+Service", re.IGNORECASE | re.MULTILINE),
        lambda m: VersionInfo(product="Microsoft FTP", version=""),
    ))
    # 220 Pure-FTPd
    P.append((
        re.compile(r"^220.*Pure-FTPd(?:\s+v?(?P<ver>[\w.\-]+))?", re.IGNORECASE | re.MULTILINE),
        lambda m: VersionInfo(product="Pure-FTPd", version=m.group("ver") or ""),
    ))

    # ---- SMTP ---- #
    # 220 mail.example.com ESMTP Postfix (Ubuntu)
    P.append((
        re.compile(r"^220[\s\-].*Postfix(?:\s+\((?P<extra>[^)]+)\))?", re.IGNORECASE | re.MULTILINE),
        lambda m: VersionInfo(product="Postfix smtpd",
                              version="",
                              extra=(m.group("extra") or "")),
    ))
    # 220 mail ESMTP Sendmail 8.15.2
    P.append((
        re.compile(r"^220.*Sendmail\s+(?P<ver>[\d.]+)", re.IGNORECASE | re.MULTILINE),
        lambda m: VersionInfo(product="Sendmail", version=m.group("ver")),
    ))
    # 220 Microsoft ESMTP MAIL Service ready at ...
    P.append((
        re.compile(r"^220.*Microsoft\s+ESMTP", re.IGNORECASE | re.MULTILINE),
        lambda m: VersionInfo(product="Microsoft Exchange/IIS SMTP", version=""),
    ))
    # 220 example.com ESMTP Exim 4.93
    P.append((
        re.compile(r"^220.*Exim\s+(?P<ver>[\d.]+)", re.IGNORECASE | re.MULTILINE),
        lambda m: VersionInfo(product="Exim smtpd", version=m.group("ver")),
    ))

    # ---- POP3 / IMAP ---- #
    # +OK Dovecot ready
    P.append((
        re.compile(r"^\+OK\s+Dovecot(?:\s+\(\S+\))?\s+ready", re.IGNORECASE | re.MULTILINE),
        lambda m: VersionInfo(product="Dovecot pop3d/imapd", version=""),
    ))
    # * OK [CAPABILITY ...] Courier-IMAP ready
    P.append((
        re.compile(r"\*\s*OK.*Courier-IMAP", re.IGNORECASE),
        lambda m: VersionInfo(product="Courier IMAP", version=""),
    ))

    # ---- Database ---- #
    # MySQL handshake — first byte is length, then protocol version (10), then version string \0
    # We can't easily regex binary, so we look for typical MySQL banner content.
    P.append((
        re.compile(r"(?P<ver>\d+\.\d+\.\d+(?:[-\w]+)?)[\x00-\x1f]+\w+_native_password", re.DOTALL),
        lambda m: VersionInfo(product="MySQL/MariaDB", version=m.group("ver")),
    ))
    # MariaDB explicit
    P.append((
        re.compile(r"(?P<ver>\d+\.\d+\.\d+)-MariaDB"),
        lambda m: VersionInfo(product="MariaDB", version=m.group("ver")),
    ))
    # PostgreSQL — typically wants real protocol; banner usually empty.
    # Redis — INFO reply contains "redis_version:6.0.16"
    P.append((
        re.compile(r"redis_version:(?P<ver>[\w.]+)", re.IGNORECASE),
        lambda m: VersionInfo(product="Redis", version=m.group("ver")),
    ))
    # Memcached — reply to "version\r\n" is "VERSION 1.6.9\r\n"
    P.append((
        re.compile(r"^VERSION\s+(?P<ver>[\w.]+)", re.MULTILINE),
        lambda m: VersionInfo(product="Memcached", version=m.group("ver")),
    ))
    # MongoDB — usually requires protocol; ismaster reply has "version"
    P.append((
        re.compile(r'"version"\s*:\s*"(?P<ver>[\d.]+)"'),
        lambda m: VersionInfo(product="MongoDB", version=m.group("ver"),
                              confidence="medium"),
    ))

    # ---- VNC / RDP ---- #
    # RFB 003.008 (VNC)
    P.append((
        re.compile(r"^RFB\s+(?P<ver>\d+\.\d+)", re.MULTILINE),
        lambda m: VersionInfo(product="VNC (RFB)", version=m.group("ver")),
    ))

    # ---- Telnet (rare and risky to fingerprint, but try) ---- #
    P.append((
        re.compile(r"Ubuntu\s+(?P<ver>[\d.]+)\s+LTS", re.IGNORECASE),
        lambda m: VersionInfo(product="Linux", version=m.group("ver"),
                              extra="Ubuntu", confidence="low"),
    ))

    # ---- TLS — pulled from cert CN by banner grabber ---- #
    # Format we emit: "TLSv1.3 | CN=example.com"
    P.append((
        re.compile(r"^(?P<proto>TLSv?[\d.]+)\s*\|\s*CN=(?P<cn>.+?)\s*$", re.MULTILINE),
        lambda m: VersionInfo(product=f"TLS ({m.group('proto')})",
                              version="",
                              extra=f"CN={m.group('cn')}"),
    ))

    return P


_PATTERNS: list[_PatternEntry] = _compile_patterns()


def detect_version(banner: str) -> VersionInfo:
    """
    Apply all patterns to a banner and return the first match.

    Returns an empty VersionInfo() if no pattern matches — never raises.
    """
    if not banner:
        return VersionInfo()

    for regex, extractor in _PATTERNS:
        m = regex.search(banner)
        if m:
            try:
                return extractor(m)
            except Exception:  # noqa: BLE001 — bad pattern shouldn't crash
                continue
    return VersionInfo()


# Public for tests/introspection
def pattern_count() -> int:
    return len(_PATTERNS)
