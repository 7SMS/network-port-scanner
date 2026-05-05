"""
Scan profiles — save and load named scan configurations.

Profiles persist to a JSON file in the user's app dir. They store the
configuration *inputs* (target/port strings, scan type, threads, etc.) —
NOT scan results. Results live in history.

A handful of built-in profiles are bundled (web, db, common-services). They're
read-only — users can't overwrite them, but they can copy and modify.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


def default_profiles_path() -> Path:
    home = Path.home() / ".portscanner"
    home.mkdir(parents=True, exist_ok=True)
    return home / "profiles.json"


@dataclass
class ScanProfile:
    """A named, reusable scan configuration."""
    name: str
    description: str = ""
    targets: str = ""
    ports: str = "1-1024"
    scan_type: str = "tcp_connect"  # matches ScanType.value
    threads: int = 200
    timeout: float = 1.0
    retries: int = 1
    grab_banners: bool = True
    rate_limit_pps: int = 0
    detect_os: bool = False
    builtin: bool = False  # built-in profiles can't be edited/deleted

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanProfile":
        # Be defensive: ignore unknown keys, fill defaults for missing.
        kwargs = {}
        for f in cls.__dataclass_fields__:
            if f in d:
                kwargs[f] = d[f]
        return cls(**kwargs)


# Built-in profiles — available out of the box. Marked builtin=True so
# they can't be deleted/overwritten by the user.
BUILTIN_PROFILES: list[ScanProfile] = [
    ScanProfile(
        name="Quick Scan (top 100)",
        description="Fast TCP scan of the 100 most common ports.",
        ports=("21,22,23,25,53,80,110,111,135,139,143,443,445,587,"
               "993,995,1080,1433,1521,1723,2049,2222,3306,3389,5432,"
               "5900,5984,6379,8000,8080,8443,8888,9000,9200,9300,11211,"
               "27017,389,636,5000,5601,5672,2375,2376,4444,7474,3000,"
               "8001,8008,8081,9092,50000,53,67,68,69,123,137,138,161,"
               "162,389,514,515,548,631,873,1194,2049,5000,5060,5061,"
               "5353,8009,8010,8020,8021,8088,8181,8500,8530,8531,8834,"
               "8899,9001,9100,9418,10000,10250,11371,15672,16379,18080,"
               "27015,27374,28017,32400,32768,49152,49153,49154"),
        scan_type="tcp_connect",
        threads=200, timeout=0.8, retries=0,
        builtin=True,
    ),
    ScanProfile(
        name="Web Servers",
        description="Common HTTP/HTTPS ports including dev servers and proxies.",
        ports="80,81,443,591,2082,2087,2095,2096,3000,4567,5000,5601,"
              "7000,7001,8000,8001,8008,8080,8081,8088,8090,8181,8443,"
              "8888,9000,9090,9443",
        scan_type="tcp_connect",
        threads=100, timeout=1.0, retries=1,
        builtin=True,
    ),
    ScanProfile(
        name="Databases",
        description="Common database server ports — useful for finding "
                    "exposed/misconfigured DBs.",
        ports="1433,1521,3306,5432,5984,6379,7474,7687,8086,9042,9092,"
              "9200,11211,27017,27018,27019,28017,50000",
        scan_type="tcp_connect",
        threads=50, timeout=1.5, retries=1,
        builtin=True,
    ),
    ScanProfile(
        name="Remote Access",
        description="SSH, RDP, VNC, Telnet, and similar remote access services.",
        ports="22,23,512,513,514,1494,2222,3283,3389,5500,5800,5900-5910,5938",
        scan_type="tcp_connect",
        threads=50, timeout=1.5, retries=1,
        builtin=True,
    ),
    ScanProfile(
        name="Mail Servers",
        description="SMTP, POP3, IMAP and their TLS variants.",
        ports="25,109,110,143,209,218,220,465,587,993,995,2525",
        scan_type="tcp_connect",
        threads=30, timeout=1.5, retries=1,
        builtin=True,
    ),
    ScanProfile(
        name="Full TCP (1-65535)",
        description="Complete TCP port range. Slow — use only when needed.",
        ports="1-65535",
        scan_type="tcp_connect",
        threads=500, timeout=0.5, retries=0,
        builtin=True,
    ),
    ScanProfile(
        name="Stealth Slow Scan",
        description="Rate-limited TCP scan to reduce IDS detection. "
                    "1 connection per 200ms.",
        ports="1-1024",
        scan_type="tcp_connect",
        threads=1, timeout=2.0, retries=1,
        rate_limit_pps=5,
        builtin=True,
    ),
]


class ProfileStore:
    """Thread-safe profile persistence."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or default_profiles_path()
        self._lock = threading.Lock()
        self._user_profiles: dict[str, ScanProfile] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return  # silently ignore corrupt profile file
        if not isinstance(data, list):
            return
        for entry in data:
            try:
                p = ScanProfile.from_dict(entry)
                p.builtin = False  # user profiles are never built-in
                self._user_profiles[p.name] = p
            except (TypeError, KeyError):
                continue

    def _save(self) -> None:
        """Write user profiles to disk. Built-ins are not persisted."""
        items = [p.to_dict() for p in self._user_profiles.values()]
        try:
            self.path.write_text(
                json.dumps(items, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass

    # ---- public API ---- #

    def list_all(self) -> list[ScanProfile]:
        """Return built-ins + user profiles, built-ins first."""
        with self._lock:
            return list(BUILTIN_PROFILES) + list(self._user_profiles.values())

    def get(self, name: str) -> Optional[ScanProfile]:
        with self._lock:
            for p in BUILTIN_PROFILES:
                if p.name == name:
                    return p
            return self._user_profiles.get(name)

    def save(self, profile: ScanProfile) -> bool:
        """
        Save (or overwrite) a user profile. Returns False if name conflicts
        with a built-in.
        """
        if not profile.name.strip():
            return False
        with self._lock:
            if any(p.name == profile.name for p in BUILTIN_PROFILES):
                return False
            profile.builtin = False
            self._user_profiles[profile.name] = profile
            self._save()
            return True

    def delete(self, name: str) -> bool:
        """Delete a user profile. Returns False if not found or built-in."""
        with self._lock:
            if name in self._user_profiles:
                del self._user_profiles[name]
                self._save()
                return True
            return False

    def exists(self, name: str) -> bool:
        with self._lock:
            return (any(p.name == name for p in BUILTIN_PROFILES)
                    or name in self._user_profiles)
