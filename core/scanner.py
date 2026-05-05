"""
Scanning engine.

Three scan types:
  - TCP connect: works everywhere, slowest, most reliable.
  - SYN: needs raw socket privileges (root/admin). We try scapy; if not available
         or not privileged, we report that and fall back to TCP connect — we do NOT
         silently lie and say "SYN scan ran" when it didn't.
  - UDP: inherently unreliable. We send a probe and watch for ICMP unreachable
         to mark "closed". Any other outcome is "open|filtered" — same convention
         nmap uses, because that's the truth.

Design notes:
  - We use a ThreadPoolExecutor capped at MAX_THREADS for TCP/UDP I/O-bound work.
    The GIL is fine here — we're blocking on sockets.
  - Every scan pushes results to a callback so the GUI can update live.
  - Cancellation is cooperative via threading.Event. We don't kill threads
    (Python doesn't safely support that) — they finish their current socket op
    and then exit.
"""

from __future__ import annotations

import logging
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, List, Optional, Iterable

from .services import lookup_service, get_probe
from .version_detect import detect_version

log = logging.getLogger(__name__)

# Hard cap. Going beyond this on Python+sockets is wasteful and can hit
# OS file descriptor limits. If you want faster, use async I/O.
MAX_THREADS = 1000


class ScanType(Enum):
    TCP_CONNECT = "tcp_connect"
    SYN = "syn"
    UDP = "udp"


class PortStatus(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"  # UDP convention
    ERROR = "error"


@dataclass
class PortResult:
    """Result of scanning a single (host, port) pair."""
    host: str
    port: int
    protocol: str               # "tcp" or "udp"
    status: PortStatus
    service: str = "unknown"
    banner: str = ""
    latency_ms: float = 0.0
    error: str = ""
    timestamp: float = field(default_factory=time.time)
    # Version detection — populated when banners are grabbed
    product: str = ""
    version: str = ""
    version_extra: str = ""
    version_confidence: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @property
    def version_string(self) -> str:
        """Human-readable product/version label, '' if unknown."""
        if not self.product:
            return ""
        parts = [self.product]
        if self.version:
            parts.append(self.version)
        s = " ".join(parts)
        if self.version_extra:
            s += f" ({self.version_extra})"
        return s


@dataclass
class ScanConfig:
    targets: List[str]
    ports: List[int]
    scan_type: ScanType = ScanType.TCP_CONNECT
    timeout: float = 1.0          # seconds per connect attempt
    threads: int = 200
    retries: int = 1
    grab_banners: bool = True
    rate_limit_pps: int = 0       # 0 = unlimited; otherwise max packets/sec global
    detect_os: bool = False

    def __post_init__(self):
        if self.threads < 1:
            self.threads = 1
        if self.threads > MAX_THREADS:
            log.warning("Capping threads at %d (requested %d)", MAX_THREADS, self.threads)
            self.threads = MAX_THREADS
        if self.timeout <= 0:
            self.timeout = 1.0


# --------------------------------------------------------------------------- #
# Banner grabbing                                                              #
# --------------------------------------------------------------------------- #

def _grab_banner_tcp(host: str, port: int, timeout: float, service: str) -> str:
    """
    Try to elicit a banner. For services that greet on connect (SSH, FTP, SMTP)
    we just read. For HTTP we send a minimal GET. For TLS ports we do a TLS
    handshake and pull the cert CN.
    """
    try:
        # TLS-wrapped services
        if service in ("https", "smtps", "imaps", "pop3s", "ldaps", "https-alt"):
            return _grab_tls_banner(host, port, timeout)

        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            probe = get_probe(service)
            if probe:
                s.sendall(probe)
            data = s.recv(2048)
            return _clean_banner(data)
    except (socket.timeout, OSError):
        return ""
    except Exception as e:  # noqa: BLE001 — banner grabbing must never crash a scan
        log.debug("Banner grab failed for %s:%d — %s", host, port, e)
        return ""


def _grab_tls_banner(host: str, port: int, timeout: float) -> str:
    """Pull subject CN and protocol info from a TLS handshake."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert(binary_form=False) or {}
                proto = tls.version() or "TLS"
                subj = ""
                for tup in cert.get("subject", ()):
                    for k, v in tup:
                        if k == "commonName":
                            subj = v
                            break
                return f"{proto} | CN={subj}" if subj else proto
    except Exception as e:  # noqa: BLE001
        log.debug("TLS banner failed for %s:%d — %s", host, port, e)
        return ""


def _clean_banner(data: bytes) -> str:
    """Decode bytes to a printable single-line banner, capped at 256 chars."""
    if not data:
        return ""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        text = repr(data)
    # Single line, strip control chars
    text = text.replace("\r", " ").replace("\n", " ").strip()
    text = "".join(c if 32 <= ord(c) < 127 else "." for c in text)
    return text[:256]


# --------------------------------------------------------------------------- #
# Rate limiter — token bucket                                                  #
# --------------------------------------------------------------------------- #

class _RateLimiter:
    """Simple thread-safe rate limiter. pps=0 means no limit."""

    def __init__(self, pps: int):
        self.pps = pps
        self._lock = threading.Lock()
        self._allowance = float(pps) if pps > 0 else 0.0
        self._last = time.monotonic()

    def acquire(self) -> None:
        if self.pps <= 0:
            return
        with self._lock:
            now = time.monotonic()
            self._allowance += (now - self._last) * self.pps
            self._last = now
            if self._allowance > self.pps:
                self._allowance = self.pps
            if self._allowance < 1.0:
                sleep_for = (1.0 - self._allowance) / self.pps
            else:
                self._allowance -= 1.0
                return
        time.sleep(sleep_for)
        # After sleeping, recurse — under contention we may need another wait.
        self.acquire()


# --------------------------------------------------------------------------- #
# Individual scan probes                                                       #
# --------------------------------------------------------------------------- #

def _scan_tcp_connect(host: str, port: int, cfg: ScanConfig) -> PortResult:
    """
    Standard TCP connect scan. Returns a PortResult.
    A successful 3-way handshake => open. RST/connection refused => closed.
    Timeout / unreachable => filtered.
    """
    last_error = ""
    for attempt in range(cfg.retries + 1):
        start = time.monotonic()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(cfg.timeout)
                s.connect((host, port))
                latency = (time.monotonic() - start) * 1000
                service = lookup_service(port, "tcp")
                banner = ""
                if cfg.grab_banners:
                    banner = _grab_banner_tcp(host, port, cfg.timeout, service)
                # Try to extract product/version from the banner.
                vinfo = detect_version(banner) if banner else None
                return PortResult(
                    host=host, port=port, protocol="tcp",
                    status=PortStatus.OPEN, service=service,
                    banner=banner, latency_ms=round(latency, 2),
                    product=(vinfo.product if vinfo else ""),
                    version=(vinfo.version if vinfo else ""),
                    version_extra=(vinfo.extra if vinfo else ""),
                    version_confidence=(vinfo.confidence if vinfo else ""),
                )
        except ConnectionRefusedError:
            return PortResult(
                host=host, port=port, protocol="tcp",
                status=PortStatus.CLOSED, service=lookup_service(port, "tcp"),
            )
        except socket.timeout:
            last_error = "timeout"
            continue
        except OSError as e:
            # ehostunreach, network unreachable, etc.
            last_error = str(e)
            continue

    return PortResult(
        host=host, port=port, protocol="tcp",
        status=PortStatus.FILTERED,
        service=lookup_service(port, "tcp"),
        error=last_error,
    )


def _scan_udp(host: str, port: int, cfg: ScanConfig) -> PortResult:
    """
    UDP scan. We send an empty datagram (or a service-specific probe for known
    ports). If we get *any* reply, the port is open. If we get an ICMP port
    unreachable, it's closed. Silence => open|filtered, because UDP doesn't
    acknowledge receipt by default. This matches nmap's convention because it's
    the only honest answer.
    """
    service = lookup_service(port, "udp")
    # Service-specific probes increase chance of a reply for "open" detection.
    payload = _udp_probe_for_service(service)

    for _ in range(cfg.retries + 1):
        start = time.monotonic()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(cfg.timeout)
                s.sendto(payload, (host, port))
                try:
                    data, _ = s.recvfrom(4096)
                    latency = (time.monotonic() - start) * 1000
                    banner = _clean_banner(data)
                    vinfo = detect_version(banner) if banner else None
                    return PortResult(
                        host=host, port=port, protocol="udp",
                        status=PortStatus.OPEN, service=service,
                        banner=banner,
                        latency_ms=round(latency, 2),
                        product=(vinfo.product if vinfo else ""),
                        version=(vinfo.version if vinfo else ""),
                        version_extra=(vinfo.extra if vinfo else ""),
                        version_confidence=(vinfo.confidence if vinfo else ""),
                    )
                except socket.timeout:
                    continue  # retry
        except OSError as e:
            errno = getattr(e, "errno", 0)
            # ECONNREFUSED on UDP means we got an ICMP port-unreachable
            if errno in (111, 10054, 10061):
                return PortResult(
                    host=host, port=port, protocol="udp",
                    status=PortStatus.CLOSED, service=service,
                )
            return PortResult(
                host=host, port=port, protocol="udp",
                status=PortStatus.ERROR, service=service, error=str(e),
            )

    # No reply after all retries — could be open (silent) or filtered.
    return PortResult(
        host=host, port=port, protocol="udp",
        status=PortStatus.OPEN_FILTERED, service=service,
    )


def _udp_probe_for_service(service: str) -> bytes:
    """Return a payload likely to elicit a UDP response for known services."""
    if service == "dns":
        # Standard DNS query for "version.bind" CHAOS TXT — many resolvers reply.
        return (
            b"\x12\x34"           # ID
            b"\x01\x00"           # flags: standard query
            b"\x00\x01"           # qdcount
            b"\x00\x00\x00\x00\x00\x00"
            b"\x07version\x04bind\x00"
            b"\x00\x10\x00\x03"   # TXT, CHAOS
        )
    if service == "ntp":
        return b"\x1b" + b"\x00" * 47  # NTP v3 client request
    if service == "snmp":
        # SNMPv1 GetRequest for sysDescr.0 with community "public"
        return bytes.fromhex(
            "302902010004067075626c6963a01c02047a05cf3a02010002010030"
            "0e300c06082b060102010101000500"
        )
    return b"\x00"  # generic single byte; works for "any reply == open"


# --------------------------------------------------------------------------- #
# SYN scan (privileged) — uses scapy if available                              #
# --------------------------------------------------------------------------- #

def _syn_available() -> tuple[bool, str]:
    """Check whether SYN scanning will actually work. Returns (ok, reason)."""
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        return False, "scapy not installed (pip install scapy)"

    # Raw sockets need root on Unix, admin on Windows. Best-effort check.
    import os, sys
    if sys.platform.startswith("win"):
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return False, "SYN scan requires Administrator on Windows"
        except Exception:  # noqa: BLE001
            return False, "Could not verify admin privileges"
    else:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return False, "SYN scan requires root (try sudo)"
    return True, ""


def _scan_syn(host: str, port: int, cfg: ScanConfig) -> PortResult:
    """
    SYN scan via scapy. Sends SYN, watches for SYN/ACK (open), RST (closed),
    or nothing (filtered). Sends RST after SYN/ACK to avoid completing the
    handshake — that's the whole point of SYN scanning.
    """
    try:
        from scapy.all import IP, TCP, sr1, send  # type: ignore
    except ImportError:
        return PortResult(
            host=host, port=port, protocol="tcp", status=PortStatus.ERROR,
            error="scapy unavailable",
        )

    pkt = IP(dst=host) / TCP(dport=port, flags="S")
    try:
        resp = sr1(pkt, timeout=cfg.timeout, verbose=0)
    except PermissionError:
        return PortResult(
            host=host, port=port, protocol="tcp", status=PortStatus.ERROR,
            error="permission denied (need root/admin for raw sockets)",
        )
    except Exception as e:  # noqa: BLE001
        return PortResult(
            host=host, port=port, protocol="tcp", status=PortStatus.ERROR,
            error=f"scapy error: {e}",
        )

    if resp is None:
        return PortResult(
            host=host, port=port, protocol="tcp", status=PortStatus.FILTERED,
            service=lookup_service(port, "tcp"),
        )

    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        if flags & 0x12:  # SYN+ACK
            # Politely tear down — send RST so we don't leave half-open.
            try:
                send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)
            except Exception:  # noqa: BLE001
                pass
            return PortResult(
                host=host, port=port, protocol="tcp", status=PortStatus.OPEN,
                service=lookup_service(port, "tcp"),
            )
        if flags & 0x04:  # RST
            return PortResult(
                host=host, port=port, protocol="tcp", status=PortStatus.CLOSED,
                service=lookup_service(port, "tcp"),
            )

    return PortResult(
        host=host, port=port, protocol="tcp", status=PortStatus.FILTERED,
        service=lookup_service(port, "tcp"),
    )


# --------------------------------------------------------------------------- #
# OS fingerprinting — the honest, limited version                              #
# --------------------------------------------------------------------------- #

def fingerprint_os_basic(host: str, timeout: float = 1.0) -> str:
    """
    Very rough OS guess based on TTL of an open-port reply. This is a HEURISTIC,
    not a fingerprint. Real OS detection looks at TCP options, window size,
    DF bit, ICMP responses, etc. Don't trust this for anything important.

    Initial TTLs:
      - 64  => Linux/macOS/*nix (most likely)
      - 128 => Windows
      - 255 => Solaris/network gear (Cisco, etc.)
    """
    try:
        from scapy.all import IP, ICMP, sr1  # type: ignore
    except ImportError:
        return "unknown (scapy not available)"

    try:
        resp = sr1(IP(dst=host) / ICMP(), timeout=timeout, verbose=0)
    except Exception:  # noqa: BLE001
        return "unknown"

    if resp is None or not resp.haslayer(IP):
        return "unknown"

    ttl = resp.getlayer(IP).ttl
    # The actual TTL we see is initial_ttl - hops. Round up to common buckets.
    if ttl <= 64:
        guess = "Linux/Unix"
    elif ttl <= 128:
        guess = "Windows"
    elif ttl <= 255:
        guess = "Cisco/Solaris"
    else:
        guess = "unknown"
    return f"{guess} (TTL={ttl}, heuristic only)"


# --------------------------------------------------------------------------- #
# Main scanner orchestration                                                   #
# --------------------------------------------------------------------------- #

class Scanner:
    """
    Orchestrates a scan run. Use start() to kick off; results stream via the
    on_result callback. Call stop() for cooperative cancellation.
    """

    def __init__(
        self,
        config: ScanConfig,
        on_result: Optional[Callable[[PortResult], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_log: Optional[Callable[[str, str], None]] = None,  # (level, message)
        on_complete: Optional[Callable[[List[PortResult]], None]] = None,
    ):
        self.config = config
        self._on_result = on_result or (lambda r: None)
        self._on_progress = on_progress or (lambda done, total: None)
        self._on_log = on_log or (lambda lvl, msg: None)
        self._on_complete = on_complete or (lambda results: None)

        self._stop_event = threading.Event()
        self._executor: Optional[ThreadPoolExecutor] = None
        self._futures: List[Future] = []
        self._results: List[PortResult] = []
        self._results_lock = threading.Lock()
        self._completed = 0
        self._completed_lock = threading.Lock()
        self._rate_limiter = _RateLimiter(config.rate_limit_pps)
        self._scanner_thread: Optional[threading.Thread] = None

    # ---- public API ---- #

    def start(self) -> None:
        """Kick off the scan in a background thread. Non-blocking."""
        if self._scanner_thread and self._scanner_thread.is_alive():
            self._log("warning", "Scan already running.")
            return
        self._stop_event.clear()
        self._results = []
        self._completed = 0
        self._scanner_thread = threading.Thread(target=self._run, daemon=True)
        self._scanner_thread.start()

    def stop(self) -> None:
        """Request cancellation. Threads finish their current op then exit."""
        self._log("warning", "Stop requested. Waiting for in-flight probes…")
        self._stop_event.set()
        if self._executor:
            # Cancel queued futures; running ones must complete their socket op.
            self._executor.shutdown(wait=False, cancel_futures=True)

    def is_running(self) -> bool:
        return self._scanner_thread is not None and self._scanner_thread.is_alive()

    # ---- internals ---- #

    def _log(self, level: str, msg: str) -> None:
        getattr(log, level, log.info)(msg)
        self._on_log(level, msg)

    def _run(self) -> None:
        cfg = self.config
        total = len(cfg.targets) * len(cfg.ports)
        self._log("info", f"Scan started: {len(cfg.targets)} host(s) × "
                          f"{len(cfg.ports)} port(s) = {total} probes "
                          f"[{cfg.scan_type.value}, {cfg.threads} threads]")

        # Pick the scan function up-front so we don't re-check per port.
        scan_fn = self._select_scan_fn()

        start_time = time.monotonic()
        self._executor = ThreadPoolExecutor(max_workers=cfg.threads,
                                            thread_name_prefix="scanworker")
        try:
            for host in cfg.targets:
                if self._stop_event.is_set():
                    break
                for port in cfg.ports:
                    if self._stop_event.is_set():
                        break
                    fut = self._executor.submit(self._probe, scan_fn, host, port, total)
                    self._futures.append(fut)

            # Wait for all submitted probes to complete (or be cancelled).
            for fut in self._futures:
                if self._stop_event.is_set():
                    break
                try:
                    fut.result()
                except Exception as e:  # noqa: BLE001
                    self._log("error", f"Probe error: {e}")
        finally:
            self._executor.shutdown(wait=True)
            elapsed = time.monotonic() - start_time
            open_count = sum(1 for r in self._results
                             if r.status in (PortStatus.OPEN, PortStatus.OPEN_FILTERED))
            self._log("info", f"Scan finished in {elapsed:.2f}s — "
                              f"{len(self._results)} probes, {open_count} open.")
            self._on_complete(list(self._results))

    def _select_scan_fn(self) -> Callable[[str, int, ScanConfig], PortResult]:
        """Pick the probe function. Falls back from SYN to TCP-connect honestly."""
        st = self.config.scan_type
        if st == ScanType.SYN:
            ok, reason = _syn_available()
            if not ok:
                self._log("warning", f"SYN scan unavailable ({reason}). "
                                     "Falling back to TCP connect scan.")
                return _scan_tcp_connect
            return _scan_syn
        if st == ScanType.UDP:
            return _scan_udp
        return _scan_tcp_connect

    def _probe(self, scan_fn, host: str, port: int, total: int) -> None:
        """One probe — runs in a worker thread."""
        if self._stop_event.is_set():
            return
        self._rate_limiter.acquire()

        try:
            result = scan_fn(host, port, self.config)
        except Exception as e:  # noqa: BLE001 — never let one bad probe kill the scan
            log.exception("Probe crashed for %s:%d", host, port)
            result = PortResult(
                host=host, port=port, protocol="tcp",
                status=PortStatus.ERROR, error=str(e),
            )

        with self._results_lock:
            self._results.append(result)
        with self._completed_lock:
            self._completed += 1
            done = self._completed

        # Stream interesting results to the GUI; everything goes to results list.
        # We forward all results so the user can see closed/filtered counts too.
        self._on_result(result)
        self._on_progress(done, total)


# --------------------------------------------------------------------------- #
# Convenience for non-GUI use                                                  #
# --------------------------------------------------------------------------- #

def scan_blocking(config: ScanConfig) -> List[PortResult]:
    """Run a scan to completion and return results. For CLI / tests."""
    results: List[PortResult] = []
    done_event = threading.Event()

    def _on_complete(rs):
        results.extend(rs)
        done_event.set()

    scanner = Scanner(config, on_complete=_on_complete)
    scanner.start()
    done_event.wait()
    return results
