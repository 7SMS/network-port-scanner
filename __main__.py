"""
Entry point.

Usage:
    python -m portscanner          # GUI
    python -m portscanner --cli ...  # CLI mode
"""

from __future__ import annotations

import argparse
import logging
import sys

from .utils.logger import setup_logging


def run_gui() -> int:
    try:
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtGui import QIcon
    except ImportError:
        print("PyQt6 not installed. Install with:  pip install PyQt6", file=sys.stderr)
        print("Or run in CLI mode:  python -m portscanner --cli --help", file=sys.stderr)
        return 2

    from .gui.main_window import MainWindow, _resolve_icon_path

    # On Windows, Python uses its own AppUserModelID by default — which means
    # our app gets grouped under "Python" in the taskbar instead of having
    # its own group with our icon. Setting an explicit ID fixes this.
    if sys.platform.startswith("win"):
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "PortScanner.7SM.CyberToolkit.1.2"
            )
        except Exception:  # noqa: BLE001
            pass  # Non-fatal; icon still works, just no taskbar grouping.

    app = QApplication(sys.argv)
    app.setApplicationName("Port Scanner")

    # Set the application-level icon (used for all child windows / dialogs).
    icon_path = _resolve_icon_path()
    if icon_path:
        app.setWindowIcon(QIcon(icon_path))

    win = MainWindow()
    win.show()
    return app.exec()


def run_cli(argv: list[str]) -> int:
    """Minimal CLI for headless / scripted use."""
    from .core.scanner import Scanner, ScanConfig, ScanType, scan_blocking, PortStatus
    from .core.targets import parse_targets, parse_ports
    from .core import exporters

    p = argparse.ArgumentParser(prog="portscanner",
                                description="Multi-threaded port scanner.")
    p.add_argument("targets", help="Target(s): IP, hostname, CIDR, or range")
    p.add_argument("-p", "--ports", default="1-1024", help="Port spec (default: 1-1024)")
    p.add_argument("-t", "--type", choices=["tcp", "syn", "udp"], default="tcp")
    p.add_argument("--threads", type=int, default=200)
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--retries", type=int, default=1)
    p.add_argument("--rate", type=int, default=0,
                   help="Rate limit in pkts/sec (0 = unlimited)")
    p.add_argument("--no-banners", action="store_true")
    p.add_argument("--export", help="Export results: out.json|out.csv|out.txt")
    p.add_argument("-v", "--verbose", action="store_true")

    args = p.parse_args(argv)

    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO)

    type_map = {"tcp": ScanType.TCP_CONNECT,
                "syn": ScanType.SYN, "udp": ScanType.UDP}

    cfg = ScanConfig(
        targets=parse_targets(args.targets),
        ports=parse_ports(args.ports),
        scan_type=type_map[args.type],
        timeout=args.timeout,
        threads=args.threads,
        retries=args.retries,
        rate_limit_pps=args.rate,
        grab_banners=not args.no_banners,
    )

    from .core import html_report

    print(f"[*] PortScanner by 7SM")
    print(f"[*] Scanning {len(cfg.targets)} host(s) × {len(cfg.ports)} port(s)…")
    import time as _time
    started = _time.time()
    results = scan_blocking(cfg)
    elapsed = _time.time() - started
    open_results = [r for r in results
                    if r.status in (PortStatus.OPEN, PortStatus.OPEN_FILTERED)]

    print(f"\n[+] Found {len(open_results)} open port(s) in {elapsed:.2f}s:")
    for r in sorted(open_results, key=lambda x: (x.host, x.port)):
        version = r.version_string or "—"
        line = (f"  {r.host}:{r.port}/{r.protocol}  "
                f"{r.status.value:<14} {r.service:<14} {version}")
        if r.banner and not r.version_string:
            line += f"  | {r.banner[:60]}"
        print(line)

    if args.export:
        lower = args.export.lower()
        if lower.endswith(".html"):
            html_report.export_html(
                results, args.export,
                title="Port Scan Report",
                targets=args.targets,
                ports=args.ports,
                scan_type=args.type,
                elapsed_seconds=elapsed,
            )
        elif lower.endswith(".json"):
            exporters.export_json(results, args.export)
        elif lower.endswith(".csv"):
            exporters.export_csv(results, args.export)
        else:
            exporters.export_txt(results, args.export)
        print(f"\n[+] Exported to {args.export}")

    return 0


def main() -> int:
    setup_logging()
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        return run_cli(sys.argv[2:])
    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
