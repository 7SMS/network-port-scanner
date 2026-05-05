"""
Export scan results to JSON, CSV, or TXT.

Each exporter is a single function — no clever class hierarchy, none needed.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .scanner import PortResult


def export_json(results: Iterable[PortResult], path: str | Path) -> None:
    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "count": 0,
        "results": [],
    }
    items = [r.to_dict() for r in results]
    payload["count"] = len(items)
    payload["results"] = items
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def export_csv(results: Iterable[PortResult], path: str | Path) -> None:
    fieldnames = [
        "host", "port", "protocol", "status",
        "service", "product", "version", "version_extra", "version_confidence",
        "banner", "latency_ms", "error", "timestamp",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in results:
            w.writerow(r.to_dict())


def export_txt(results: Iterable[PortResult], path: str | Path) -> None:
    """Human-readable nmap-ish output."""
    items = list(results)
    by_host: dict[str, list[PortResult]] = {}
    for r in items:
        by_host.setdefault(r.host, []).append(r)

    lines = []
    lines.append("Port Scan Report")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Total probes: {len(items)}")
    lines.append("")

    for host, results_list in by_host.items():
        lines.append(f"Host: {host}")
        lines.append("-" * 60)
        # Show only open / open|filtered by default — closed is noise.
        interesting = [r for r in results_list
                       if r.status.value in ("open", "open|filtered")]
        if not interesting:
            lines.append("  No open ports detected.")
        else:
            lines.append(f"  {'PORT':<10}{'PROTO':<8}{'STATE':<18}"
                         f"{'SERVICE':<14}{'VERSION':<28}BANNER")
            for r in sorted(interesting, key=lambda x: x.port):
                banner = r.banner[:60] if r.banner else ""
                # version_string may not exist on shim objects
                version = getattr(r, "version_string", "") or "—"
                lines.append(
                    f"  {r.port:<10}{r.protocol:<8}{r.status.value:<18}"
                    f"{r.service:<14}{version[:27]:<28}{banner}"
                )
        lines.append("")

    Path(path).write_text("\n".join(lines), encoding="utf-8")
