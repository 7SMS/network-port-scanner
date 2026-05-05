"""
HTML report generator — single-file, self-contained, professionally styled.

Why no Jinja2: keeps the package dependency-free. The template is a single
f-string. For more complex reports, switch to Jinja2 — but for what we need
(summary + per-host tables + a chart), inline templating is fine.

The output is a single .html file with embedded CSS — open it in a browser
or send it to a client. No external resources, no internet required.
"""

from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .scanner import PortResult


# CSS lives outside the f-string for readability. We inject it at the end.
_CSS = """
:root {
  --bg: #0a0e14;
  --bg-alt: #11161e;
  --border: #1f2933;
  --text: #c5d1de;
  --text-dim: #7a8694;
  --text-bright: #e4ecf5;
  --accent: #39ff14;
  --accent-dim: #2bc70f;
  --warn: #ffb000;
  --danger: #ff3860;
  --info: #3abff8;
}

* { box-sizing: border-box; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  margin: 0;
  padding: 0;
  line-height: 1.55;
}

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 32px 24px;
}

header {
  border-bottom: 2px solid var(--accent);
  padding-bottom: 20px;
  margin-bottom: 28px;
}

header h1 {
  color: var(--accent);
  font-family: "Consolas", "Menlo", monospace;
  margin: 0;
  font-size: 28px;
  letter-spacing: 2px;
}

header .subtitle {
  color: var(--text-dim);
  font-size: 13px;
  margin-top: 4px;
  font-family: "Consolas", monospace;
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 14px;
  margin-bottom: 28px;
}

.stat {
  background: var(--bg-alt);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 16px 18px;
}

.stat .label {
  color: var(--text-dim);
  font-size: 11px;
  letter-spacing: 2px;
  text-transform: uppercase;
}

.stat .value {
  color: var(--text-bright);
  font-size: 26px;
  font-weight: 600;
  margin-top: 4px;
  font-family: "Consolas", monospace;
}

.stat.accent .value { color: var(--accent); }
.stat.warn .value   { color: var(--warn); }
.stat.danger .value { color: var(--danger); }

section {
  background: var(--bg-alt);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 20px 24px;
  margin-bottom: 20px;
}

section h2 {
  color: var(--accent);
  font-family: "Consolas", monospace;
  font-size: 14px;
  letter-spacing: 3px;
  margin: 0 0 16px 0;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
}

.host-block {
  margin-bottom: 24px;
}

.host-header {
  font-family: "Consolas", monospace;
  color: var(--text-bright);
  font-size: 16px;
  margin: 18px 0 10px 0;
  padding: 8px 12px;
  background: rgba(57, 255, 20, 0.06);
  border-left: 3px solid var(--accent);
}

.host-header .open-count {
  color: var(--accent);
  font-weight: bold;
  margin-left: 12px;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-family: "Consolas", monospace;
  font-size: 13px;
}

th {
  text-align: left;
  color: var(--accent);
  background: var(--bg);
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  font-size: 11px;
  letter-spacing: 1px;
  text-transform: uppercase;
}

td {
  padding: 6px 10px;
  border-bottom: 1px solid var(--border);
  color: var(--text);
  vertical-align: top;
}

tr:hover td {
  background: rgba(255, 255, 255, 0.02);
}

.status-open       { color: var(--accent); font-weight: bold; }
.status-closed     { color: var(--text-dim); }
.status-filtered   { color: var(--warn); }
.status-error      { color: var(--danger); }

.version-known   { color: var(--accent); }
.version-unknown { color: var(--text-dim); font-style: italic; }

.banner-cell {
  max-width: 400px;
  word-break: break-all;
  color: var(--text-dim);
  font-size: 12px;
}

.bar-chart {
  display: flex;
  align-items: flex-end;
  gap: 8px;
  height: 180px;
  padding: 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
}

.bar {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-end;
  min-width: 60px;
}

.bar-fill {
  width: 100%;
  background: linear-gradient(180deg, var(--accent) 0%, var(--accent-dim) 100%);
  border-radius: 3px 3px 0 0;
  min-height: 2px;
  transition: opacity 0.2s;
}

.bar:hover .bar-fill {
  opacity: 0.8;
}

.bar-label {
  margin-top: 6px;
  font-size: 11px;
  color: var(--text-dim);
  font-family: "Consolas", monospace;
}

.bar-value {
  font-size: 12px;
  color: var(--text-bright);
  font-weight: bold;
  margin-bottom: 4px;
}

.disclaimer {
  background: rgba(255, 176, 0, 0.08);
  border: 1px solid var(--warn);
  color: var(--warn);
  padding: 10px 14px;
  border-radius: 4px;
  font-size: 12px;
  margin-bottom: 24px;
}

footer {
  text-align: center;
  color: var(--text-dim);
  font-size: 11px;
  padding: 24px 0 0 0;
  margin-top: 24px;
  border-top: 1px solid var(--border);
  font-family: "Consolas", monospace;
  letter-spacing: 2px;
}

footer .signature {
  color: var(--accent);
  font-weight: bold;
}

.no-results {
  color: var(--text-dim);
  font-style: italic;
  padding: 12px;
}

@media print {
  body { background: white; color: black; }
  .stat, section, table { background: white; color: black; }
  th { color: black; background: #eee; }
  .status-open { color: green; }
  .status-filtered { color: orange; }
}
"""


def _esc(s: str) -> str:
    """Shorthand for HTML escape."""
    return html.escape(s or "", quote=True)


def _status_class(status: str) -> str:
    if status == "open" or status == "open|filtered":
        return "status-open"
    if status == "closed":
        return "status-closed"
    if status == "filtered":
        return "status-filtered"
    if status == "error":
        return "status-error"
    return ""


def _build_port_distribution_chart(open_results: list[PortResult]) -> str:
    """
    Returns SVG-free bar chart HTML showing the most common open services.
    Top 10 services. If no opens, returns a placeholder.
    """
    if not open_results:
        return '<div class="no-results">No open ports detected.</div>'

    services = Counter(r.service for r in open_results)
    top = services.most_common(10)
    max_count = max(c for _, c in top) if top else 1

    bars = []
    for service, count in top:
        height_pct = (count / max_count) * 100
        bars.append(
            f'<div class="bar" title="{_esc(service)}: {count}">'
            f'<div class="bar-value">{count}</div>'
            f'<div class="bar-fill" style="height:{height_pct}%"></div>'
            f'<div class="bar-label">{_esc(service)}</div>'
            f'</div>'
        )
    return f'<div class="bar-chart">{"".join(bars)}</div>'


def export_html(
    results: Iterable[PortResult],
    path: str | Path,
    title: str = "Port Scan Report",
    targets: str = "",
    ports: str = "",
    scan_type: str = "",
    elapsed_seconds: float = 0.0,
) -> None:
    """Render results to a single self-contained HTML file."""
    items = list(results)
    by_host: dict[str, list[PortResult]] = defaultdict(list)
    for r in items:
        by_host[r.host].append(r)

    # ---- summary stats ---- #
    total = len(items)
    open_results = [r for r in items if r.status.value in ("open", "open|filtered")]
    closed = sum(1 for r in items if r.status.value == "closed")
    filtered = sum(1 for r in items if r.status.value == "filtered")
    errors = sum(1 for r in items if r.status.value == "error")
    hosts_with_open = sum(1 for h, rs in by_host.items()
                          if any(r.status.value in ("open", "open|filtered") for r in rs))

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ---- per-host sections ---- #
    host_sections = []
    for host, host_results in sorted(by_host.items()):
        opens = sorted(
            [r for r in host_results if r.status.value in ("open", "open|filtered")],
            key=lambda r: r.port,
        )
        rows = []
        if not opens:
            rows.append('<tr><td colspan="6" class="no-results">No open ports.</td></tr>')
        else:
            for r in opens:
                version_html = (
                    f'<span class="version-known">{_esc(r.version_string)}</span>'
                    if r.version_string
                    else '<span class="version-unknown">—</span>'
                )
                rows.append(
                    "<tr>"
                    f'<td>{r.port}</td>'
                    f'<td>{_esc(r.protocol.upper())}</td>'
                    f'<td class="{_status_class(r.status.value)}">{_esc(r.status.value.upper())}</td>'
                    f'<td>{_esc(r.service)}</td>'
                    f'<td>{version_html}</td>'
                    f'<td class="banner-cell">{_esc(r.banner or "")}</td>'
                    "</tr>"
                )

        host_sections.append(f"""
        <div class="host-block">
          <div class="host-header">
            {_esc(host)}
            <span class="open-count">{len(opens)} open</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Port</th>
                <th>Proto</th>
                <th>Status</th>
                <th>Service</th>
                <th>Version</th>
                <th>Banner</th>
              </tr>
            </thead>
            <tbody>{''.join(rows)}</tbody>
          </table>
        </div>
        """)

    chart_html = _build_port_distribution_chart(open_results)

    # ---- main HTML ---- #
    body = f"""
    <header>
      <h1>◢ {_esc(title)}</h1>
      <div class="subtitle">
        Generated {generated}
      </div>
    </header>

    <div class="disclaimer">
      ⚠ AUTHORIZED USE ONLY — This report contains scan results from
      systems you should have explicit permission to scan. Treat the
      information here as confidential.
    </div>

    <div class="summary-grid">
      <div class="stat accent">
        <div class="label">Open Ports</div>
        <div class="value">{len(open_results)}</div>
      </div>
      <div class="stat">
        <div class="label">Hosts with open ports</div>
        <div class="value">{hosts_with_open} / {len(by_host)}</div>
      </div>
      <div class="stat">
        <div class="label">Total probes</div>
        <div class="value">{total}</div>
      </div>
      <div class="stat warn">
        <div class="label">Filtered</div>
        <div class="value">{filtered}</div>
      </div>
      <div class="stat">
        <div class="label">Closed</div>
        <div class="value">{closed}</div>
      </div>
      <div class="stat danger">
        <div class="label">Errors</div>
        <div class="value">{errors}</div>
      </div>
    </div>

    <section>
      <h2>◆ SCAN PARAMETERS</h2>
      <table>
        <tr><td><strong>Targets</strong></td><td>{_esc(targets)}</td></tr>
        <tr><td><strong>Ports</strong></td><td>{_esc(ports)}</td></tr>
        <tr><td><strong>Scan type</strong></td><td>{_esc(scan_type)}</td></tr>
        <tr><td><strong>Elapsed</strong></td><td>{elapsed_seconds:.2f}s</td></tr>
      </table>
    </section>

    <section>
      <h2>◆ TOP OPEN SERVICES</h2>
      {chart_html}
    </section>

    <section>
      <h2>◆ FINDINGS BY HOST</h2>
      {''.join(host_sections) if host_sections else '<div class="no-results">No hosts scanned.</div>'}
    </section>

    <footer>
      Generated by PortScanner • <span class="signature">7SM</span>
    </footer>
    """

    full = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_esc(title)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="container">
    {body}
  </div>
</body>
</html>"""

    Path(path).write_text(full, encoding="utf-8")
