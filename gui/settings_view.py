"""
Settings / About view.

Kept simple — there's not much to configure beyond what's already on the scan
page. This is mostly for showing log/db locations, the disclaimer, and an
"about" blurb. If you want to add real settings later (default thread count,
default ports, color theme), this is where they go.
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QTextBrowser,
)

from ..core.history import default_db_path
from .theme import COLORS


ABOUT_HTML = f"""
<div style="color:{COLORS['text']}; font-family:Consolas,monospace;">
<h2 style="color:{COLORS['accent']}; margin:0 0 8px 0;">Network Port Scanner</h2>
<p style="color:{COLORS['accent']}; margin:0 0 4px 0; font-size:14px;">
<b>Developed by 7SM</b>
</p>
<p style="color:{COLORS['text_dim']}; margin:0 0 16px 0;">
A multi-threaded TCP/SYN/UDP port scanner with banner grabbing and a
dark-themed PyQt6 GUI.
</p>

<h3 style="color:{COLORS['accent']};">⚠ Disclaimer</h3>
<p>
This tool is provided for <b>authorized security testing and educational
use only</b>. Scanning networks or systems without the explicit written
permission of the owner is illegal in most jurisdictions and may carry
significant criminal and civil penalties. The authors accept no liability
for misuse.
</p>

<h3 style="color:{COLORS['accent']};">Honest limitations</h3>
<ul>
<li><b>SYN scan</b> requires root/Administrator privileges and the
<code>scapy</code> package. If unavailable, the scanner falls back to TCP
connect — and tells you so in the log. It does not silently lie.</li>
<li><b>UDP scan</b> is fundamentally unreliable. Silent ports show as
<code>open|filtered</code> because that's the only honest classification.</li>
<li><b>OS fingerprinting</b> here is a heuristic based on TTL only. Real OS
detection (à la nmap) requires dozens of probes and stack quirks. Treat
the result as a guess, not a fact.</li>
<li><b>Thread count</b> beyond ~500 yields diminishing returns on most
systems due to OS socket limits. More threads ≠ faster scan.</li>
</ul>

<h3 style="color:{COLORS['accent']};">Hot-key tips</h3>
<table style="margin-top:8px;">
<tr><td style="padding:2px 14px 2px 0;"><code style="color:{COLORS['accent']};">Ctrl+R</code> or <code style="color:{COLORS['accent']};">F5</code></td><td>Start scan</td></tr>
<tr><td style="padding:2px 14px 2px 0;"><code style="color:{COLORS['accent']};">Ctrl+E</code> or <code style="color:{COLORS['accent']};">Esc</code></td><td>Stop running scan</td></tr>
<tr><td style="padding:2px 14px 2px 0;"><code style="color:{COLORS['accent']};">Ctrl+S</code></td><td>Export results</td></tr>
<tr><td style="padding:2px 14px 2px 0;"><code style="color:{COLORS['accent']};">Ctrl+L</code></td><td>Focus the target field</td></tr>
<tr><td style="padding:2px 14px 2px 0;"><code style="color:{COLORS['accent']};">Ctrl+P</code></td><td>Focus the ports field</td></tr>
<tr><td style="padding:2px 14px 2px 0;"><code style="color:{COLORS['accent']};">Ctrl+F</code></td><td>Focus the results filter</td></tr>
<tr><td style="padding:2px 14px 2px 0;"><code style="color:{COLORS['accent']};">Ctrl+K</code></td><td>Clear terminal output</td></tr>
</table>
<p style="margin-top:12px;">Other tips:</p>
<ul>
<li>Double-click any result row for full details.</li>
<li>The "Open only" toggle filters out closed/filtered noise.</li>
<li>Save current settings as a profile via the Profile dropdown's <b>Save</b> button. Built-in profiles (★) can't be overwritten.</li>
<li>Export to <b>HTML</b> for shareable reports with charts and per-host tables.</li>
</ul>
</div>
"""


class SettingsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        # About card
        about_card = QFrame()
        about_card.setObjectName("Card")
        v1 = QVBoxLayout(about_card)
        v1.setContentsMargins(16, 14, 16, 14)
        v1.setSpacing(8)

        title1 = QLabel("◆ ABOUT")
        title1.setObjectName("CardTitle")
        v1.addWidget(title1)

        about = QTextBrowser()
        about.setOpenExternalLinks(True)
        about.setHtml(ABOUT_HTML)
        about.setStyleSheet(f"""
            QTextBrowser {{
                background-color: {COLORS['bg']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 8px;
            }}
        """)
        v1.addWidget(about)

        root.addWidget(about_card, stretch=1)

        # Paths card
        paths_card = QFrame()
        paths_card.setObjectName("Card")
        v2 = QVBoxLayout(paths_card)
        v2.setContentsMargins(16, 14, 16, 14)
        v2.setSpacing(6)

        title2 = QLabel("◆ DATA PATHS")
        title2.setObjectName("CardTitle")
        v2.addWidget(title2)

        db_path = default_db_path()
        log_path = Path.home() / ".portscanner" / "logs" / "scanner.log"

        v2.addWidget(self._kv("History DB", str(db_path)))
        v2.addWidget(self._kv("Log file",   str(log_path)))

        root.addWidget(paths_card)

    def _kv(self, key: str, value: str) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        k = QLabel(key + ":")
        k.setStyleSheet(f"color:{COLORS['text_dim']}; font-weight:bold;")
        k.setMinimumWidth(110)
        v = QLabel(value)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.setStyleSheet(f"color:{COLORS['text_bright']};")
        h.addWidget(k)
        h.addWidget(v, stretch=1)
        return w
