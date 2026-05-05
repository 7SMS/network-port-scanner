"""
History view — list past scans, view details, delete entries.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QFrame, QMessageBox, QFileDialog,
)

from ..core.history import HistoryStore, ScanRecord
from ..core import exporters
from ..core import html_report
from ..core.scanner import PortResult, PortStatus
from .theme import COLORS


class HistoryView(QWidget):
    """Browse past scan runs."""

    def __init__(self, history: HistoryStore, parent=None):
        super().__init__(parent)
        self.history = history
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        # Header card
        card = QFrame()
        card.setObjectName("Card")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 14, 16, 14)
        v.setSpacing(8)

        head = QHBoxLayout()
        title = QLabel("◆ SCAN HISTORY")
        title.setObjectName("CardTitle")
        head.addWidget(title)
        head.addStretch()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        head.addWidget(refresh_btn)

        export_btn = QPushButton("Export selected")
        export_btn.clicked.connect(self._export_selected)
        head.addWidget(export_btn)

        delete_btn = QPushButton("Delete selected")
        delete_btn.setObjectName("DangerButton")
        delete_btn.clicked.connect(self._delete_selected)
        head.addWidget(delete_btn)

        clear_btn = QPushButton("Clear all")
        clear_btn.setObjectName("DangerButton")
        clear_btn.clicked.connect(self._clear_all)
        head.addWidget(clear_btn)

        v.addLayout(head)

        # Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["When", "Targets", "Ports", "Type", "Open", "Total"]
        )
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.itemDoubleClicked.connect(self._show_detail)
        v.addWidget(self.table)

        root.addWidget(card)

    # ---------- ops ---------- #

    def refresh(self) -> None:
        self.table.setRowCount(0)
        records = self.history.list_scans(limit=500)
        for rec in records:
            self._append_record(rec)

    def _append_record(self, rec: ScanRecord) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        when = datetime.fromtimestamp(rec.started_at).strftime("%Y-%m-%d %H:%M:%S")
        items = [
            QTableWidgetItem(when),
            QTableWidgetItem(rec.targets[:80]),
            QTableWidgetItem(rec.ports[:40]),
            QTableWidgetItem(rec.scan_type),
            QTableWidgetItem(str(rec.open_count)),
            QTableWidgetItem(str(rec.total_probes)),
        ]
        items[0].setData(Qt.ItemDataRole.UserRole, rec.id)
        for col, it in enumerate(items):
            self.table.setItem(row, col, it)

    def _selected_id(self) -> Optional[int]:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self.table.item(rows[0].row(), 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _show_detail(self, _item) -> None:
        scan_id = self._selected_id()
        if scan_id is None:
            return
        rec = self.history.get_scan(scan_id)
        if not rec:
            return
        try:
            results = json.loads(rec.results_json)
        except json.JSONDecodeError:
            results = []
        open_results = [r for r in results
                        if r.get("status") in ("open", "open|filtered")]
        lines = [f"<b style='color:{COLORS['accent']}'>Scan #{rec.id}</b><br>",
                 f"Targets: {rec.targets}<br>",
                 f"Ports: {rec.ports}<br>",
                 f"Type: {rec.scan_type}<br>",
                 f"Open: {rec.open_count} / {rec.total_probes}<br><br>"]
        if open_results:
            lines.append("<b>Open ports:</b><br>")
            for r in open_results[:50]:
                lines.append(
                    f"&nbsp;&nbsp;{r['host']}:{r['port']}/{r['protocol']} "
                    f"— {r.get('service','?')} {r.get('banner','')}<br>"
                )
            if len(open_results) > 50:
                lines.append(f"<i>...and {len(open_results) - 50} more</i><br>")
        else:
            lines.append("<i>No open ports.</i>")
        QMessageBox.information(self, f"Scan #{rec.id}", "".join(lines))

    def _delete_selected(self) -> None:
        scan_id = self._selected_id()
        if scan_id is None:
            return
        ans = QMessageBox.question(
            self, "Delete scan",
            f"Delete scan #{scan_id}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if ans == QMessageBox.StandardButton.Yes:
            self.history.delete_scan(scan_id)
            self.refresh()

    def _clear_all(self) -> None:
        ans = QMessageBox.question(
            self, "Clear history",
            "Delete ALL scan history? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if ans == QMessageBox.StandardButton.Yes:
            self.history.clear_all()
            self.refresh()

    def _export_selected(self) -> None:
        scan_id = self._selected_id()
        if scan_id is None:
            QMessageBox.information(self, "Export", "Select a scan first.")
            return
        rec = self.history.get_scan(scan_id)
        if not rec:
            return
        try:
            raw = json.loads(rec.results_json)
        except json.JSONDecodeError:
            raw = []

        # Reconstruct PortResult-ish objects for export.
        # We use a lightweight shim because exporters call .to_dict() and
        # access .status.value / .banner / etc.
        results = [_DictResult(d) for d in raw]

        path, fmt = QFileDialog.getSaveFileName(
            self, "Export scan", f"scan_{rec.id}",
            "HTML Report (*.html);;JSON (*.json);;CSV (*.csv);;Text (*.txt)",
        )
        if not path:
            return
        try:
            lower = path.lower()
            if lower.endswith(".html") or "HTML" in fmt:
                if not lower.endswith(".html"):
                    path += ".html"
                elapsed = max(0.0, rec.finished_at - rec.started_at)
                html_report.export_html(
                    results, path,
                    title=f"Port Scan Report — #{rec.id}",
                    targets=rec.targets,
                    ports=rec.ports,
                    scan_type=rec.scan_type,
                    elapsed_seconds=elapsed,
                )
            elif lower.endswith(".json") or "JSON" in fmt:
                if not lower.endswith(".json"):
                    path += ".json"
                exporters.export_json(results, path)
            elif lower.endswith(".csv") or "CSV" in fmt:
                if not lower.endswith(".csv"):
                    path += ".csv"
                exporters.export_csv(results, path)
            else:
                if not lower.endswith(".txt"):
                    path += ".txt"
                exporters.export_txt(results, path)
            QMessageBox.information(self, "Export", f"Saved to {path}")
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Export failed", str(e))


class _DictResult:
    """Adapter: makes a dict look enough like PortResult for the exporters."""

    class _StatusShim:
        def __init__(self, value): self.value = value

    def __init__(self, d: dict):
        self._d = d
        self.host = d.get("host", "")
        self.port = d.get("port", 0)
        self.protocol = d.get("protocol", "tcp")
        self.status = self._StatusShim(d.get("status", "unknown"))
        self.service = d.get("service", "unknown")
        self.banner = d.get("banner", "")
        self.latency_ms = d.get("latency_ms", 0.0)
        self.error = d.get("error", "")
        self.timestamp = d.get("timestamp", time.time())
        # Version fields (newer scans). Older scans default these to "".
        self.product = d.get("product", "")
        self.version = d.get("version", "")
        self.version_extra = d.get("version_extra", "")
        self.version_confidence = d.get("version_confidence", "")

    @property
    def version_string(self) -> str:
        if not self.product:
            return ""
        parts = [self.product]
        if self.version:
            parts.append(self.version)
        s = " ".join(parts)
        if self.version_extra:
            s += f" ({self.version_extra})"
        return s

    def to_dict(self) -> dict:
        return dict(self._d)
