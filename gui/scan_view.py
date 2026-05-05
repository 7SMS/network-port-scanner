"""
Main scan page — input panel, live terminal output, results table, controls.

Threading note: the Scanner class runs probes on its own threads and calls
back via on_result/on_progress/on_log/on_complete. Those callbacks come
from worker threads, NOT the GUI thread. So we route them through Qt signals
which marshal the data back to the GUI thread safely. Don't ever touch
QWidgets from a worker thread — that path is undefined-behavior land.
"""

from __future__ import annotations

import time
from typing import List, Optional

from PyQt6.QtCore import (
    Qt, QObject, pyqtSignal, pyqtSlot, QSortFilterProxyModel, QTimer,
)
from PyQt6.QtGui import QColor, QFont, QTextCursor, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QSpinBox, QDoubleSpinBox, QCheckBox, QProgressBar,
    QPlainTextEdit, QTableWidget, QTableWidgetItem, QFrame, QSplitter,
    QHeaderView, QFileDialog, QMessageBox, QGroupBox, QSizePolicy,
    QInputDialog, QDialog, QDialogButtonBox, QListWidget, QListWidgetItem,
    QTextEdit, QTableView, QAbstractItemView,
)

from ..core.scanner import (
    Scanner, ScanConfig, ScanType, PortResult, PortStatus,
)
from ..core.targets import parse_targets, parse_ports, is_private_ip, TargetParseError
from ..core.profiles import ProfileStore, ScanProfile
from ..core.history import HistoryStore
from ..core import exporters
from ..core import html_report
from .theme import COLORS
from .results_model import ResultsTableModel, ResultsFilterProxy


# --------------------------------------------------------------------------- #
# Signal bridge — marshals worker-thread callbacks onto the GUI thread.        #
# --------------------------------------------------------------------------- #

class _ScanSignals(QObject):
    result_ready = pyqtSignal(object)              # PortResult
    progress = pyqtSignal(int, int)                # done, total
    log_msg = pyqtSignal(str, str)                 # level, msg
    completed = pyqtSignal(list)                   # List[PortResult]


# --------------------------------------------------------------------------- #
# Scan view                                                                    #
# --------------------------------------------------------------------------- #

class ScanView(QWidget):
    """The main scanning page."""

    STATUS_COLORS = {
        "open":          COLORS["open"],
        "closed":        COLORS["closed"],
        "filtered":      COLORS["filtered"],
        "open|filtered": COLORS["filtered"],
        "error":         COLORS["error"],
    }

    def __init__(self, history: HistoryStore, parent=None):
        super().__init__(parent)
        self.history = history
        self.profile_store = ProfileStore()
        self._scanner: Optional[Scanner] = None
        self._signals = _ScanSignals()
        self._scan_started_at: float = 0.0
        self._current_targets_str = ""
        self._current_ports_str = ""

        # Throttle terminal updates — flooding it with 65535 lines lags Qt.
        self._terminal_buffer: list[str] = []
        self._terminal_timer = QTimer(self)
        self._terminal_timer.setInterval(100)  # 10 Hz flush
        self._terminal_timer.timeout.connect(self._flush_terminal)

        self._build_ui()
        self._wire_signals()
        self._install_shortcuts()

    # ---------- UI construction ---------- #

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        # Disclaimer banner — always visible, can't be dismissed.
        disclaimer = QLabel(
            "⚠  AUTHORIZED USE ONLY  —  Scan only systems you own or have "
            "explicit written permission to test. Unauthorized scanning may "
            "violate computer-misuse laws."
        )
        disclaimer.setObjectName("DisclaimerBanner")
        disclaimer.setWordWrap(True)
        root.addWidget(disclaimer)

        # Top: input panel
        root.addWidget(self._build_input_panel())

        # Middle: terminal + results split
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(4)
        splitter.addWidget(self._build_terminal_panel())
        splitter.addWidget(self._build_results_panel())
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([200, 400])
        root.addWidget(splitter, stretch=1)

        # Bottom: progress + actions
        root.addLayout(self._build_progress_row())

    def _build_input_panel(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(10)

        # Title row with profile selector on the right
        title_row = QHBoxLayout()
        title = QLabel("◆ TARGET CONFIGURATION")
        title.setObjectName("CardTitle")
        title_row.addWidget(title)
        title_row.addStretch()

        profile_label = QLabel("PROFILE:")
        profile_label.setObjectName("FieldLabel")
        title_row.addWidget(profile_label)

        self.profile_combo = QComboBox()
        self.profile_combo.setMinimumWidth(220)
        self.profile_combo.activated.connect(self._on_profile_selected)
        title_row.addWidget(self.profile_combo)

        save_profile_btn = QPushButton("Save")
        save_profile_btn.setToolTip("Save current settings as a profile")
        save_profile_btn.clicked.connect(self._on_save_profile)
        title_row.addWidget(save_profile_btn)

        del_profile_btn = QPushButton("Delete")
        del_profile_btn.setToolTip("Delete the selected user profile")
        del_profile_btn.clicked.connect(self._on_delete_profile)
        title_row.addWidget(del_profile_btn)

        outer.addLayout(title_row)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(10)

        # Row 0: targets, ports
        grid.addWidget(self._field_label("TARGET"), 0, 0)
        grid.addWidget(self._field_label("PORTS"), 0, 2)

        self.targets_edit = QLineEdit()
        self.targets_edit.setPlaceholderText(
            "e.g. 192.168.1.1, 10.0.0.0/24, scanme.nmap.org, 10.0.0.1-50"
        )
        self.targets_edit.setText("127.0.0.1")
        grid.addWidget(self.targets_edit, 1, 0, 1, 2)

        self.ports_edit = QLineEdit()
        self.ports_edit.setPlaceholderText("e.g. 1-1024, 3306, 8000-8100")
        self.ports_edit.setText("1-1024")
        grid.addWidget(self.ports_edit, 1, 2, 1, 2)

        # Row 1: scan type, threads, timeout, retries
        grid.addWidget(self._field_label("SCAN TYPE"), 2, 0)
        grid.addWidget(self._field_label("THREADS"), 2, 1)
        grid.addWidget(self._field_label("TIMEOUT (s)"), 2, 2)
        grid.addWidget(self._field_label("RETRIES"), 2, 3)

        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItem("TCP Connect", ScanType.TCP_CONNECT)
        self.scan_type_combo.addItem("SYN (privileged)", ScanType.SYN)
        self.scan_type_combo.addItem("UDP", ScanType.UDP)
        grid.addWidget(self.scan_type_combo, 3, 0)

        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 1000)
        self.threads_spin.setValue(200)
        self.threads_spin.setSingleStep(50)
        grid.addWidget(self.threads_spin, 3, 1)

        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.1, 30.0)
        self.timeout_spin.setSingleStep(0.5)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setDecimals(1)
        grid.addWidget(self.timeout_spin, 3, 2)

        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 5)
        self.retries_spin.setValue(1)
        grid.addWidget(self.retries_spin, 3, 3)

        # Row 2: rate limit + flags
        grid.addWidget(self._field_label("RATE LIMIT (pkts/s, 0=unlimited)"), 4, 0, 1, 2)
        self.rate_spin = QSpinBox()
        self.rate_spin.setRange(0, 100000)
        self.rate_spin.setValue(0)
        self.rate_spin.setSingleStep(100)
        grid.addWidget(self.rate_spin, 5, 0, 1, 2)

        flags_row = QHBoxLayout()
        self.banner_check = QCheckBox("Grab banners")
        self.banner_check.setChecked(True)
        self.os_check = QCheckBox("OS fingerprint (heuristic)")
        flags_row.addWidget(self.banner_check)
        flags_row.addWidget(self.os_check)
        flags_row.addStretch()
        grid.addLayout(flags_row, 5, 2, 1, 2)

        outer.addLayout(grid)
        # Populate the profile dropdown now that all fields exist.
        self._refresh_profiles()
        return card

    def _field_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("FieldLabel")
        return lbl

        lbl = QLabel(text)
        lbl.setObjectName("FieldLabel")
        return lbl

    def _build_terminal_panel(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 14, 16, 14)
        v.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel("◆ LIVE OUTPUT")
        title.setObjectName("CardTitle")
        header.addWidget(title)
        header.addStretch()
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._clear_terminal)
        header.addWidget(clear_btn)
        v.addLayout(header)

        self.terminal = QPlainTextEdit()
        self.terminal.setObjectName("Terminal")
        self.terminal.setReadOnly(True)
        self.terminal.setMaximumBlockCount(5000)  # cap memory
        v.addWidget(self.terminal)
        return card

    def _build_results_panel(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 14, 16, 14)
        v.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel("◆ RESULTS")
        title.setObjectName("CardTitle")
        header.addWidget(title)
        header.addSpacing(20)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter (host, port, service, banner…)")
        self.filter_edit.textChanged.connect(self._apply_filter)
        header.addWidget(self.filter_edit, stretch=1)

        self.show_only_open = QCheckBox("Open only")
        self.show_only_open.toggled.connect(self._apply_filter)
        header.addWidget(self.show_only_open)

        v.addLayout(header)

        # Virtual model + filter proxy — scales to millions of rows.
        self.results_model = ResultsTableModel(self)
        self.results_proxy = ResultsFilterProxy(self)
        self.results_proxy.setSourceModel(self.results_model)

        self.results_table = QTableView()
        self.results_table.setModel(self.results_proxy)
        self.results_table.setSortingEnabled(True)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.results_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.results_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.results_table.doubleClicked.connect(self._show_row_detail)

        hh = self.results_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        hh.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        v.addWidget(self.results_table)

        return card

    def _build_progress_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat("Idle")
        row.addWidget(self.progress, stretch=1)

        self.start_btn = QPushButton("▶  START SCAN")
        self.start_btn.setObjectName("PrimaryButton")
        self.start_btn.setMinimumWidth(140)
        self.start_btn.clicked.connect(self._on_start_clicked)
        row.addWidget(self.start_btn)

        self.stop_btn = QPushButton("■  STOP")
        self.stop_btn.setObjectName("DangerButton")
        self.stop_btn.setMinimumWidth(100)
        self.stop_btn.clicked.connect(self._on_stop_clicked)
        self.stop_btn.setEnabled(False)
        row.addWidget(self.stop_btn)

        self.export_btn = QPushButton("⇩  EXPORT")
        self.export_btn.setMinimumWidth(110)
        self.export_btn.clicked.connect(self._on_export_clicked)
        self.export_btn.setEnabled(False)
        row.addWidget(self.export_btn)

        return row

    # ---------- signal wiring ---------- #

    def _wire_signals(self) -> None:
        self._signals.result_ready.connect(self._on_result_ready)
        self._signals.progress.connect(self._on_progress)
        self._signals.log_msg.connect(self._append_log)
        self._signals.completed.connect(self._on_completed)

    # ---------- keyboard shortcuts ---------- #

    def _install_shortcuts(self) -> None:
        """
        Wire common keyboard shortcuts. We use QShortcut on `self` (the page)
        so they work whenever the scan view has focus, without needing a menu
        bar. Shortcuts are documented in the About page.
        """
        # Run scan
        QShortcut(QKeySequence("Ctrl+R"), self,
                  activated=self._shortcut_run).setContext(
                      Qt.ShortcutContext.WidgetWithChildrenShortcut)
        QShortcut(QKeySequence("F5"), self,
                  activated=self._shortcut_run).setContext(
                      Qt.ShortcutContext.WidgetWithChildrenShortcut)
        # Stop
        QShortcut(QKeySequence("Ctrl+E"), self,
                  activated=self._shortcut_stop).setContext(
                      Qt.ShortcutContext.WidgetWithChildrenShortcut)
        QShortcut(QKeySequence("Escape"), self,
                  activated=self._shortcut_stop).setContext(
                      Qt.ShortcutContext.WidgetWithChildrenShortcut)
        # Export
        QShortcut(QKeySequence("Ctrl+S"), self,
                  activated=self._shortcut_export).setContext(
                      Qt.ShortcutContext.WidgetWithChildrenShortcut)
        # Focus targets / ports / filter
        QShortcut(QKeySequence("Ctrl+L"), self,
                  activated=lambda: self.targets_edit.setFocus()).setContext(
                      Qt.ShortcutContext.WidgetWithChildrenShortcut)
        QShortcut(QKeySequence("Ctrl+P"), self,
                  activated=lambda: self.ports_edit.setFocus()).setContext(
                      Qt.ShortcutContext.WidgetWithChildrenShortcut)
        QShortcut(QKeySequence("Ctrl+F"), self,
                  activated=lambda: self.filter_edit.setFocus()).setContext(
                      Qt.ShortcutContext.WidgetWithChildrenShortcut)
        # Clear terminal
        QShortcut(QKeySequence("Ctrl+K"), self,
                  activated=self._clear_terminal).setContext(
                      Qt.ShortcutContext.WidgetWithChildrenShortcut)

    def _shortcut_run(self) -> None:
        if self.start_btn.isEnabled():
            self._on_start_clicked()

    def _shortcut_stop(self) -> None:
        if self.stop_btn.isEnabled():
            self._on_stop_clicked()

    def _shortcut_export(self) -> None:
        if self.export_btn.isEnabled():
            self._on_export_clicked()

    # ---------- profiles ---------- #

    def _refresh_profiles(self) -> None:
        """Reload profile dropdown. Built-ins shown with [BI] prefix."""
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.profile_combo.addItem("— Custom (no profile) —", None)
        for p in self.profile_store.list_all():
            label = ("[★] " if p.builtin else "") + p.name
            self.profile_combo.addItem(label, p.name)
        self.profile_combo.setCurrentIndex(0)
        self.profile_combo.blockSignals(False)

    def _on_profile_selected(self, idx: int) -> None:
        name = self.profile_combo.itemData(idx)
        if not name:
            return
        prof = self.profile_store.get(name)
        if not prof:
            return
        self._apply_profile(prof)

    def _apply_profile(self, prof: ScanProfile) -> None:
        """Populate the form fields from a profile."""
        if prof.targets:
            self.targets_edit.setText(prof.targets)
        if prof.ports:
            self.ports_edit.setText(prof.ports)
        # Map scan_type string to enum
        for i in range(self.scan_type_combo.count()):
            if self.scan_type_combo.itemData(i).value == prof.scan_type:
                self.scan_type_combo.setCurrentIndex(i)
                break
        self.threads_spin.setValue(prof.threads)
        self.timeout_spin.setValue(prof.timeout)
        self.retries_spin.setValue(prof.retries)
        self.banner_check.setChecked(prof.grab_banners)
        self.os_check.setChecked(prof.detect_os)
        self.rate_spin.setValue(prof.rate_limit_pps)

    def _on_save_profile(self) -> None:
        """Save current form state as a new (or updated) profile."""
        name, ok = QInputDialog.getText(
            self, "Save Profile",
            "Profile name:",
            QLineEdit.EchoMode.Normal,
            "",
        )
        if not ok or not name.strip():
            return
        name = name.strip()
        if self.profile_store.exists(name):
            # Could be built-in (refuse) or user (overwrite).
            existing = self.profile_store.get(name)
            if existing and existing.builtin:
                QMessageBox.warning(
                    self, "Cannot overwrite",
                    f"'{name}' is a built-in profile and cannot be overwritten.\n"
                    "Choose a different name.",
                )
                return
            ans = QMessageBox.question(
                self, "Overwrite profile?",
                f"A profile named '{name}' already exists. Overwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

        prof = ScanProfile(
            name=name,
            description="User-saved profile",
            targets=self.targets_edit.text(),
            ports=self.ports_edit.text(),
            scan_type=self.scan_type_combo.currentData().value,
            threads=self.threads_spin.value(),
            timeout=self.timeout_spin.value(),
            retries=self.retries_spin.value(),
            grab_banners=self.banner_check.isChecked(),
            rate_limit_pps=self.rate_spin.value(),
            detect_os=self.os_check.isChecked(),
            builtin=False,
        )
        if self.profile_store.save(prof):
            self._refresh_profiles()
            # Select the just-saved profile
            for i in range(self.profile_combo.count()):
                if self.profile_combo.itemData(i) == name:
                    self.profile_combo.setCurrentIndex(i)
                    break
            self._append_terminal_line("system", f"Profile saved: {name}")
        else:
            QMessageBox.warning(self, "Save failed",
                                "Could not save profile (name conflict?).")

    def _on_delete_profile(self) -> None:
        idx = self.profile_combo.currentIndex()
        name = self.profile_combo.itemData(idx)
        if not name:
            QMessageBox.information(
                self, "Nothing to delete",
                "Select a user profile first.",
            )
            return
        existing = self.profile_store.get(name)
        if existing and existing.builtin:
            QMessageBox.information(
                self, "Built-in profile",
                "Built-in profiles can't be deleted.",
            )
            return
        ans = QMessageBox.question(
            self, "Delete profile",
            f"Delete profile '{name}'? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if ans != QMessageBox.StandardButton.Yes:
            return
        if self.profile_store.delete(name):
            self._refresh_profiles()
            self._append_terminal_line("system", f"Profile deleted: {name}")

    # ---------- start / stop ---------- #

    def _on_start_clicked(self) -> None:
        # Parse + validate
        try:
            targets = parse_targets(self.targets_edit.text())
            ports = parse_ports(self.ports_edit.text())
        except TargetParseError as e:
            QMessageBox.critical(self, "Invalid input", str(e))
            return

        # External-target warning — only nag once per session per target set.
        external = [t for t in targets if not is_private_ip(t)]
        if external:
            sample = ", ".join(external[:3]) + ("…" if len(external) > 3 else "")
            ans = QMessageBox.warning(
                self,
                "Scanning external targets",
                f"You are about to scan {len(external)} non-private "
                f"address(es) ({sample}).\n\n"
                "Scanning systems without authorization is illegal in most "
                "jurisdictions. Are you certain you have permission?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if ans != QMessageBox.StandardButton.Yes:
                return

        cfg = ScanConfig(
            targets=targets,
            ports=ports,
            scan_type=self.scan_type_combo.currentData(),
            timeout=self.timeout_spin.value(),
            threads=self.threads_spin.value(),
            retries=self.retries_spin.value(),
            grab_banners=self.banner_check.isChecked(),
            rate_limit_pps=self.rate_spin.value(),
            detect_os=self.os_check.isChecked(),
        )

        # Reset UI state
        self.results_table.setSortingEnabled(False)
        self.results_model.clear()
        self._last_results = []
        self._clear_terminal()
        self.progress.setValue(0)
        self.progress.setFormat("Starting…")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)

        # Save context for history
        self._current_targets_str = self.targets_edit.text()
        self._current_ports_str = self.ports_edit.text()
        self._scan_started_at = time.time()

        # Build and launch
        self._scanner = Scanner(
            cfg,
            on_result=self._signals.result_ready.emit,
            on_progress=self._signals.progress.emit,
            on_log=self._signals.log_msg.emit,
            on_complete=self._signals.completed.emit,
        )
        self._terminal_timer.start()
        self._scanner.start()

    def _on_stop_clicked(self) -> None:
        if self._scanner and self._scanner.is_running():
            self._scanner.stop()
            self.stop_btn.setEnabled(False)
            self.progress.setFormat("Stopping…")

    # ---------- streaming callbacks (GUI thread) ---------- #

    @pyqtSlot(object)
    def _on_result_ready(self, result: PortResult) -> None:
        # Only put "interesting" results in the table to keep it usable
        # when scanning 65k ports. Closed ports go to the count, not the table.
        status = result.status.value
        if status in ("open", "open|filtered"):
            self._append_result_row(result)
            self._buffer_log(
                "info",
                f"[+] {result.host}:{result.port}/{result.protocol} "
                f"{status.upper()} — {result.service}"
                + (f" — {result.banner}" if result.banner else "")
            )
        elif status == "error":
            self._buffer_log(
                "error",
                f"[!] {result.host}:{result.port}/{result.protocol} "
                f"ERROR — {result.error}"
            )
        # closed/filtered are silent in the terminal — too noisy otherwise.

    @pyqtSlot(int, int)
    def _on_progress(self, done: int, total: int) -> None:
        if total <= 0:
            return
        pct = int(done * 100 / total)
        self.progress.setValue(pct)
        self.progress.setFormat(f"Scanning… {done}/{total} ({pct}%)")

    @pyqtSlot(str, str)
    def _append_log(self, level: str, msg: str) -> None:
        self._buffer_log(level, msg)

    @pyqtSlot(list)
    def _on_completed(self, results: list) -> None:
        self._terminal_timer.stop()
        self._flush_terminal()  # ensure last lines land

        elapsed = time.time() - self._scan_started_at
        open_count = sum(1 for r in results
                         if r.status.value in ("open", "open|filtered"))

        self._append_terminal_line(
            "system",
            f"\n══════ Scan complete: {len(results)} probes, "
            f"{open_count} open, {elapsed:.2f}s ══════\n",
        )

        self.progress.setFormat(f"Done — {open_count} open / {len(results)} probes "
                                f"in {elapsed:.2f}s")
        self.progress.setValue(100)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(bool(results))
        self.results_table.setSortingEnabled(True)

        # Cache the full results list — model only holds open results, but
        # exports may want everything (closed/filtered counts in JSON, etc).
        self._last_results = list(results)

        # Persist
        if results:
            try:
                self.history.save_scan(
                    started_at=self._scan_started_at,
                    finished_at=time.time(),
                    targets=self._current_targets_str,
                    ports=self._current_ports_str,
                    scan_type=self._scanner.config.scan_type.value if self._scanner else "",
                    results=results,
                )
            except Exception as e:  # noqa: BLE001
                self._append_terminal_line("error", f"Failed to save history: {e}")

    # ---------- terminal helpers ---------- #

    def _buffer_log(self, level: str, msg: str) -> None:
        self._terminal_buffer.append(f"{level.upper()}|{msg}")

    def _flush_terminal(self) -> None:
        if not self._terminal_buffer:
            return
        # Render in one batch — way faster than per-line appends.
        for entry in self._terminal_buffer:
            level, _, msg = entry.partition("|")
            self._append_terminal_line(level.lower(), msg)
        self._terminal_buffer.clear()

    def _append_terminal_line(self, level: str, msg: str) -> None:
        color = {
            "info":    COLORS["text"],
            "warning": COLORS["warn"],
            "error":   COLORS["error"],
            "system":  COLORS["accent"],
        }.get(level, COLORS["text"])
        ts = time.strftime("%H:%M:%S")
        # Use HTML for color; QPlainTextEdit doesn't support it natively, so
        # use appendHtml on a QTextEdit-like fallback — switch to QTextEdit.
        # Workaround: prepend ANSI-style label, color via stylesheet selection.
        # Simplest: just append with a colored prefix using inline HTML via
        # appendHtml. QPlainTextEdit doesn't have appendHtml, so use
        # appendPlainText for body and rely on terminal-style monochrome output.
        # We *do* color the line via a small trick: keep the log monochrome,
        # use [+] / [!] / [*] markers users will recognize.
        marker = {"info": "[*]", "warning": "[!]", "error": "[X]",
                  "system": "[#]"}.get(level, "[*]")
        # Drop already-prefixed markers from result lines (they have their own).
        prefix = "" if msg.lstrip().startswith(("[+]", "[!]", "[*]", "[X]", "[#]")) \
                 else f"{marker} "
        line = f"[{ts}] {prefix}{msg}"
        self.terminal.appendPlainText(line)
        # Auto-scroll
        self.terminal.moveCursor(QTextCursor.MoveOperation.End)

    def _clear_terminal(self) -> None:
        self.terminal.clear()

    # ---------- results table ---------- #

    def _append_result_row(self, r: PortResult) -> None:
        """Append a result via the virtual model. O(1)."""
        self.results_model.append_result(r)

    def _apply_filter(self) -> None:
        """Refresh proxy filter from current text + open-only state."""
        self.results_proxy.set_search_text(self.filter_edit.text())
        self.results_proxy.set_open_only(self.show_only_open.isChecked())

    def _show_row_detail(self, proxy_index) -> None:
        """Double-click handler: show details for the selected row."""
        if not proxy_index.isValid():
            return
        # Map proxy index -> source model index, then look up the result.
        src_index = self.results_proxy.mapToSource(proxy_index)
        r = self.results_model.result_at(src_index.row())
        if r is None:
            return
        data = r.to_dict()
        # Build a readable dialog
        lines = [f"<b style='color:{COLORS['accent']}'>"
                 f"{data.get('host')}:{data.get('port')}/"
                 f"{data.get('protocol','tcp').upper()}</b><br><br>"]
        for k, v in data.items():
            if v in (None, "", 0):
                continue
            lines.append(f"<b>{k}:</b> {v}<br>")
        QMessageBox.information(self, "Port Details", "".join(lines))

    # ---------- export ---------- #

    def _on_export_clicked(self) -> None:
        # Pull from the table, not the scanner — that way filtered/sorted
        # state is preserved if the user wants. Actually, export ALL rows
        # (visible or not) — filtering is for viewing, not data destruction.
        results = self._collect_all_results_from_table()
        if not results:
            return

        path, fmt = QFileDialog.getSaveFileName(
            self, "Export results", "scan_results",
            "HTML Report (*.html);;JSON (*.json);;CSV (*.csv);;Text (*.txt)",
        )
        if not path:
            return

        try:
            lower = path.lower()
            if lower.endswith(".html") or "HTML" in fmt:
                if not lower.endswith(".html"):
                    path += ".html"
                # Calculate elapsed time from saved scan start.
                import time as _time
                elapsed = (_time.time() - self._scan_started_at
                           if self._scan_started_at else 0.0)
                scan_type_str = (self._scanner.config.scan_type.value
                                 if self._scanner else "")
                html_report.export_html(
                    results, path,
                    title="Port Scan Report",
                    targets=self._current_targets_str,
                    ports=self._current_ports_str,
                    scan_type=scan_type_str,
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
            self._append_terminal_line("system", f"Exported to {path}")
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Export failed", str(e))

    def _collect_all_results_from_table(self) -> List[PortResult]:
        """Source of truth for export: prefer full result list (incl. closed),
        fall back to model contents (open only) if scan still in progress."""
        full = getattr(self, "_last_results", None)
        if full:
            return list(full)
        return self.results_model.all_results()
