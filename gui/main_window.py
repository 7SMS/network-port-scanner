"""
MainWindow — sidebar nav + stacked content area.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton,
    QStackedWidget, QFrame, QButtonGroup, QStatusBar, QSpacerItem, QSizePolicy,
)

from ..core.history import HistoryStore
from .scan_view import ScanView
from .history_view import HistoryView
from .settings_view import SettingsView
from .theme import STYLESHEET, COLORS


def _resolve_icon_path() -> str:
    """
    Locate the bundled application icon. Returns an empty string if no
    icon file is present — never raises. We try .ico first (best on
    Windows), then .png (works everywhere), then .svg (last resort).
    """
    from pathlib import Path
    # Walk up from this file to the package root, then into resources/.
    pkg_root = Path(__file__).resolve().parent.parent
    res_dir = pkg_root / "resources"
    if not res_dir.is_dir():
        return ""
    for name in ("icon_shield.ico", "icon_shield_256.png", "icon_shield.svg",
                 "icon_7sm.ico", "icon_7sm_256.png", "icon_7sm.svg"):
        candidate = res_dir / name
        if candidate.exists():
            return str(candidate)
    return ""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Port Scanner   Cybersecurity Toolkit")
        self.resize(1280, 820)
        self.setMinimumSize(1024, 700)
        self.setStyleSheet(STYLESHEET)

        # Window icon — shows in title bar (left edge), taskbar, and alt-tab.
        # Falls back silently if the icon file is missing.
        icon_path = _resolve_icon_path()
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))

        self.history_store = HistoryStore()
        self._dark_titlebar_applied = False

        self._build_ui()

    def showEvent(self, event):
        """Apply dark titlebar on first show — needs HWND to exist."""
        super().showEvent(event)
        if not self._dark_titlebar_applied:
            # Lazy import: this module is platform-specific and may no-op
            # silently on non-Windows systems.
            from ..utils.platform_window import apply_dark_titlebar
            apply_dark_titlebar(self)
            self._dark_titlebar_applied = True

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Sidebar
        sidebar = self._build_sidebar()
        layout.addWidget(sidebar)

        # Content stack
        self.stack = QStackedWidget()
        self.scan_view = ScanView(self.history_store)
        self.history_view = HistoryView(self.history_store)
        self.settings_view = SettingsView()

        self.stack.addWidget(self.scan_view)
        self.stack.addWidget(self.history_view)
        self.stack.addWidget(self.settings_view)
        layout.addWidget(self.stack, stretch=1)

        # Status bar
        sb = QStatusBar()
        sb.showMessage("Ready  •  Authorized testing only  •  Developed by 7SM")
        self.setStatusBar(sb)

        # Default page
        self.scan_btn.setChecked(True)
        self.stack.setCurrentIndex(0)

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(200)
        v = QVBoxLayout(sidebar)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        title = QLabel("◢ PORTSCAN")
        title.setObjectName("SidebarTitle")
        v.addWidget(title)

        subtitle = QLabel("CYBER TOOLKIT v1.0")
        subtitle.setObjectName("SidebarSubtitle")
        v.addWidget(subtitle)

        # Developer signature
        sig = QLabel("by 7SM")
        sig.setObjectName("DevSignature")
        v.addWidget(sig)

        # Nav buttons
        self.scan_btn = self._nav_button("⚡  SCAN")
        self.history_btn = self._nav_button("◷  HISTORY")
        self.settings_btn = self._nav_button("⚙  ABOUT")

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_group.addButton(self.scan_btn, 0)
        self.nav_group.addButton(self.history_btn, 1)
        self.nav_group.addButton(self.settings_btn, 2)
        self.nav_group.idClicked.connect(self._on_nav_clicked)

        v.addWidget(self.scan_btn)
        v.addWidget(self.history_btn)
        v.addWidget(self.settings_btn)

        v.addStretch()

        # Footer
        footer = QLabel("AUTHORIZED USE ONLY\n— 7SM —")
        footer.setStyleSheet(
            f"color:{COLORS['warn']}; font-size:9px; padding:12px; "
            f"letter-spacing:2px; background:transparent;"
        )
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(footer)

        return sidebar

    def _nav_button(self, text: str) -> QPushButton:
        b = QPushButton(text)
        b.setObjectName("NavButton")
        b.setCheckable(True)
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        return b

    def _on_nav_clicked(self, idx: int) -> None:
        self.stack.setCurrentIndex(idx)
        if idx == 1:  # History — refresh on entry
            self.history_view.refresh()

    def closeEvent(self, event) -> None:
        # Stop any running scan cleanly.
        if self.scan_view._scanner and self.scan_view._scanner.is_running():
            self.scan_view._scanner.stop()
        try:
            self.history_store.close()
        except Exception:  # noqa: BLE001
            pass
        super().closeEvent(event)
