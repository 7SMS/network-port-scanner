"""
Results table model — Qt model/view architecture for scalable result display.

Why this exists: the previous implementation used QTableWidget which creates
a QTableWidgetItem per cell. For a /16 × 100 ports = 6.5M cells, that's
650MB+ of widget objects — Qt freezes long before that.

QAbstractTableModel + QTableView only renders visible rows. We can hold
millions of results in memory (a list of PortResult objects) without lag.

Filtering: we use a QSortFilterProxyModel on top, with a custom filter
function that checks the "Open only" toggle and the text filter together.

Cancellation-safe: append_result() is called from the GUI thread (via
the signal bridge), so no locking needed on the underlying list.
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import (
    Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QVariant,
)
from PyQt6.QtGui import QColor, QFont

from ..core.scanner import PortResult
from .theme import COLORS


_COLUMN_TITLES = ["Host", "Port", "Proto", "Status", "Service", "Version", "Banner"]
_COL_HOST, _COL_PORT, _COL_PROTO, _COL_STATUS, _COL_SERVICE, _COL_VERSION, _COL_BANNER = range(7)


class ResultsTableModel(QAbstractTableModel):
    """A live-appendable, sortable, filterable model of PortResults."""

    STATUS_COLORS = {
        "open":          COLORS["open"],
        "closed":        COLORS["closed"],
        "filtered":      COLORS["filtered"],
        "open|filtered": COLORS["filtered"],
        "error":         COLORS["error"],
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: list[PortResult] = []

    # ---- model state ---- #

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def append_result(self, r: PortResult) -> None:
        """Append a single result. O(1). Triggers a single-row insert."""
        row = len(self._rows)
        self.beginInsertRows(QModelIndex(), row, row)
        self._rows.append(r)
        self.endInsertRows()

    def all_results(self) -> list[PortResult]:
        return list(self._rows)

    def result_at(self, row: int) -> Optional[PortResult]:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    # ---- required Qt model API ---- #

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(_COLUMN_TITLES)

    def headerData(self, section: int,
                   orientation: Qt.Orientation,
                   role: int = Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return QVariant()
        if orientation == Qt.Orientation.Horizontal:
            if 0 <= section < len(_COLUMN_TITLES):
                return _COLUMN_TITLES[section]
        return QVariant()

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return QVariant()
        row = index.row()
        col = index.column()
        if not (0 <= row < len(self._rows)):
            return QVariant()
        r = self._rows[row]

        if role == Qt.ItemDataRole.DisplayRole:
            if col == _COL_HOST:    return r.host
            if col == _COL_PORT:    return r.port  # int — Qt displays as text but sorts numerically
            if col == _COL_PROTO:   return r.protocol.upper()
            if col == _COL_STATUS:  return r.status.value.upper()
            if col == _COL_SERVICE: return r.service
            if col == _COL_VERSION: return r.version_string or "—"
            if col == _COL_BANNER:  return r.banner or ""

        if role == Qt.ItemDataRole.ForegroundRole:
            if col == _COL_STATUS:
                return QColor(self.STATUS_COLORS.get(
                    r.status.value, COLORS["text"]))
            if col == _COL_VERSION:
                if r.version_string:
                    return QColor(COLORS["accent"])
                return QColor(COLORS["text_dim"])
            # All other columns: use the standard text color explicitly.
            # If we don't return a color here, Qt may fall back to the system
            # palette, which on light-mode desktops produces black text on
            # alternating rows that ignore our QSS.
            return QColor(COLORS["text"])

        if role == Qt.ItemDataRole.BackgroundRole:
            # Belt-and-braces: enforce dark backgrounds even when the QSS
            # alternate-row rule is overridden by the platform style.
            # Even rows -> bg_alt, odd rows -> a slightly darker shade.
            if row % 2 == 0:
                return QColor(COLORS["bg_alt"])
            else:
                return QColor("#0d1219")

        if role == Qt.ItemDataRole.FontRole:
            if col == _COL_STATUS:
                f = QFont()
                f.setBold(True)
                return f

        if role == Qt.ItemDataRole.UserRole:
            # Used by detail dialog & export
            return r.to_dict()

        if role == Qt.ItemDataRole.ToolTipRole:
            if col == _COL_BANNER and r.banner:
                # Full banner in tooltip if it's truncated in display.
                return r.banner

        return QVariant()


class ResultsFilterProxy(QSortFilterProxyModel):
    """Filters by free text + 'open only' flag, sorts numerically by port."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._search_text = ""
        self._open_only = False
        # Filter every row, every column — we do the matching ourselves.
        self.setFilterKeyColumn(-1)

    def set_search_text(self, text: str) -> None:
        self._search_text = text.lower().strip()
        self.invalidateFilter()

    def set_open_only(self, on: bool) -> None:
        self._open_only = on
        self.invalidateFilter()

    # ---- filter ---- #

    def filterAcceptsRow(self, source_row: int, parent: QModelIndex) -> bool:
        model: ResultsTableModel = self.sourceModel()  # type: ignore[assignment]
        r = model.result_at(source_row)
        if r is None:
            return False

        if self._open_only and r.status.value not in ("open", "open|filtered"):
            return False

        if self._search_text:
            haystack = " ".join([
                r.host,
                str(r.port),
                r.protocol,
                r.status.value,
                r.service,
                r.version_string,
                r.banner or "",
            ]).lower()
            if self._search_text not in haystack:
                return False

        return True

    # ---- sort: ensure port column sorts numerically ---- #

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        model: ResultsTableModel = self.sourceModel()  # type: ignore[assignment]
        col = left.column()
        l_r = model.result_at(left.row())
        r_r = model.result_at(right.row())
        if l_r is None or r_r is None:
            return False
        if col == _COL_PORT:
            return l_r.port < r_r.port
        # Default: string compare on display value
        ld = model.data(left, Qt.ItemDataRole.DisplayRole)
        rd = model.data(right, Qt.ItemDataRole.DisplayRole)
        return str(ld) < str(rd)
