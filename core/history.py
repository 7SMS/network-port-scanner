"""
Scan history — stored in a SQLite DB in the user's app dir.

Why SQLite and not JSON files? Because we want filtering/searching across
runs, and SQLite gives us that for free. Also handles concurrent access.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .scanner import PortResult


def default_db_path() -> Path:
    home = Path.home() / ".portscanner"
    home.mkdir(parents=True, exist_ok=True)
    return home / "history.db"


@dataclass
class ScanRecord:
    id: int
    started_at: float
    finished_at: float
    targets: str
    ports: str
    scan_type: str
    open_count: int
    total_probes: int
    results_json: str  # serialized list of PortResult dicts


class HistoryStore:
    """Thread-safe history store — single connection guarded by a lock."""

    def __init__(self, db_path: Optional[Path] = None):
        self.path = db_path or default_db_path()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at    REAL    NOT NULL,
                    finished_at   REAL    NOT NULL,
                    targets       TEXT    NOT NULL,
                    ports         TEXT    NOT NULL,
                    scan_type     TEXT    NOT NULL,
                    open_count    INTEGER NOT NULL,
                    total_probes  INTEGER NOT NULL,
                    results_json  TEXT    NOT NULL
                )
            """)
            self._conn.commit()

    def save_scan(
        self,
        started_at: float,
        finished_at: float,
        targets: str,
        ports: str,
        scan_type: str,
        results: List[PortResult],
    ) -> int:
        open_count = sum(1 for r in results
                         if r.status.value in ("open", "open|filtered"))
        results_json = json.dumps([r.to_dict() for r in results])
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO scans
                   (started_at, finished_at, targets, ports, scan_type,
                    open_count, total_probes, results_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (started_at, finished_at, targets, ports, scan_type,
                 open_count, len(results), results_json),
            )
            self._conn.commit()
            return cur.lastrowid

    def list_scans(self, limit: int = 100) -> List[ScanRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def get_scan(self, scan_id: int) -> Optional[ScanRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def delete_scan(self, scan_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            self._conn.commit()

    def clear_all(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM scans")
            self._conn.commit()

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ScanRecord:
        return ScanRecord(
            id=row["id"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            targets=row["targets"],
            ports=row["ports"],
            scan_type=row["scan_type"],
            open_count=row["open_count"],
            total_probes=row["total_probes"],
            results_json=row["results_json"],
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
