from __future__ import annotations

from datetime import datetime
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Any

import pandas as pd


DEFAULT_DB_PATH = Path(__file__).resolve().parent / "traffic_history.db"


class TrafficDatabase:
    """Thread-safe SQLite storage for captured packet metadata and security alerts."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._lock = Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    time_str TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    source_port TEXT NOT NULL,
                    destination_port TEXT NOT NULL,
                    source_mac TEXT NOT NULL,
                    destination_mac TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
                CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
                CREATE INDEX IF NOT EXISTS idx_packets_source_ip ON packets(source_ip);

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    time_str TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    details TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                """
            )

    def insert_packet(self, record: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO packets (
                    timestamp, time_str, source_ip, destination_ip, protocol,
                    source_port, destination_port, source_mac, destination_mac,
                    direction, size_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    float(record["Timestamp"]),
                    str(record["Time"]),
                    str(record["Source"]),
                    str(record["Destination"]),
                    str(record["Protocol"]),
                    str(record["Source Port"]),
                    str(record["Destination Port"]),
                    str(record["Source MAC"]),
                    str(record["Destination MAC"]),
                    str(record["Direction"]),
                    int(record["Size"]),
                ),
            )

    def insert_alert(self, alert: dict[str, Any], timestamp: float | None = None) -> None:
        ts = float(timestamp) if timestamp is not None else datetime.now().timestamp()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO alerts (
                    timestamp, time_str, severity, alert_type,
                    source_ip, destination_ip, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    str(alert["Time"]),
                    str(alert["Severity"]),
                    str(alert["Type"]),
                    str(alert["Source"]),
                    str(alert["Destination"]),
                    str(alert["Details"]),
                ),
            )

    def get_summary(self) -> dict[str, Any]:
        with self._lock:
            pkt_row = self._conn.execute(
                """
                SELECT
                    COUNT(*) AS total_packets,
                    COALESCE(SUM(size_bytes), 0) AS total_bytes,
                    COUNT(DISTINCT protocol) AS protocol_count,
                    COUNT(DISTINCT source_ip) AS unique_sources,
                    COUNT(DISTINCT destination_ip) AS unique_destinations
                FROM packets
                """
            ).fetchone()
            alert_row = self._conn.execute(
                "SELECT COUNT(*) AS total_alerts FROM alerts"
            ).fetchone()

        return {
            "total_packets": int(pkt_row["total_packets"]),
            "total_bytes": int(pkt_row["total_bytes"]),
            "total_mb": int(pkt_row["total_bytes"]) / (1024 * 1024),
            "protocol_count": int(pkt_row["protocol_count"]),
            "unique_sources": int(pkt_row["unique_sources"]),
            "unique_destinations": int(pkt_row["unique_destinations"]),
            "total_alerts": int(alert_row["total_alerts"]),
        }

    def query_packets(self, limit: int = 1000) -> pd.DataFrame:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    time_str AS "Time",
                    source_ip AS "Source",
                    destination_ip AS "Destination",
                    protocol AS "Protocol",
                    source_port AS "Source Port",
                    destination_port AS "Destination Port",
                    source_mac AS "Source MAC",
                    destination_mac AS "Destination MAC",
                    direction AS "Direction",
                    size_bytes AS "Size"
                FROM packets
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        if not rows:
            return pd.DataFrame(
                columns=[
                    "Time",
                    "Source",
                    "Destination",
                    "Protocol",
                    "Source Port",
                    "Destination Port",
                    "Source MAC",
                    "Destination MAC",
                    "Direction",
                    "Size",
                ]
            )
        return pd.DataFrame([dict(r) for r in rows])

    def query_alerts(self, limit: int = 200) -> pd.DataFrame:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT
                    time_str AS "Time",
                    severity AS "Severity",
                    alert_type AS "Type",
                    source_ip AS "Source",
                    destination_ip AS "Destination",
                    details AS "Details"
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
        if not rows:
            return pd.DataFrame(
                columns=["Time", "Severity", "Type", "Source", "Destination", "Details"]
            )
        return pd.DataFrame([dict(r) for r in rows])

    def clear_history(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM packets")
            self._conn.execute("DELETE FROM alerts")

    def close(self) -> None:
        with self._lock:
            self._conn.close()
