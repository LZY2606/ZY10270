"""SQLite persistence with explicit migrations.

Importing an archive keeps the whole-archive hash, every EOCD candidate,
every central directory record and every local file header with precise
byte ranges.  Re-importing identical bytes is a no-op that returns the
existing archive identity.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from .analysis import build_report
from .parser import Budgets

MIGRATIONS: list[tuple[int, str]] = [
    (1, """
CREATE TABLE archives (
    id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    name TEXT,
    imported_at TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
CREATE TABLE eocd_candidates (
    id INTEGER PRIMARY KEY,
    archive_id INTEGER NOT NULL REFERENCES archives(id),
    seq INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    exclusion_reason TEXT,
    disk_no INTEGER NOT NULL,
    cd_disk INTEGER NOT NULL,
    entries_total INTEGER NOT NULL,
    cd_offset INTEGER NOT NULL,
    cd_size INTEGER NOT NULL,
    comment_len INTEGER NOT NULL,
    zip64_locator_offset INTEGER,
    zip64_eocd_offset INTEGER
);
CREATE TABLE cd_records (
    id INTEGER PRIMARY KEY,
    candidate_id INTEGER NOT NULL REFERENCES eocd_candidates(id),
    idx INTEGER NOT NULL,
    offset INTEGER NOT NULL,
    header_len INTEGER NOT NULL,
    name TEXT NOT NULL,
    flags INTEGER NOT NULL,
    method INTEGER NOT NULL,
    crc32 INTEGER NOT NULL,
    csize INTEGER NOT NULL,
    usize INTEGER NOT NULL,
    local_header_offset INTEGER NOT NULL,
    disk_start INTEGER NOT NULL
);
CREATE TABLE local_headers (
    id INTEGER PRIMARY KEY,
    cd_record_id INTEGER NOT NULL REFERENCES cd_records(id),
    offset INTEGER,
    header_len INTEGER,
    name TEXT,
    flags INTEGER,
    method INTEGER,
    crc32 INTEGER,
    csize INTEGER,
    usize INTEGER,
    data_start INTEGER,
    data_end INTEGER,
    descriptor_offset INTEGER,
    descriptor_len INTEGER,
    descriptor_has_sig INTEGER,
    crc_status TEXT NOT NULL
);
CREATE TABLE anomalies (
    id INTEGER PRIMARY KEY,
    archive_id INTEGER NOT NULL REFERENCES archives(id),
    candidate_seq INTEGER,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX idx_candidates_archive ON eocd_candidates(archive_id);
CREATE INDEX idx_cd_records_candidate ON cd_records(candidate_id);
CREATE INDEX idx_local_headers_record ON local_headers(cd_record_id);
CREATE INDEX idx_anomalies_archive ON anomalies(archive_id);
"""),
]


class Store:
    def __init__(self, path: str, budgets: Budgets | None = None):
        self.path = str(path)
        self.budgets = budgets or Budgets()
        self.migrate()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def migrate(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )""")
            applied = {r[0] for r in conn.execute(
                "SELECT version FROM schema_migrations")}
            for version, sql in MIGRATIONS:
                if version in applied:
                    continue
                conn.executescript(sql)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) "
                    "VALUES (?, ?)",
                    (version, datetime.now(timezone.utc).isoformat()))

    def import_archive(self, data: bytes, name: str | None = None) -> dict:
        report = build_report(data, name=name, budgets=self.budgets)
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM archives WHERE sha256 = ?",
                               (report["sha256"],)).fetchone()
            if row is not None:
                return {"archive_id": row["id"], "sha256": report["sha256"],
                        "size": report["size"], "created": False}
            cur = conn.execute(
                "INSERT INTO archives (sha256, size, name, imported_at, "
                "detail_json) VALUES (?, ?, ?, ?, ?)",
                (report["sha256"], report["size"], name,
                 datetime.now(timezone.utc).isoformat(),
                 json.dumps(report, ensure_ascii=False)))
            archive_id = cur.lastrowid
            for seq, cand in enumerate(report["candidates"]):
                cur = conn.execute(
                    "INSERT INTO eocd_candidates (archive_id, seq, offset, "
                    "kind, status, exclusion_reason, disk_no, cd_disk, "
                    "entries_total, cd_offset, cd_size, comment_len, "
                    "zip64_locator_offset, zip64_eocd_offset) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (archive_id, seq, cand["offset"], cand["kind"],
                     cand["status"], cand["exclusion_reason"], cand["disk_no"],
                     cand["cd_disk"], cand["entries_total"], cand["cd_offset"],
                     cand["cd_size"], cand["comment_len"],
                     cand["zip64_locator_offset"], cand["zip64_eocd_offset"]))
                candidate_id = cur.lastrowid
                for member in cand["members"]:
                    cd = member["cd"]
                    cur = conn.execute(
                        "INSERT INTO cd_records (candidate_id, idx, offset, "
                        "header_len, name, flags, method, crc32, csize, "
                        "usize, local_header_offset, disk_start) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (candidate_id, member["index"], cd["offset"],
                         cd["header_len"], member["name"], cd["flags"],
                         member["method"], cd["crc32"], cd["csize"],
                         cd["usize"], cd["local_header_offset"],
                         cd["disk_start"]))
                    record_id = cur.lastrowid
                    local = member["local"] or {}
                    desc = member["descriptor"] or {}
                    conn.execute(
                        "INSERT INTO local_headers (cd_record_id, offset, "
                        "header_len, name, flags, method, crc32, csize, "
                        "usize, data_start, data_end, descriptor_offset, "
                        "descriptor_len, descriptor_has_sig, crc_status) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (record_id, local.get("offset"),
                         local.get("header_len"), local.get("name"),
                         local.get("flags"), local.get("method"),
                         local.get("crc32"), local.get("csize"),
                         local.get("usize"), member["data_start"],
                         member["data_end"], desc.get("offset"),
                         desc.get("length"),
                         (None if desc.get("has_signature") is None
                          else int(desc.get("has_signature", False))),
                         member["crc_status"]))
            for anomaly in report["anomalies"]:
                conn.execute(
                    "INSERT INTO anomalies (archive_id, candidate_seq, kind, "
                    "detail) VALUES (?, ?, ?, ?)",
                    (archive_id, anomaly["candidate"], anomaly["kind"],
                     anomaly["detail"]))
            return {"archive_id": archive_id, "sha256": report["sha256"],
                    "size": report["size"], "created": True}

    def list_archives(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT a.id, a.sha256, a.size, a.name, a.imported_at,
                       (SELECT COUNT(*) FROM eocd_candidates c
                        WHERE c.archive_id = a.id) AS candidates,
                       (SELECT COUNT(*) FROM anomalies n
                        WHERE n.archive_id = a.id) AS anomalies
                FROM archives a ORDER BY a.id""").fetchall()
            return [dict(r) for r in rows]

    def get_detail(self, archive_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, sha256, size, name, imported_at, detail_json "
                "FROM archives WHERE id = ?", (archive_id,)).fetchone()
            if row is None:
                return None
            detail = json.loads(row["detail_json"])
            detail["archive_id"] = row["id"]
            detail["imported_at"] = row["imported_at"]
            return detail
