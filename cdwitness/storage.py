"""SQLite 存储：显式迁移版本表，证词以 JSON 原样保留。"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SCHEMA = [
    # version 1：初始证词台结构
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS archives (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sha256 TEXT NOT NULL UNIQUE,
        filename TEXT NOT NULL,
        size INTEGER NOT NULL,
        imported_at TEXT NOT NULL DEFAULT (datetime('now')),
        report_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS candidate_summaries (
        archive_id INTEGER NOT NULL,
        candidate_index INTEGER NOT NULL,
        valid INTEGER NOT NULL,
        exclusion_reason TEXT,
        zip64 INTEGER NOT NULL,
        member_count INTEGER NOT NULL,
        PRIMARY KEY (archive_id, candidate_index),
        FOREIGN KEY (archive_id) REFERENCES archives(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS finding_summaries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        archive_id INTEGER NOT NULL,
        scope TEXT NOT NULL,
        candidate_index INTEGER,
        member_name TEXT,
        code TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT NOT NULL,
        FOREIGN KEY (archive_id) REFERENCES archives(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_archive ON finding_summaries(archive_id)",
    "CREATE INDEX IF NOT EXISTS idx_candidates_archive ON candidate_summaries(archive_id)",
]

LATEST_VERSION = 1


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    """顺序应用迁移，版本记录在 schema_version 中。"""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version ("
        "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT "
        "(datetime('now')))")
    row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
    current = row["v"] or 0
    if current < LATEST_VERSION:
        for statement in SCHEMA:
            conn.execute(statement)
        conn.execute(
            "INSERT OR REPLACE INTO schema_version(version) VALUES (?)",
            (LATEST_VERSION,))
    conn.commit()


def save_analysis(conn, sha256: str, filename: str, size: int, report: dict):
    """幂等导入：整包哈希相同则返回既有 id 与 reused=True。"""
    existing = conn.execute(
        "SELECT id FROM archives WHERE sha256 = ?", (sha256,)).fetchone()
    if existing:
        return existing["id"], True

    cur = conn.execute(
        "INSERT INTO archives(sha256, filename, size, report_json) "
        "VALUES (?, ?, ?, ?)",
        (sha256, filename, size, json.dumps(report, ensure_ascii=False)))
    archive_id = cur.lastrowid
    for cand in report["candidates"]:
        conn.execute(
            "INSERT INTO candidate_summaries(archive_id, candidate_index, "
            "valid, exclusion_reason, zip64, member_count) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (archive_id, cand["index"], 1 if cand["valid"] else 0,
             cand["exclusion_reason"], 1 if cand["zip64"] else 0,
             len(cand["members"])))
        for f in cand["findings"]:
            conn.execute(
                "INSERT INTO finding_summaries(archive_id, scope, "
                "candidate_index, member_name, code, severity, message) "
                "VALUES (?, 'candidate', ?, NULL, ?, ?, ?)",
                (archive_id, cand["index"], f["code"], f["severity"],
                 f["message"]))
        for m in cand["members"]:
            for f in m["findings"]:
                conn.execute(
                    "INSERT INTO finding_summaries(archive_id, scope, "
                    "candidate_index, member_name, code, severity, message) "
                    "VALUES (?, 'member', ?, ?, ?, ?, ?)",
                    (archive_id, cand["index"], m["name"], f["code"],
                     f["severity"], f["message"]))
    for f in report["findings"]:
        conn.execute(
            "INSERT INTO finding_summaries(archive_id, scope, "
            "candidate_index, member_name, code, severity, message) "
            "VALUES (?, 'archive', NULL, NULL, ?, ?, ?)",
            (archive_id, f["code"], f["severity"], f["message"]))
    conn.commit()
    return archive_id, False


def list_archives(conn):
    rows = conn.execute(
        "SELECT id, sha256, filename, size, imported_at FROM archives "
        "ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def get_archive(conn, archive_id: int):
    row = conn.execute(
        "SELECT * FROM archives WHERE id = ?", (archive_id,)).fetchone()
    if not row:
        return None
    data = dict(row)
    data["report"] = json.loads(data.pop("report_json"))
    data["candidate_summaries"] = [dict(r) for r in conn.execute(
        "SELECT * FROM candidate_summaries WHERE archive_id = ? "
        "ORDER BY candidate_index", (archive_id,))]
    data["finding_summaries"] = [dict(r) for r in conn.execute(
        "SELECT * FROM finding_summaries WHERE archive_id = ? ORDER BY id",
        (archive_id,))]
    return data
