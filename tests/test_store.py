import sqlite3

from zipforensics import fixtures
from zipforensics.analysis import build_report
from zipforensics.store import Store


def table_counts(path):
    conn = sqlite3.connect(path)
    tables = ["archives", "eocd_candidates", "cd_records", "local_headers",
              "anomalies"]
    counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in tables}
    conn.close()
    return counts


def test_reimport_identity_stability(tmp_path):
    db = str(tmp_path / "a.db")
    store = Store(db)
    blob = fixtures.build("shared-range")
    first = store.import_archive(blob, name="one")
    second = store.import_archive(blob, name="two")  # same bytes, new name
    assert first["created"] is True
    assert second["created"] is False
    assert first["archive_id"] == second["archive_id"]
    counts = table_counts(db)
    # importing every fixture must not disturb the first archive's rows
    for name in fixtures.fixture_names():
        store.import_archive(fixtures.build(name), name=name)
    again = store.import_archive(blob)
    assert again["archive_id"] == first["archive_id"]
    assert again["created"] is False
    # shared-range was already imported, so total == number of fixtures
    assert table_counts(db)["archives"] == len(fixtures.fixture_names())
    del counts


def test_byte_ranges_persisted(tmp_path):
    db = str(tmp_path / "b.db")
    store = Store(db)
    blob = fixtures.build("zip64-sentinel")
    result = store.import_archive(blob)
    report = build_report(blob)
    cand = next(c for c in report["candidates"] if c["status"] == "primary")
    member = cand["members"][0]
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM eocd_candidates WHERE archive_id = ?",
        (result["archive_id"],)).fetchone()
    assert row["offset"] == cand["offset"]
    assert row["kind"] == "zip64"
    assert row["zip64_eocd_offset"] == cand["zip64_eocd_offset"]
    rec = conn.execute("SELECT * FROM cd_records").fetchone()
    assert rec["offset"] == member["cd"]["offset"]
    assert rec["local_header_offset"] == member["cd"]["local_header_offset"]
    lh = conn.execute("SELECT * FROM local_headers").fetchone()
    assert lh["data_start"] == member["data_start"]
    assert lh["data_end"] == member["data_end"]
    assert lh["crc_status"] == "ok"
    conn.close()


def test_excluded_candidates_persisted(tmp_path):
    store = Store(str(tmp_path / "c.db"))
    result = store.import_archive(fixtures.build("fake-eocd-comment"))
    detail = store.get_detail(result["archive_id"])
    statuses = sorted(c["status"] for c in detail["candidates"])
    assert statuses == ["excluded", "primary"]


def test_migration_idempotent(tmp_path):
    db = str(tmp_path / "m.db")
    Store(db)
    Store(db)  # second open must not re-apply migrations
    conn = sqlite3.connect(db)
    versions = [r[0] for r in conn.execute(
        "SELECT version FROM schema_migrations ORDER BY version")]
    conn.close()
    assert versions == [1]
