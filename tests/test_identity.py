"""同一归档重复导入的身份稳定性：哈希即身份，范围图字节级确定。"""
import hashlib

from cdwitness.parser import analyze
from cdwitness.storage import connect, get_archive, migrate, save_analysis


def test_sha256_identity(fixtures):
    for name, blob in fixtures.items():
        report = analyze(blob)
        assert report.sha256 == hashlib.sha256(blob).hexdigest()


def test_deterministic_ranges(fixtures):
    first = analyze(fixtures["twin_eocd.zip"]).to_dict()
    second = analyze(fixtures["twin_eocd.zip"]).to_dict()
    assert first == second


def test_reimport_returns_same_id(tmp_path, fixtures):
    conn = connect(tmp_path / "id.db")
    migrate(conn)
    blob = fixtures["normal.zip"]
    report = analyze(blob).to_dict()
    id1, reused1 = save_analysis(conn, report["sha256"], "normal.zip",
                                 report["size"], report)
    id2, reused2 = save_analysis(conn, report["sha256"], "normal-copy.zip",
                                 report["size"], report)
    assert id1 == id2
    assert reused1 is False and reused2 is True
    row = get_archive(conn, id1)
    assert row["report"]["sha256"] == report["sha256"]
    conn.close()


def test_distinct_archives_get_distinct_ids(tmp_path, fixtures):
    conn = connect(tmp_path / "id2.db")
    migrate(conn)
    ids = set()
    for name in ("normal.zip", "evil_names.zip", "twin_eocd.zip"):
        blob = fixtures[name]
        r = analyze(blob).to_dict()
        aid, _ = save_analysis(conn, r["sha256"], name, r["size"], r)
        ids.add(aid)
    assert len(ids) == 3
    conn.close()


def test_eocd_candidates_persisted(tmp_path, fixtures):
    conn = connect(tmp_path / "id3.db")
    migrate(conn)
    r = analyze(fixtures["twin_eocd.zip"]).to_dict()
    aid, _ = save_analysis(conn, r["sha256"], "twin_eocd.zip",
                           r["size"], r)
    row = get_archive(conn, aid)
    assert len(row["candidate_summaries"]) == 2
    assert all(s["valid"] for s in row["candidate_summaries"])
    codes = {s["code"] for s in row["finding_summaries"]}
    assert "multiple_valid_directories" in codes
    conn.close()
