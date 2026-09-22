"""FastAPI 端到端：页面标题、fixture 导入、上传、重复导入、详情。"""
from cdwitness.fixtures import all_fixtures


def test_index_title(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "中央目录证词台" in r.text


def test_health_and_fixtures(client):
    assert client.get("/api/health").json()["status"] == "ok"
    data = client.get("/api/fixtures").json()
    names = {f["name"] for f in data["fixtures"]}
    assert {"zip64_sentinel.zip", "unsigned_descriptor.zip",
            "fake_eocd_comment.zip", "shared_range.zip",
            "truncated_extra.zip"} <= names


def test_fixture_import_and_detail(client):
    r = client.post("/api/fixtures/twin_eocd.zip/import")
    assert r.status_code == 200
    data = r.json()
    assert len(data["report"]["candidates"]) == 2
    # 再次导入：身份复用
    r2 = client.post("/api/fixtures/twin_eocd.zip/import")
    assert r2.json()["archive_id"] == data["archive_id"]
    assert r2.json()["reused"] is True
    detail = client.get(f"/api/archives/{data['archive_id']}").json()
    assert len(detail["candidate_summaries"]) == 2


def test_fixture_candidate_exclusion(client):
    r = client.post("/api/fixtures/fake_eocd_comment.zip/import").json()
    cands = r["report"]["candidates"]
    assert cands[0]["valid"] is False
    assert cands[0]["exclusion_reason"] == "eocd_not_at_tail"


def test_upload_roundtrip(client):
    blob = all_fixtures()["zip64_sentinel.zip"]
    r = client.post(
        "/api/archives",
        files={"file": ("z64.zip", blob, "application/zip")})
    assert r.status_code == 200
    data = r.json()
    assert data["report"]["candidates"][0]["zip64"] is True
    listing = client.get("/api/archives").json()["archives"]
    assert any(a["id"] == data["archive_id"] for a in listing)


def test_upload_same_bytes_stable_identity(client):
    blob = all_fixtures()["normal.zip"]
    r1 = client.post("/api/archives",
                     files={"file": ("a.zip", blob, "application/zip")}).json()
    r2 = client.post("/api/archives",
                     files={"file": ("b.zip", blob, "application/zip")}).json()
    assert r1["archive_id"] == r2["archive_id"]
    assert r2["reused"] is True


def test_reanalyze_with_budget(client):
    r = client.post("/api/fixtures/evil_names.zip/import").json()
    aid = r["archive_id"]
    r2 = client.post(f"/api/archives/{aid}/reanalyze",
                     json={"max_entries": 2})
    data = r2.json()["report"]
    assert data["candidates"][0]["exclusion_reason"] == "entry_budget_exceeded"
