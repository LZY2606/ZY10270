import pytest
from fastapi.testclient import TestClient

from app import create_app
from zipforensics import fixtures


@pytest.fixture()
def client(tmp_path):
    app = create_app(str(tmp_path / "api.db"))
    with TestClient(app) as c:
        yield c


def test_index_shows_witness_stand(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "中央目录证词台" in resp.text


def test_fixture_roundtrip(client):
    names = client.get("/api/fixtures").json()
    assert set(names) == set(fixtures.fixture_names())
    for name in names:
        r = client.post(f"/api/import-fixture/{name}").json()
        assert r["created"] is True
        detail = client.get(f"/api/archives/{r['archive_id']}").json()
        assert detail["sha256"] == r["sha256"]
        assert detail["candidates"]
        # re-import: identity stable
        r2 = client.post(f"/api/import-fixture/{name}").json()
        assert r2["archive_id"] == r["archive_id"]
        assert r2["created"] is False
    archives = client.get("/api/archives").json()
    assert len(archives) == len(names)


def test_upload_raw_body(client):
    blob = fixtures.build("nosig-descriptor")
    r = client.post("/api/import", content=blob,
                    headers={"X-Filename": "up.zip"}).json()
    assert r["created"] is True
    detail = client.get(f"/api/archives/{r['archive_id']}").json()
    member = detail["candidates"][0]["members"][0]
    assert member["descriptor"]["has_signature"] is False
    assert member["crc_status"] == "ok"


def test_unknown_routes(client):
    assert client.post("/api/import-fixture/nope").status_code == 404
    assert client.get("/api/archives/999").status_code == 404
    assert client.post("/api/import", content=b"").status_code == 400
