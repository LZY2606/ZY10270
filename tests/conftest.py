"""pytest 共享夹具：内置样例与内存/临时数据库。"""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as webapp  # noqa: E402
from cdwitness.budget import Budget  # noqa: E402
from cdwitness.fixtures import all_fixtures  # noqa: E402
from cdwitness.parser import analyze  # noqa: E402
from cdwitness.storage import connect, migrate  # noqa: E402


@pytest.fixture(scope="session")
def fixtures():
    return all_fixtures()


@pytest.fixture()
def analyses(fixtures):
    return {name: analyze(blob) for name, blob in fixtures.items()}


@pytest.fixture()
def tiny_budget():
    return Budget(
        max_file_size=1024, max_entries=2,
        max_uncompressed_total=120, max_uncompressed_member=60,
        max_candidates=64)


@pytest.fixture()
def client(tmp_path):
    db = tmp_path / "test.db"
    webapp.DB_PATH = db
    conn = connect(db)
    migrate(conn)
    conn.close()
    with TestClient(webapp.app) as c:
        yield c
