"""FastAPI entry point.  Run: uvicorn app:app --host 127.0.0.1 --port 5970"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from zipforensics import fixtures
from zipforensics.store import Store
from zipforensics.web import INDEX_HTML

MAX_UPLOAD = 512 * 1024 * 1024


def create_app(db_path: str | None = None) -> FastAPI:
    db_path = db_path or os.environ.get("ZIPREVIEW_DB", "zipreview.db")
    store = Store(db_path)
    app = FastAPI(title="中央目录证词台")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return INDEX_HTML

    @app.get("/api/fixtures")
    def list_fixtures() -> list[str]:
        return fixtures.fixture_names()

    @app.post("/api/import")
    async def import_zip(request: Request) -> dict:
        data = await request.body()
        if not data:
            raise HTTPException(400, "empty body")
        if len(data) > MAX_UPLOAD:
            raise HTTPException(413, "archive too large")
        name = request.headers.get("X-Filename")
        return store.import_archive(data, name=name)

    @app.post("/api/import-fixture/{name}")
    def import_fixture(name: str) -> dict:
        if name not in fixtures.FIXTURES:
            raise HTTPException(404, f"unknown fixture {name!r}")
        return store.import_archive(fixtures.build(name),
                                    name=f"fixture:{name}")

    @app.get("/api/archives")
    def list_archives() -> list[dict]:
        return store.list_archives()

    @app.get("/api/archives/{archive_id}")
    def archive_detail(archive_id: int) -> dict:
        detail = store.get_detail(archive_id)
        if detail is None:
            raise HTTPException(404, "archive not found")
        return detail

    return app


app = create_app()
