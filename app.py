"""FastAPI 入口：中央目录证词台。

路由：
  GET  /                 Web UI
  GET  /api/health       健康检查
  GET  /api/fixtures     内置样例清单
  POST /api/fixtures/{name}/import  将内置样例导入审阅（不落盘解压）
  POST /api/archives     上传 ZIP 审阅
  GET  /api/archives     已导入归档列表
  GET  /api/archives/{id} 证词详情
  POST /api/archives/{id}/reanalyze 用自定义资源预算重新审阅
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from cdwitness.budget import Budget, DEFAULT_BUDGET
from cdwitness.fixtures import all_fixtures
from cdwitness.parser import analyze
from cdwitness.storage import connect, get_archive, list_archives, migrate, save_analysis

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("CDWITNESS_DB", BASE_DIR / "data" / "witness.db"))

@asynccontextmanager
async def lifespan(_app):
    conn = get_conn()
    conn.close()
    yield


app = FastAPI(title="中央目录证词台", version="1.0.0", lifespan=lifespan)


def get_conn():
    conn = connect(DB_PATH)
    migrate(conn)
    return conn


@app.get("/api/health")
def health():
    return {"status": "ok", "db": str(DB_PATH)}


@app.get("/api/fixtures")
def fixtures():
    items = all_fixtures()
    return {"fixtures": [
        {"name": name, "size": len(blob),
         "sha256": hashlib.sha256(blob).hexdigest()}
        for name, blob in sorted(items.items())]}


@app.post("/api/fixtures/{name}/import")
def import_fixture(name: str):
    items = all_fixtures()
    if name not in items:
        raise HTTPException(404, f"内置样例 {name} 不存在")
    blob = items[name]
    report = analyze(blob, DEFAULT_BUDGET).to_dict()
    conn = get_conn()
    try:
        archive_id, reused = save_analysis(
            conn, report["sha256"], name, report["size"], report)
    finally:
        conn.close()
    return {"archive_id": archive_id, "reused": reused, "report": report}


@app.post("/api/archives")
async def upload_archive(file: UploadFile = File(...)):
    blob = await file.read()
    if len(blob) > DEFAULT_BUDGET.max_file_size:
        raise HTTPException(
            413, f"文件超过预算 {DEFAULT_BUDGET.max_file_size} 字节")
    report = analyze(blob, DEFAULT_BUDGET).to_dict()
    conn = get_conn()
    try:
        archive_id, reused = save_analysis(
            conn, report["sha256"], file.filename or "uploaded.zip",
            report["size"], report)
    finally:
        conn.close()
    return {"archive_id": archive_id, "reused": reused, "report": report}


class ReanalyzeBody(BaseModel):
    max_file_size: int | None = None
    max_entries: int | None = None
    max_uncompressed_total: int | None = None
    max_uncompressed_member: int | None = None
    max_candidates: int | None = None


@app.post("/api/archives/{archive_id}/reanalyze")
def reanalyze(archive_id: int, body: ReanalyzeBody):
    conn = get_conn()
    try:
        row = get_archive(conn, archive_id)
        if not row:
            raise HTTPException(404, "归档不存在")
        items = all_fixtures()
        blob = items.get(row["filename"])
        if blob is None:
            raise HTTPException(
                409, "重新审阅自定义预算仅对当前进程上传的字节可用，"
                "本版本不把原始压缩包落盘；请重新上传该文件")
        overrides = {k: v for k, v in body.model_dump().items()
                     if v is not None}
        budget = Budget(**overrides) if overrides else DEFAULT_BUDGET
        report = analyze(blob, budget).to_dict()
        return {"archive_id": archive_id, "budget": overrides,
                "report": report}
    finally:
        conn.close()


@app.get("/api/archives")
def archives():
    conn = get_conn()
    try:
        return {"archives": list_archives(conn)}
    finally:
        conn.close()


@app.get("/api/archives/{archive_id}")
def archive_detail(archive_id: int):
    conn = get_conn()
    try:
        row = get_archive(conn, archive_id)
        if not row:
            raise HTTPException(404, "归档不存在")
        return row
    finally:
        conn.close()


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")),
          name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(str(BASE_DIR / "static" / "index.html"))
