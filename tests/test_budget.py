"""资源预算：文件大小、条目数、解压总量、候选风暴。"""

from cdwitness.fixtures import build_zip
from cdwitness.budget import Budget
from cdwitness.parser import analyze, scan_eocd_signatures


def test_file_size_budget():
    blob = build_zip([dict(name=b"x.txt", data=b"x")])
    budget = Budget(max_file_size=10)
    report = analyze(blob, budget)
    assert report.rejected is True
    assert report.reject_reason and "超过预算" in report.reject_reason


def test_entry_budget(tiny_budget, fixtures):
    # normal.zip 有 2 个成员，预算 max_entries=2 应通过
    ok = analyze(fixtures["normal.zip"], tiny_budget)
    assert not ok.rejected
    # 3 个成员的 evil_names.zip 触发条目预算
    report = analyze(fixtures["evil_names.zip"], tiny_budget)
    cand = report.candidates[0]
    assert not cand.valid
    assert cand.exclusion_reason == "entry_budget_exceeded"


def test_uncompressed_member_budget():
    blob = build_zip([dict(name=b"big.txt", data=b"Z" * 100)])
    budget = Budget(max_uncompressed_member=50)
    report = analyze(blob, budget)
    m = [c for c in report.candidates if c.valid][0].members[0]
    assert m.crc_status == "skipped_budget"
    assert any(f.code == "uncompressed_member_budget" for f in m.findings)


def test_uncompressed_total_budget():
    blob = build_zip([
        dict(name=b"a", data=b"A" * 40),
        dict(name=b"b", data=b"B" * 40),
        dict(name=b"c", data=b"C" * 40),
    ])
    budget = Budget(max_uncompressed_total=90, max_uncompressed_member=500)
    report = analyze(blob, budget)
    cand = [c for c in report.candidates if c.valid][0]
    assert any(f.code == "uncompressed_total_budget"
               for f in cand.findings)
    statuses = {m.name: m.crc_status for m in cand.members}
    assert statuses[b"c".decode()] == "skipped_budget"


def test_decompression_bomb_cap():
    # 高压缩比炸弹：100KB 解压远超成员预算，必须有界、快速完成
    payload = b"\0" * 200_000
    blob = build_zip([dict(name=b"bomb", data=payload, method=8)])
    budget = Budget(max_uncompressed_member=10_000)
    report = analyze(blob, budget)
    m = [c for c in report.candidates if c.valid][0].members[0]
    assert m.crc_status == "skipped_budget"


def test_candidate_budget(fixtures):
    # 在尾部窗口塞入大量伪 EOCD 签名（不带注释，均无法贴边）
    blob = fixtures["normal.zip"]
    junk = b"PK\x05\x06" + b"\0" * 18
    padded = blob + junk * 60
    budget = Budget(max_candidates=8)
    sigs = scan_eocd_signatures(padded, budget)
    assert len(sigs) <= 8
