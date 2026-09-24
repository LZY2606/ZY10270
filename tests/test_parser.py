import io
import zipfile

from zipforensics import fixtures
from zipforensics.analysis import build_report
from zipforensics.parser import (Budgets, parse_archive, parse_extra)


def primary(report):
    return next(c for c in report["candidates"] if c["status"] == "primary")


def test_zip64_sentinel_resolves_real_geometry():
    data = fixtures.build("zip64-sentinel")
    report = build_report(data)
    cand = primary(report)
    assert cand["kind"] == "zip64"
    assert cand["zip64_eocd_offset"] is not None
    assert cand["zip64_locator_offset"] == cand["offset"] - 20
    # resolved values point at the real single-record directory
    assert cand["entries_total"] == 1
    assert cand["cd_offset"] + cand["cd_size"] == cand["zip64_eocd_offset"]
    member = cand["members"][0]
    assert member["zip64"] is True
    assert data[member["data_start"]:member["data_end"]] == b"hello zip64\n"
    assert member["crc_status"] == "ok"


def test_nosig_descriptor_detected_by_consistency():
    report = build_report(fixtures.build("nosig-descriptor"))
    member = primary(report)["members"][0]
    assert member["bit3"] is True
    assert member["utf8"] is True
    desc = member["descriptor"]
    assert desc["has_signature"] is False
    assert desc["length"] == 12
    assert desc["consistent"] is True
    assert member["crc_status"] == "ok"
    assert any("trusting central directory" in n for n in member["notes"])


def test_fake_eocd_comment_keeps_all_candidates():
    report = build_report(fixtures.build("fake-eocd-comment"))
    assert len(report["candidates"]) == 2  # nothing silently discarded
    real = primary(report)
    assert real["offset"] + 22 + real["comment_len"] == report["size"]
    assert len(real["members"]) == 1
    forged = next(c for c in report["candidates"] if c["status"] == "excluded")
    assert forged["exclusion_reason"] == "central directory range outside file"


def test_shared_range_member_ranges():
    report = build_report(fixtures.build("shared-range"))
    members = {m["name"]: m for m in primary(report)["members"]}
    a, b = members["a.txt"], members["b.txt"]
    # b's range is strictly inside a's range
    assert a["data_start"] < b["data_start"] < b["data_end"] < a["data_end"]
    assert a["crc_status"] == "ok" and b["crc_status"] == "ok"


def test_truncated_extra_field_flagged():
    report = build_report(fixtures.build("truncated-extra"))
    member = primary(report)["members"][0]
    assert member["cd"]["extras"][0]["truncated"] is True
    assert member["cd"]["extras"][0]["declared_len"] == 100
    assert member["local"]["extras"][0]["truncated"] is True
    kinds = {a["kind"] for a in report["anomalies"]}
    assert "extra_truncated" in kinds


def test_parse_extra_trailing_garbage():
    fields = parse_extra(b"\x01\x00\x02\x00ab\x99")  # valid field + 1 stray byte
    assert len(fields) == 2
    assert fields[0].truncated is False
    assert fields[1].truncated is True


def test_stdlib_roundtrip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("dir/hello.txt", b"hello world" * 10)
        zf.comment = b"roundtrip"
    data = buf.getvalue()
    report = build_report(data)
    cand = primary(report)
    assert cand["comment_text"] == "roundtrip"
    member = cand["members"][0]
    assert member["name"] == "dir/hello.txt"
    assert member["crc_status"] == "ok"
    assert data[member["data_start"]:member["data_end"]]


def test_candidate_budget_event():
    data = fixtures.build("fake-eocd-comment")
    parse = parse_archive(data, Budgets(max_candidates=1))
    assert len(parse.candidates) == 1
    assert any("candidate budget" in e for e in parse.budget_events)
