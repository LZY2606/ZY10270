"""EOCD 候选、排除原因与风险证词。"""
import struct

from cdwitness.parser import analyze


def _valid(analysis):
    return [c for c in analysis.candidates if c.valid]


def test_fake_eocd_in_comment_excluded(analyses):
    a = analyses["fake_eocd_comment.zip"]
    assert len(a.candidates) == 2
    fake = a.candidates[0]
    assert not fake.valid
    assert fake.exclusion_reason == "eocd_not_at_tail"
    real = a.candidates[1]
    assert real.valid
    assert a.preferred_candidate == 1
    # 伪 EOCD 的注释区间为零宽，真 EOCD 的注释包含伪记录
    assert real.comment_range.length == 26


def test_twin_eocd_both_kept(analyses):
    a = analyses["twin_eocd.zip"]
    valid = _valid(a)
    assert len(valid) == 2
    assert any(f.code == "multiple_valid_directories" for f in a.findings)
    # 两个候选各自形成独立目录图，成员名不同
    names = {tuple(m.name for m in c.members) for c in valid}
    assert names == {("a.txt",), ("b.txt",)}
    # 第二个 EOCD 藏在第一个的注释区间里（扫描从尾部向前，故按起点排序）
    first, second = sorted(a.candidates, key=lambda c: c.eocd_range.start)
    assert first.comment_range.contains(second.eocd_range)
    assert first.eocd_range.end == second.eocd_range.end


def test_no_valid_directory_keeps_all_candidates(fixtures):
    # 把真 EOCD 的中央目录偏移改坏：所有候选都被排除，且原因保留
    blob = bytearray(fixtures["normal.zip"])
    a = analyze(fixtures["normal.zip"])
    cand = _valid(a)[0]
    pos = cand.eocd_range.start
    struct.pack_into("<I", blob, pos + 16, 0xFFFFFFF0)  # cd_offset 指向越界
    report = analyze(bytes(blob))
    assert all(not c.valid for c in report.candidates)
    assert report.candidates[0].exclusion_reason in (
        "central_directory_out_of_bounds", "integer_wrap_or_oversize")
    assert any(f.code == "no_valid_directory" for f in report.findings)
    assert report.preferred_candidate is None


def test_shared_compressed_range_flagged(analyses):
    cand = _valid(analyses["shared_range.zip"])[0]
    codes = {f.code for m in cand.members for f in m.findings}
    assert "shared_compressed_range" in codes
    a, b = cand.members
    assert a.data_range.start == b.data_range.start
    assert a.data_range.end == b.data_range.end
    # 共享区间不应产生名称不一致误报
    assert "name_mismatch" not in codes


def test_truncated_extra_recorded(analyses):
    cand = _valid(analyses["truncated_extra.zip"])[0]
    m = cand.members[0]
    assert any(f.code == "extra_field_truncated" for f in m.findings)
    assert m.crc_status == "ok"  # 截断 extra 不影响数据区验证


def test_path_traversal_and_duplicates(analyses):
    cand = _valid(analyses["evil_names.zip"])[0]
    codes = {f.code for m in cand.members for f in m.findings}
    assert "path_traversal" in codes
    assert "duplicate_name" in codes
    escape = cand.members[0]
    assert escape.name == "../escape.txt"
    assert any(f.code == "path_traversal" for f in escape.findings)


def test_multidisk_fields_recorded(analyses):
    cand = _valid(analyses["multidisk.zip"])[0]
    assert cand.disk_no == 1 and cand.cd_disk == 1
    assert any(f.code == "multidisk_member" for m in cand.members
               for f in m.findings)


def test_encrypted_member_skips_crc(fixtures):
    from cdwitness.fixtures import build_zip
    blob = build_zip([dict(name=b"secret.txt", data=b"classified\n",
                           encrypted=True)])
    report = analyze(blob)
    m = _valid(report)[0].members[0]
    assert m.encrypted is True
    assert m.crc_status == "skipped_encrypted"
    assert any(f.code == "encrypted_members" for f in
               _valid(report)[0].findings)


def test_integer_wrap_cd_offset(fixtures):
    blob = bytearray(fixtures["normal.zip"])
    a = analyze(fixtures["normal.zip"])
    pos = _valid(a)[0].eocd_range.start
    struct.pack_into("<I", blob, pos + 12, 0xFFFFFFFF)  # cd_size 哨兵但无 ZIP64
    report = analyze(bytes(blob))
    assert not report.candidates[0].valid
    assert report.candidates[0].exclusion_reason == \
        "zip64_sentinel_without_locator"


def test_eocd_truncated_excluded(fixtures):
    blob = fixtures["normal.zip"][:-10]  # 截掉 EOCD 注释尾部
    report = analyze(blob)
    assert all(not c.valid for c in report.candidates)
    assert report.candidates[0].exclusion_reason in (
        "eocd_truncated", "eocd_not_at_tail")
