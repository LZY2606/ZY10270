"""范围图与 CRC：中央目录、局部头、压缩数据、descriptor 的精确区间。"""
from cdwitness.parser import UINT32_MAX, analyze


def _only(analysis):
    valid = [c for c in analysis.candidates if c.valid]
    assert len(valid) == 1
    return valid[0]


def test_normal_range_map_covers_file(analyses):
    cand = _only(analyses["normal.zip"])
    members = cand.members
    # 第二个成员的 data_range 结束处紧邻中央目录起点
    assert members[1].data_range.end == cand.central_directory_range.start
    # EOCD 紧贴文件尾
    assert cand.eocd_range.end == analyses["normal.zip"].size
    # 局部头/名称/extra 区间正确（normal 无 extra）
    m0 = members[0]
    assert m0.local_header_range.start == 0
    assert m0.local_extra_range.length == 0
    assert m0.central_extra_range.length == 0


def test_crc_ok_stored_and_deflate(analyses):
    for name in ("normal.zip", "zip64_sentinel.zip",
                 "unsigned_descriptor.zip", "signed_descriptor.zip"):
        cand = _only(analyses[name])
        assert cand.members, name
        for m in cand.members:
            assert m.crc_status == "ok", (name, m.name, m.findings)


def test_crc_mismatch_detects_tampered_data(fixtures):
    blob = bytearray(fixtures["normal.zip"])
    # 破坏 hello.txt 的 stored 数据第一字节
    blob[39] ^= 0xFF
    report = analyze(bytes(blob))
    m = _only(report).members[0]
    assert m.crc_status == "mismatch"
    assert any(f.code == "crc_mismatch" for f in m.findings)


def test_zip64_sentinel_resolution(analyses):
    a = analyses["zip64_sentinel.zip"]
    cand = _only(a)
    assert cand.zip64 is True
    assert cand.zip64_eocd_range is not None
    assert cand.zip64_locator_range is not None
    # EOCD 头字段保持哨兵，真实值来自 ZIP64 EOCD
    assert cand.cd_size != UINT32_MAX
    sizes = sorted(m.central_uncomp_size for m in cand.members)
    assert sizes == [10, 20]
    for m in cand.members:
        assert m.data_range.length == m.central_comp_size
        assert m.crc_status == "ok"


def test_unsigned_descriptor_detected_by_consistency(analyses):
    cand = _only(analyses["unsigned_descriptor.zip"])
    m = cand.members[0]
    assert m.bit3_descriptor is True
    assert m.descriptor_signed is False
    assert m.descriptor_range.length == 12
    assert any(f.code == "local_zero_placeholder" for f in m.findings)
    assert any(f.code == "descriptor_unsigned" for f in m.findings)
    # descriptor 紧跟压缩数据
    assert m.descriptor_range.start == m.data_range.end


def test_signed_descriptor(analyses):
    cand = _only(analyses["signed_descriptor.zip"])
    m = cand.members[0]
    assert m.descriptor_signed is True
    assert m.descriptor_range.length == 16
    assert not any(f.code == "descriptor_inconsistent" for f in m.findings)


def test_bit3_zero_sizes_never_used_as_layout(fixtures):
    # bit3 局部头零尺寸，但中央目录声明真实尺寸；数据范围必须用中央目录
    report = analyze(fixtures["unsigned_descriptor.zip"])
    m = _only(report).members[0]
    assert (m.local_comp_size, m.local_uncomp_size) == (0, 0)
    assert m.data_range.length > 0
    assert m.data_range.length == m.central_comp_size


def test_descriptor_tamper_consistency_rule(fixtures):
    # 手工构造：descriptor 无签名但 CRC 字段被改坏，应判无签名+不一致
    blob = bytearray(fixtures["unsigned_descriptor.zip"])
    cand = _only(analyze(bytes(blob)))
    desc_pos = cand.members[0].descriptor_range.start
    blob[desc_pos] ^= 0xFF  # 破坏 descriptor CRC 首字节
    report = analyze(bytes(blob))
    m = _only(report).members[0]
    # 数据本身 CRC 仍应 ok（descriptor 只做尾部证词），但 descriptor 不一致
    assert m.crc_status == "ok"
    assert m.descriptor_signed is False
    assert any(f.code == "descriptor_inconsistent" for f in m.findings)
