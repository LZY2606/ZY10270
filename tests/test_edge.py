"""额外边界：ZIP64 目标损坏、中央目录尺寸不符、伪签名在文件数据中。"""
import struct

from cdwitness.fixtures import build_zip
from cdwitness.parser import (EOCD_SIG, UINT16_MAX, UINT32_MAX,
                              Z64_LOC_SIG, analyze)


def test_zip64_locator_target_bad(fixtures):
    # 制造哨兵 + locator（紧贴 EOCD 之前），但 locator 指向垃圾偏移
    blob = bytearray(fixtures["normal.zip"])
    a = analyze(fixtures["normal.zip"])
    pos = [c for c in a.candidates if c.valid][0].eocd_range.start
    eocd_bytes = bytes(blob[pos:])
    struct.pack_into("<HHHH", blob, pos + 4,
                     UINT16_MAX, UINT16_MAX, UINT16_MAX, UINT16_MAX)
    struct.pack_into("<II", blob, pos + 12, UINT32_MAX, UINT32_MAX)
    loc = struct.pack("<IIQI", Z64_LOC_SIG, 0, pos + 2000, 1)
    blob = blob[:pos] + bytearray(loc) + bytearray(
        struct.pack("<IHHHHIIH", EOCD_SIG, UINT16_MAX, UINT16_MAX,
                    UINT16_MAX, UINT16_MAX, UINT32_MAX, UINT32_MAX,
                    len(eocd_bytes) - 22)) + blob[pos + 22:]
    report = analyze(bytes(blob))
    assert not report.candidates[0].valid
    assert report.candidates[0].exclusion_reason == "zip64_eocd_target_bad"


def test_fake_signature_inside_member_data(fixtures):
    # 在 stored 成员压缩数据区植入伪 EOCD 字节：它不在尾部窗口，不影响真候选
    blob = bytearray(fixtures["normal.zip"])
    blob[42:46] = EOCD_SIG.to_bytes(4, "little")
    report = analyze(bytes(blob))
    valid = [c for c in report.candidates if c.valid]
    assert len(valid) == 1
    m = valid[0].members[0]
    assert m.crc_status == "mismatch"  # 数据被改，CRC 抓到


def test_method_8_unsupported_other_methods():
    blob = build_zip([dict(name=b"x", data=b"hi", method=12)])  # bzip2 不支持
    report = analyze(blob)
    m = [c for c in report.candidates if c.valid][0].members[0]
    assert m.crc_status == "skipped_method"
    assert any(f.code == "unsupported_compression" for f in m.findings)
