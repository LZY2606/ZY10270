import struct
import zlib

from zipforensics import fixtures
from zipforensics.analysis import build_report, is_traversal
from zipforensics.fixtures import _cen, _eocd, _lfh
from zipforensics.parser import Budgets


def primary(report):
    return next(c for c in report["candidates"] if c["status"] == "primary")


def kinds(report):
    return {a["kind"] for a in report["anomalies"]}


def test_crc_mismatch_detected():
    data = bytearray(fixtures.build("zip64-sentinel"))
    report0 = build_report(bytes(data))
    m = primary(report0)["members"][0]
    data[m["data_start"]] ^= 0xFF  # corrupt one payload byte
    report = build_report(bytes(data))
    member = primary(report)["members"][0]
    assert member["crc_status"] == "mismatch"
    assert member["crc_actual"] != member["crc_expected"]


def test_overlap_and_pointer_anomalies():
    report = build_report(fixtures.build("shared-range"))
    assert "overlap" in kinds(report)
    assert "pointer_into_member_data" in kinds(report)


def test_encrypted_member_flagged_and_crc_skipped():
    name, payload = b"secret.txt", b"not really encrypted"
    crc = zlib.crc32(payload)
    lfh = _lfh(name, 0x0001, 0, crc, len(payload), len(payload))
    cen = _cen(name, 0x0001, 0, crc, len(payload), len(payload), 0)
    data = lfh + payload + cen + _eocd(1, len(cen), len(lfh) + len(payload))
    report = build_report(data)
    member = primary(report)["members"][0]
    assert member["encrypted"] is True
    assert member["crc_status"] == "skipped: encrypted"
    assert "encrypted" in kinds(report)


def test_path_traversal_and_duplicate_names():
    payload = b"x"
    crc = zlib.crc32(payload)
    names = [b"../evil.txt", b"../evil.txt", b"C:\\abs.txt"]
    body, records = b"", []
    for n in names:
        records.append((n, len(body)))
        body += _lfh(n, 0, 0, crc, 1, 1) + payload
    cd = b"".join(_cen(n, 0, 0, crc, 1, 1, off) for n, off in records)
    data = body + cd + _eocd(len(names), len(cd), len(body))
    report = build_report(data)
    assert "path_traversal" in kinds(report)
    assert "duplicate_name" in kinds(report)
    assert is_traversal("/abs") and is_traversal("a/../../b")
    assert not is_traversal("normal/path.txt")


def test_multi_disk_fields_flagged():
    payload = b"d"
    crc = zlib.crc32(payload)
    name = b"m.txt"
    lfh = _lfh(name, 0, 0, crc, 1, 1)
    cen = _cen(name, 0, 0, crc, 1, 1, 0, disk_start=2)
    data = lfh + payload + cen + _eocd(1, len(cen), len(lfh) + 1, disk_no=1)
    report = build_report(data)
    assert "multi_disk" in kinds(report)


def test_range_overflow_flagged():
    name = b"big.txt"
    huge = 0xFFFFFFF0  # wrapped/truncated size: end lands far beyond EOF
    lfh = _lfh(name, 0, 0, 0, huge, 10)
    cen = _cen(name, 0, 0, 0, huge, 10, 0)
    data = lfh + cen + _eocd(1, len(cen), len(lfh))
    report = build_report(data)
    assert "range_overflow" in kinds(report)
    member = primary(report)["members"][0]
    assert member["crc_status"] == "skipped: data range outside file"


def test_member_budget_event():
    report = build_report(fixtures.build("shared-range"),
                          budgets=Budgets(max_members=1))
    assert any("member budget" in e for e in report["budget_events"])
    assert len(primary(report)["members"]) == 1


def test_decompression_budget_skips_crc():
    report = build_report(fixtures.build("nosig-descriptor"),
                          budgets=Budgets(max_decompress_per_member=4))
    member = primary(report)["members"][0]
    assert member["crc_status"] == "skipped: budget"
    assert any("budget" in e for e in report["budget_events"])


def test_bit3_zero_sizes_not_trusted():
    # local header says 0/0/0 under bit 3; central directory is authoritative
    report = build_report(fixtures.build("nosig-descriptor"))
    member = primary(report)["members"][0]
    assert member["local"]["csize"] == 0
    assert member["cd"]["csize"] > 0
    assert member["data_end"] - member["data_start"] == member["cd"]["csize"]


def test_descriptor_with_signature_parsed():
    name = b"sig.txt"
    payload = b"signed descriptor payload"
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    cdata = comp.compress(payload) + comp.flush()
    crc = zlib.crc32(payload)
    lfh = _lfh(name, 0x0008, 8, 0, 0, 0)
    dd = b"PK\x07\x08" + struct.pack("<LLL", crc, len(cdata), len(payload))
    cen = _cen(name, 0x0008, 8, crc, len(cdata), len(payload), 0)
    data = lfh + cdata + dd + cen + _eocd(1, len(cen), len(lfh) + len(cdata) + len(dd))
    report = build_report(data)
    desc = primary(report)["members"][0]["descriptor"]
    assert desc["has_signature"] is True
    assert desc["length"] == 16
    assert desc["consistent"] is True
