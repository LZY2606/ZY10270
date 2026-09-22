"""内置审阅样例：全部手工拼装为确定性字节，测试不依赖外部文件或网络。

样例清单：
  normal.zip               普通 stored + deflate，基线
  zip64_sentinel.zip       EOCD/CD 全部使用 ZIP64 哨兵字段
  unsigned_descriptor.zip  bit 3 + 无签名字节的 data descriptor
  fake_eocd_comment.zip    真实 EOCD 注释里藏一个伪 EOCD
  shared_range.zip         两个中央目录条目共享同一压缩区间
  truncated_extra.zip      中央 extra 子字段长度声明越界
  evil_names.zip           路径穿越 + 重复文件名
  multidisk.zip            声明多磁盘字段的单文件
  twin_eocd.zip            尾部两个同时贴边、各自自洽的 EOCD
"""
from __future__ import annotations

import struct
import zlib

from .parser import (CDH_SIG, DD_SIG, EOCD_SIG, LFH_SIG, UINT16_MAX,
                     UINT32_MAX, Z64_EOCD_SIG, Z64_LOC_SIG)


def _deflate_raw(data: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()


def _name_flag(name: bytes) -> int:
    return 0x800 if any(b >= 0x80 for b in name) else 0


def build_zip(entries, *, zip64=False, eocd_comment=b"", disk_no=0,
              cd_disk=0, disk_total=1):
    """entries: dict(name, data, method, descriptor, force_z64, encrypted,
    disk_start, alias_offset, cd_extra_override)。"""
    blob = bytearray()
    metas = []
    for e in entries:
        name = e["name"]
        data = e.get("data", b"")
        method = e.get("method", 0)
        descriptor = e.get("descriptor")  # None / "signed" / "unsigned"
        force_z64 = e.get("force_z64", False)
        encrypted = e.get("encrypted", False)
        disk_start = e.get("disk_start", 0)
        alias = e.get("alias_offset")
        flag = _name_flag(name)
        if descriptor:
            flag |= 0x08
        if encrypted:
            flag |= 0x01
        crc = zlib.crc32(data) & 0xFFFFFFFF
        comp = data if method == 0 else _deflate_raw(data)
        uncomp = len(data)

        if alias is None:
            offset = len(blob)
            l_extra = b""
            if force_z64:
                l_extra = struct.pack("<HHQQ", 0x0001, 16, uncomp, len(comp))
                assert len(l_extra) == 20
            l_crc = 0 if descriptor else crc
            l_cs = 0 if descriptor else len(comp)
            l_us = 0 if descriptor else uncomp
            lfh = struct.pack(
                "<IHHHHHIIIHH", LFH_SIG, 20, flag, method, 0, 0,
                l_crc, l_cs, l_us, len(name), len(l_extra))
            blob += lfh + name + l_extra + comp
            if descriptor == "signed":
                blob += struct.pack("<IIII", DD_SIG, crc, len(comp), uncomp)
            elif descriptor == "unsigned":
                blob += struct.pack("<III", crc, len(comp), uncomp)
        else:
            offset = alias

        cd_extra = b""
        if "cd_extra_override" in e:
            cd_extra = e["cd_extra_override"]
        elif force_z64:
            cd_extra = struct.pack("<HHQQ", 0x0001, 16, uncomp, len(comp))
            assert len(cd_extra) == 20
        c_cs = UINT32_MAX if force_z64 else len(comp)
        c_us = UINT32_MAX if force_z64 else uncomp
        metas.append(dict(name=name, method=method, flag=flag, crc=crc,
                          comp_len=len(comp), uncomp_len=uncomp,
                          offset=offset, disk_start=disk_start,
                          cd_extra=cd_extra, c_cs=c_cs, c_us=c_us,
                          alias=alias is not None))

    cd_start = len(blob)
    for mt in metas:
        cdh = struct.pack(
            "<IHHHHHHIIIHHHHHII", CDH_SIG, 20, 20, mt["flag"],
            mt["method"], 0, 0, mt["crc"], mt["c_cs"], mt["c_us"],
            len(mt["name"]), len(mt["cd_extra"]), 0, mt["disk_start"],
            0, 0, mt["offset"])
        blob += cdh + mt["name"] + mt["cd_extra"]
    cd_size = len(blob) - cd_start
    n_entries = len(metas)

    if zip64:
        z64_start = len(blob)
        blob += struct.pack(
            "<IQHHIIQQQQ", Z64_EOCD_SIG, 44, 45, 45, disk_no, cd_disk,
            n_entries, n_entries, cd_size, cd_start)
        blob += struct.pack(
            "<IIQI", Z64_LOC_SIG, cd_disk, z64_start, disk_total)
        e_disk = e_cddisk = UINT16_MAX
        e_entd = e_entt = UINT16_MAX
        e_cdsize = e_cdoff = UINT32_MAX
    else:
        e_disk, e_cddisk = disk_no, cd_disk
        e_entd = e_entt = n_entries
        e_cdsize, e_cdoff = cd_size, cd_start

    blob += struct.pack(
        "<IHHHHIIH", EOCD_SIG, e_disk, e_cddisk, e_entd, e_entt,
        e_cdsize, e_cdoff, len(eocd_comment))
    blob += eocd_comment
    return bytes(blob)


FIXTURES = {}


def _fake_eocd_comment():
    inner = struct.pack(
        "<IHHHHIIH", EOCD_SIG, 7, 7, 9, 9, 0xDEADBEEF, 0xDEADBEEF, 0)
    comment = inner + b"TAIL"
    return build_zip(
        [dict(name=b"readme.txt", data=b"central directory witness\n")],
        eocd_comment=comment)


def _twin_eocd():
    """两个 EOCD 记录都紧贴文件尾：后者藏在前者的注释里，各自指向一个 CD。"""
    blob = bytearray()
    # 两个局部文件头 + stored 数据
    entries = [(b"a.txt", b"AAAA"), (b"b.txt", b"BBBB")]
    offs = []
    for name, data in entries:
        offs.append(len(blob))
        crc = zlib.crc32(data) & 0xFFFFFFFF
        blob += struct.pack(
            "<IHHHHHIIIHH", LFH_SIG, 20, 0, 0, 0, 0, crc,
            len(data), len(data), len(name), 0)
        blob += name + data

    def cd_record(name, data, off):
        crc = zlib.crc32(data) & 0xFFFFFFFF
        return struct.pack(
            "<IHHHHHHIIIHHHHHII", CDH_SIG, 20, 20, 0, 0, 0, 0,
            crc, len(data), len(data), len(name), 0, 0, 0, 0, 0, off
        ) + name

    cd_a_start = len(blob)
    rec_a = cd_record(entries[0][0], entries[0][1], offs[0])
    blob += rec_a
    cd_b_start = len(blob)
    rec_b = cd_record(entries[1][0], entries[1][1], offs[1])
    blob += rec_b

    # EOCD1 在前，其注释 = EOCD2 完整记录（无注释），两者结束位置相同
    eocd2 = struct.pack(
        "<IHHHHIIH", EOCD_SIG, 0, 0, 1, 1, len(rec_b), cd_b_start, 0)
    eocd1 = struct.pack(
        "<IHHHHIIH", EOCD_SIG, 0, 0, 1, 1, len(rec_a), cd_a_start,
        len(eocd2))
    blob += eocd1 + eocd2
    return bytes(blob)


def all_fixtures():
    global FIXTURES
    if FIXTURES:
        return FIXTURES
    FIXTURES = {
        "normal.zip": build_zip([
            dict(name=b"hello.txt", data=b"hello witness\n"),
            dict(name=b"notes/deflated.txt",
                 data=b"deflate " * 200, method=8),
        ]),
        "zip64_sentinel.zip": build_zip([
            dict(name=b"big-style-a.bin", data=b"A" * 10, force_z64=True),
            dict(name=b"big-style-b.bin", data=b"B" * 20, force_z64=True),
        ], zip64=True),
        "unsigned_descriptor.zip": build_zip([
            dict(name=b"streaming.txt", data=b"data descriptor without "
                 b"signature bytes\n", method=8, descriptor="unsigned"),
        ]),
        "signed_descriptor.zip": build_zip([
            dict(name=b"streaming-s.txt", data=b"signed descriptor\n",
                 method=8, descriptor="signed"),
        ]),
        "fake_eocd_comment.zip": _fake_eocd_comment(),
        "shared_range.zip": _shared_range(),
        "truncated_extra.zip": _truncated_extra(),
        "evil_names.zip": build_zip([
            dict(name=b"../escape.txt", data=b"escaped\n"),
            dict(name=b"dup.txt", data=b"first\n"),
            dict(name=b"dup.txt", data=b"second\n"),
        ]),
        "multidisk.zip": build_zip([
            dict(name=b"span.bin", data=b"multi disk fields\n"),
        ], disk_no=1, cd_disk=1, disk_total=2),
        "twin_eocd.zip": _twin_eocd(),
    }
    return FIXTURES


def _shared_range():
    base = build_zip([
        dict(name=b"visible.txt", data=b"shared compressed payload\n"),
    ])
    # 在第二个中央记录中让同一 local offset 再出现一次
    e = dict(name=b"hidden.txt", data=b"shared compressed payload\n",
             alias_offset=_find_first_offset(base))
    return build_zip([
        dict(name=b"visible.txt", data=b"shared compressed payload\n"),
        e,
    ])


def _find_first_offset(blob):
    return 0


def _truncated_extra():
    # tag=0x0001 声称 20 字节 ZIP64 数据，但整个 extra 只有 4 字节
    bad_extra = struct.pack("<HH", 0x0001, 20)
    return build_zip([
        dict(name=b"cut.txt", data=b"truncated extra field\n",
             cd_extra_override=bad_extra),
    ])
