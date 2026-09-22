"""ZIP 二进制审阅核心：不解压落盘，逐字节保留区间与候选目录图。

设计原则：
* 同时解析所有 EOCD 候选，绝不因"最后一个目录能打开"就抹掉其他候选；
* 中央目录与局部头分别记录，二者冲突都作为证词保留；
* bit 3(数据描述符) 开启时，局部头的零尺寸只作展示、不作布局依据；
* descriptor 是否带 0x08074b50 签名由"与中央目录一致性 + 边界一致性"判定。
"""
from __future__ import annotations

import hashlib
import struct
import zlib

from .budget import Budget, DEFAULT_BUDGET
from .models import Analysis, ByteRange, Candidate, Finding, Member

LFH_SIG = 0x04034B50
CDH_SIG = 0x02014B50
EOCD_SIG = 0x06054B50
Z64_EOCD_SIG = 0x06064B50
Z64_LOC_SIG = 0x07064B50
DD_SIG = 0x08074B50

UINT16_MAX = 0xFFFF
UINT32_MAX = 0xFFFFFFFF

# 固定结构格式
LFH_FMT = "<IHHHHHIIIHH"
LFH_FIXED = 30
CDH_FMT = "<IHHHHHHIIIHHHHHII"
CDH_FIXED = 46
EOCD_FMT = "<IHHHHIIH"
EOCD_FIXED = 22
Z64_LOC_FMT = "<IIQI"
Z64_LOC_FIXED = 20
Z64_EOCD_FMT = "<IQHHIIQQQQ"
Z64_EOCD_FIXED = 56
Z64_EOCD_MIN = 44  # 规范允许尾部可选字段缺失
DD_SIGNED_FMT = "<IIII"
DD_UNSIGNED_FMT = "<III"


class _Unpack:
    def __init__(self, blob: bytes):
        self.blob = blob

    def take(self, fmt: str, offset: int, size: int):
        if offset < 0 or offset + size > len(self.blob):
            return None
        return struct.unpack_from(fmt, self.blob, offset)


def _finding(code, severity, message, member=None, candidate=None, rng=None):
    return Finding(code=code, severity=severity, message=message,
                   member=member, candidate=candidate, range=rng)


def _add32(a: int, b: int):
    """32 位地址加法，回绕时返回 None。"""
    if a < 0 or b < 0:
        return None
    s = a + b
    if s > UINT32_MAX:
        return None
    return s


def scan_eocd_signatures(blob: bytes, budget: Budget):
    """在尾部合法窗口内找出全部 EOCD 签名，返回 [(pos, record_range, comment_range,
    truncated)]。真实 EOCD 必须紧贴文件尾；注释中的伪签名会落到文件内部。"""
    out = []
    n = len(blob)
    window = 22 + budget.max_comment_len
    start = max(0, n - window)
    pos = blob.rfind(EOCD_SIG.to_bytes(4, "little"), start, n)
    count = 0
    while pos != -1:
        if pos + EOCD_FIXED > n:
            out.append((pos, ByteRange(pos, n), None, True))
        else:
            (comment_len,) = struct.unpack_from("<H", blob, pos + 20)
            end = pos + EOCD_FIXED + comment_len
            if end > n:
                out.append((pos, ByteRange(pos, n), None, True))
            else:
                out.append((
                    pos,
                    ByteRange(pos, end),
                    ByteRange(pos + EOCD_FIXED, end),
                    False,
                ))
        count += 1
        if count >= budget.max_candidates:
            break
        pos = blob.rfind(EOCD_SIG.to_bytes(4, "little"), start, pos)
    return out


def _parse_extra(blob, rng):
    """解析 extra 字段，返回 (tag_values, truncated:bool)。

    tag_values: {tag: (data_start, data_end)}，ZIP64(0x0001) 调用方按顺序读。
    任何子字段头或长度越界都记 truncated=True，绝不读越界数据。
    """
    tags = {}
    truncated = False
    p = rng.start
    end = rng.end
    while p < end:
        if p + 4 > end:
            truncated = True
            break
        tag, size = struct.unpack_from("<HH", blob, p)
        ds, de = p + 4, p + 4 + size
        if de > end:
            truncated = True
            break
        tags.setdefault(tag, (ds, de))
        p = de
    return tags, truncated


def _zip64_resolve(blob, cand, n, budget):
    """解析 ZIP64 EOCD record 与 locator，就地更新 cand。返回是否致命。"""
    up = _Unpack(blob)
    # ZIP64 locator 规范上紧贴 EOCD record 之前（允许尾部兼容填充时做有限回退）
    epos = cand.eocd_range.start
    lpos = None
    candidate_pos = epos - Z64_LOC_FIXED
    if candidate_pos >= 0 and blob[candidate_pos:candidate_pos + 4] == \
            Z64_LOC_SIG.to_bytes(4, "little"):
        lpos = candidate_pos
    if lpos is None:
        lstart = max(0, epos - 64)
        lpos = blob.rfind(Z64_LOC_SIG.to_bytes(4, "little"),
                          lstart, epos)
    sentinel_any = (
        cand.disk_no == UINT16_MAX or cand.cd_disk == UINT16_MAX
        or cand.entries_disk == UINT16_MAX or cand.entries_total == UINT16_MAX
        or cand.cd_size == UINT32_MAX or cand.cd_offset == UINT32_MAX
    )
    if sentinel_any and lpos == -1:
        cand.valid = False
        cand.exclusion_reason = "zip64_sentinel_without_locator"
        cand.exclusion_detail = "EOCD 字段为 ZIP64 哨兵但找不到 ZIP64 end of central directory locator"
        return True
    if lpos != -1:
        lhdr = up.take(Z64_LOC_FMT, lpos, Z64_LOC_FIXED)
        if lhdr is None:
            if sentinel_any:
                cand.valid = False
                cand.exclusion_reason = "zip64_locator_truncated"
                cand.exclusion_detail = "ZIP64 locator 被截断"
                return True
        else:
            _, l_disk, z64_offset, l_total = lhdr
            cand.zip64_locator_range = ByteRange(lpos, lpos + Z64_LOC_FIXED)
            if l_total != 1:
                cand.findings.append(_finding(
                    "multidisk_archive", "medium",
                    f"ZIP64 locator 声明 {l_total} 个磁盘，工具只审阅当前磁盘的证词",
                    candidate=cand.index))
            zhdr = up.take(Z64_EOCD_FMT, z64_offset, Z64_EOCD_MIN)
            if zhdr is None or zhdr[0] != Z64_EOCD_SIG:
                if sentinel_any:
                    cand.valid = False
                    cand.exclusion_reason = "zip64_eocd_target_bad"
                    cand.exclusion_detail = (
                        f"locator 指向偏移 {z64_offset}，该处不是 ZIP64 EOCD record")
                    return True
            else:
                rec_size = zhdr[1]
                if rec_size >= Z64_EOCD_MIN - 12 and z64_offset + 12 + rec_size <= n:
                    cand.zip64_eocd_range = ByteRange(z64_offset, z64_offset + 12 + rec_size)
                else:
                    cand.zip64_eocd_range = ByteRange(z64_offset, z64_offset + Z64_EOCD_MIN)
                # ZIP64 EOCD: sig, size, vermade, verneed, disk, cddisk,
                # entries_disk, entries_total, cd_size, cd_offset
                z_disk, z_cddisk = zhdr[4], zhdr[5]
                z_ent_disk, z_ent_total = zhdr[6], zhdr[7]
                z_cd_size, z_cd_offset = zhdr[8], zhdr[9]
                cand.zip64 = True
                if cand.disk_no == UINT16_MAX:
                    cand.disk_no = z_disk
                elif cand.disk_no != z_disk:
                    cand.findings.append(_finding(
                        "zip64_field_conflict", "low",
                        f"EOCD 磁盘号 {cand.disk_no} 与 ZIP64 EOCD {z_disk} 不一致",
                        candidate=cand.index))
                if cand.cd_disk == UINT16_MAX:
                    cand.cd_disk = z_cddisk
                if cand.entries_disk == UINT16_MAX:
                    cand.entries_disk = z_ent_disk
                elif cand.entries_disk != z_ent_disk:
                    cand.findings.append(_finding(
                        "zip64_field_conflict", "low",
                        f"本盘条目数 EOCD={cand.entries_disk} ZIP64={z_ent_disk}",
                        candidate=cand.index))
                if cand.entries_total == UINT16_MAX:
                    cand.entries_total = z_ent_total
                elif cand.entries_total != z_ent_total:
                    cand.findings.append(_finding(
                        "zip64_field_conflict", "low",
                        f"条目总数 EOCD={cand.entries_total} ZIP64={z_ent_total}",
                        candidate=cand.index))
                if cand.cd_size == UINT32_MAX:
                    cand.cd_size = z_cd_size
                elif cand.cd_size != z_cd_size:
                    cand.findings.append(_finding(
                        "zip64_field_conflict", "low",
                        f"中央目录尺寸 EOCD={cand.cd_size} ZIP64={z_cd_size}",
                        candidate=cand.index))
                if cand.cd_offset == UINT32_MAX:
                    cand.cd_offset = z_cd_offset
                elif cand.cd_offset != z_cd_offset:
                    cand.findings.append(_finding(
                        "zip64_field_conflict", "low",
                        f"中央目录偏移 EOCD={cand.cd_offset} ZIP64={z_cd_offset}",
                        candidate=cand.index))
    return False


def _build_candidate(idx, pos, rec_range, comment_range, truncated, blob, n, budget):
    if truncated:
        cand = Candidate(index=idx, eocd_range=rec_range,
                         comment_range=ByteRange(rec_range.end, rec_range.end),
                         comment_len=0, disk_no=0, cd_disk=0, entries_disk=0,
                         entries_total=0, cd_size=0, cd_offset=0, zip64=False)
        cand.valid = False
        cand.exclusion_reason = "eocd_truncated"
        cand.exclusion_detail = "EOCD 记录跨越文件尾，无法读取 22 字节固定头"
        return cand

    fields = struct.unpack_from(EOCD_FMT, blob, pos)
    _, disk_no, cd_disk, entries_disk, entries_total, cd_size, cd_offset, comment_len = fields
    cand = Candidate(
        index=idx, eocd_range=rec_range, comment_range=comment_range,
        comment_len=comment_len, disk_no=disk_no, cd_disk=cd_disk,
        entries_disk=entries_disk, entries_total=entries_total,
        cd_size=cd_size, cd_offset=cd_offset, zip64=False)

    if rec_range.end != n:
        cand.valid = False
        cand.exclusion_reason = "eocd_not_at_tail"
        cand.exclusion_detail = (
            f"该 EOCD 结束于 {rec_range.end}，但文件长 {n}；"
            "真实 EOCD 必须紧贴文件尾，这个签名很可能藏在注释/数据中")
        return cand

    if _zip64_resolve(blob, cand, n, budget):
        return cand

    # 多磁盘：中央目录位于其它磁盘时无法在本文件中验证
    if cand.cd_disk != 0 or cand.disk_no != 0:
        # ZIP64 locator 多盘仅在单盘文件上才致命；本工具只处理单文件
        if cand.cd_disk != cand.disk_no or cand.cd_offset >= n:
            cand.findings.append(_finding(
                "multidisk_archive", "medium",
                f"中央目录声明位于磁盘 {cand.cd_disk}，当前为磁盘 {cand.disk_no}，"
                "本文件无法独立形成完整目录图",
                candidate=cand.index))

    if cand.entries_total > budget.max_entries or cand.entries_disk > budget.max_entries:
        cand.valid = False
        cand.exclusion_reason = "entry_budget_exceeded"
        cand.exclusion_detail = (
            f"条目数 {cand.entries_total}(总)/{cand.entries_disk}(本盘) "
            f"超过预算 {budget.max_entries}")
        return cand

    if cand.cd_offset > UINT32_MAX or cand.cd_size > n:
        cand.valid = False
        cand.exclusion_reason = "integer_wrap_or_oversize"
        cand.exclusion_detail = (
            f"中央目录偏移 {cand.cd_offset} 尺寸 {cand.cd_size} 非法或回绕")
        return cand
    cd_start = cand.cd_offset
    cd_end = cd_start + cand.cd_size
    if cd_start > n or cd_end > n:
        cand.valid = False
        cand.exclusion_reason = "central_directory_out_of_bounds"
        cand.exclusion_detail = (
            f"中央目录区间 [{cd_start},{cd_end}) 超出 {n} 字节文件")
        return cand
    cand.central_directory_range = ByteRange(cd_start, cd_end)
    return cand


def _decode_name(raw: bytes, utf8: bool):
    if utf8:
        return raw.decode("utf-8", errors="replace")
    # CP437 是 APPNOTE 规定的兜底编码
    return raw.decode("cp437", errors="replace")


def _zip64_central_values(blob, tags, c_crc, c_comp, c_uncomp, l_off, disk):
    """按 ZIP64 extra 布局顺序读取（仅对哨兵字段生效）。"""
    vals = {}
    detail = None
    if 0x0001 not in tags:
        return vals, detail
    ds, de = tags[0x0001]
    p = ds
    fields = [
        ("uncomp", c_uncomp == UINT32_MAX, 8),
        ("comp", c_comp == UINT32_MAX, 8),
        ("offset", l_off == UINT32_MAX, 8),
        ("disk", disk == UINT16_MAX, 4),
    ]
    for key, needed, width in fields:
        if needed:
            if p + width > de:
                detail = "ZIP64 extra 子字段声明的 8 字节数据不完整"
                return vals, detail
            vals[key] = int.from_bytes(blob[p:p + width], "little")
            p += width
    return vals, detail


def _parse_central_directory(cand, blob, n, budget):
    rng = cand.central_directory_range
    p = rng.start
    members = []
    expected = cand.entries_disk if cand.entries_disk else cand.entries_total
    for i in range(expected):
        if p + 4 > rng.end:
            cand.valid = False
            cand.exclusion_reason = "central_directory_truncated"
            cand.exclusion_detail = (
                f"第 {i} 条中央目录记录起点 {p} 已无完整签名，声明 {expected} 条")
            return False
        sig = struct.unpack_from("<I", blob, p)[0]
        if sig != CDH_SIG:
            cand.valid = False
            cand.exclusion_reason = "central_bad_signature"
            cand.exclusion_detail = (
                f"偏移 {p} 处签名为 0x{sig:08x}，期望中央目录签名 0x{CDH_SIG:08x}")
            return False
        if p + CDH_FIXED > rng.end:
            cand.valid = False
            cand.exclusion_reason = "central_directory_truncated"
            cand.exclusion_detail = f"第 {i} 条中央目录固定头跨越区间边界 {rng.end}"
            return False
        vals = struct.unpack_from(CDH_FMT, blob, p)
        (_sig, _vmade, _vneed, flag, method, mt, md, crc, comp, uncomp,
         nlen, elen, clen, disk_start, iattr, eattr, l_off) = vals
        name_s = p + CDH_FIXED
        extra_s = name_s + nlen
        comment_s = extra_s + elen
        rec_end = comment_s + clen
        if rec_end > rng.end:
            cand.valid = False
            cand.exclusion_reason = "central_directory_truncated"
            cand.exclusion_detail = (
                f"第 {i} 条记录结束于 {rec_end}，超出中央目录区间 {rng.end}")
            return False
        extra_rng = ByteRange(extra_s, extra_s + elen)
        tags, extra_trunc = _parse_extra(blob, extra_rng)
        zvals, z64_detail = _zip64_central_values(
            blob, tags, crc, comp, uncomp, l_off, disk_start)
        real_uncomp = zvals.get("uncomp", uncomp)
        real_comp = zvals.get("comp", comp)
        real_offset = zvals.get("offset", l_off)
        real_disk = zvals.get("disk", disk_start)
        raw_name = blob[name_s:extra_s]
        utf8 = bool(flag & 0x800)
        name = _decode_name(raw_name, utf8)
        m = Member(
            index=i, name=name, utf8_flag=utf8, encrypted=bool(flag & 0x1),
            method=method, flags=flag, bit3_descriptor=bool(flag & 0x8),
            central_header_range=ByteRange(p, rec_end),
            central_extra_range=extra_rng,
            central_comment_range=ByteRange(comment_s, rec_end),
            local_header_range=None, local_name_range=None,
            local_extra_range=None, data_range=None,
            descriptor_range=None, descriptor_signed=None,
            descriptor_ambiguous=False, central_crc=crc,
            central_comp_size=real_comp, central_uncomp_size=real_uncomp,
            local_crc=None, local_comp_size=None, local_uncomp_size=None,
            local_offset=real_offset,
            local_offset_source="zip64_extra" if "offset" in zvals else "central32",
            disk_start=real_disk, crc_status="skipped_no_data")
        if extra_trunc:
            m.findings.append(_finding(
                "extra_field_truncated", "medium",
                f"成员 {name!r} 中央目录 extra 字段长度声明越界或子字段头不完整",
                member=name, candidate=cand.index, rng=extra_rng))
        if z64_detail:
            m.findings.append(_finding(
                "zip64_extra_truncated", "medium",
                f"成员 {name!r} {z64_detail}",
                member=name, candidate=cand.index, rng=extra_rng))
        if disk_start != real_disk:
            m.findings.append(_finding(
                "multidisk_member", "medium",
                f"成员 {name!r} 声明起始磁盘 {disk_start}（ZIP64: {real_disk}）",
                member=name, candidate=cand.index))
        if real_uncomp > budget.max_uncompressed_member:
            m.findings.append(_finding(
                "uncompressed_member_budget", "high",
                f"成员 {name!r} 声明解压后 {real_uncomp} 字节，"
                f"超过单成员预算 {budget.max_uncompressed_member}，跳过 CRC",
                member=name, candidate=cand.index))
        members.append(m)
        p = rec_end
    if p != rng.end:
        cand.findings.append(_finding(
            "central_directory_size_mismatch", "low",
            f"按 {expected} 条记录解析到 {p}，但 EOCD 声明中央目录结束于 {rng.end}",
            candidate=cand.index, rng=ByteRange(p, rng.end)))
    return members


def _analyze_descriptor(blob, data_start, comp_size, uncomp, crc, n):
    """判定 descriptor 是否带签名。

    返回 (data_range, desc_range, signed, ambiguous, note)。
    规则：分别尝试"无签名(12B)"与"有签名(16B)"两种读法，只有与中央目录的
    CRC/压缩尺寸/解压尺寸全部一致的解读才成立；若恰好都成立，记 ambiguous。
    """
    unsigned_p = data_start + comp_size
    signed_p = data_start + comp_size
    fits_u = 0 <= unsigned_p and unsigned_p + 12 <= n
    fits_s = 0 <= signed_p and signed_p + 16 <= n
    u_ok = s_ok = False
    u_vals = s_vals = None
    if fits_u:
        u_vals = struct.unpack_from(DD_UNSIGNED_FMT, blob, unsigned_p)
        u_ok = (u_vals[0] == crc and u_vals[1] == comp_size and u_vals[2] == uncomp)
    if fits_s and blob[signed_p:signed_p + 4] == DD_SIG.to_bytes(4, "little"):
        s_vals = struct.unpack_from(DD_SIGNED_FMT, blob, signed_p)
        s_ok = (s_vals[1] == crc and s_vals[2] == comp_size and s_vals[3] == uncomp)
    data_end = data_start + comp_size
    if u_ok and s_ok:
        return (ByteRange(data_start, data_end),
                ByteRange(signed_p, signed_p + 16), True, True,
                "descriptor 带签名与无签名两种解读都与中央目录一致")
    if s_ok:
        return (ByteRange(data_start, data_end),
                ByteRange(signed_p, signed_p + 16), True, False, None)
    if u_ok:
        return (ByteRange(data_start, data_end),
                ByteRange(unsigned_p, unsigned_p + 12), False, False, None)
    # 都不一致：优先按签名字节本身判定，保留证据
    if fits_s and blob[signed_p:signed_p + 4] == DD_SIG.to_bytes(4, "little"):
        note = ("带签名 descriptor 字段与中央目录不一致："
                f"descriptor={s_vals[1:]} 中央目录=(crc={crc:#x},"
                f"comp={comp_size},uncomp={uncomp})")
        return (ByteRange(data_start, data_end),
                ByteRange(signed_p, signed_p + 16), True, False, note)
    if fits_u:
        note = ("无签名 descriptor 字段与中央目录不一致："
                f"descriptor={u_vals} 中央目录=(crc={crc:#x},"
                f"comp={comp_size},uncomp={uncomp})")
        return (ByteRange(data_start, data_end),
                ByteRange(unsigned_p, unsigned_p + 12), False, False, note)
    return (ByteRange(data_start, data_end), None, None, False,
            "数据描述符区间越过文件尾，descriptor 被截断")


def _offset_aliased(cand, m):
    """该成员的 local offset 是否与前面的另一个成员完全相同（共享局部头）。"""
    for other in cand.members:
        if other.index < m.index and other.local_offset == m.local_offset:
            return True
    return False


def _resolve_local(cand, m, blob, n, uncomp_total_left, budget):
    """解析成员局部头与压缩数据区间，并执行 CRC 验证（全部在内存中）。"""
    off = m.local_offset
    if m.disk_start != 0:
        m.findings.append(_finding(
            "multidisk_member", "medium",
            f"成员 {m.name!r} 声明起始磁盘 {m.disk_start}（当前磁盘 {cand.disk_no}），"
            "跨盘部分无法在本文件内验证",
            member=m.name, candidate=cand.index))
    elif m.disk_start != cand.disk_no:
        m.findings.append(_finding(
            "multidisk_member", "medium",
            f"成员 {m.name!r} 起始磁盘 {m.disk_start} 与 EOCD 磁盘 {cand.disk_no} 不一致",
            member=m.name, candidate=cand.index))
    if off < 0 or off + LFH_FIXED > n:
        m.findings.append(_finding(
            "local_header_out_of_bounds", "high",
            f"成员 {m.name!r} 局部头偏移 {off} 越界或 32 位回绕",
            member=m.name, candidate=cand.index,
            rng=ByteRange(max(0, off), min(n, off + LFH_FIXED))))
        return
    vals = struct.unpack_from(LFH_FMT, blob, off)
    (_sig, _ver, l_flag, l_method, _mt, _md, l_crc, l_comp, l_uncomp,
     nlen, elen) = vals
    if _sig != LFH_SIG:
        m.findings.append(_finding(
            "local_bad_signature", "high",
            f"成员 {m.name!r} 偏移 {off} 处签名 0x{_sig:08x} 非局部头签名",
            member=m.name, candidate=cand.index,
            rng=ByteRange(off, off + 4)))
    lname_s = off + LFH_FIXED
    lextra_s = lname_s + nlen
    ldata_s = lextra_s + elen
    m.local_header_range = ByteRange(off, ldata_s)
    m.local_name_range = ByteRange(lname_s, lextra_s)
    m.local_extra_range = ByteRange(lextra_s, ldata_s)
    m.local_crc = l_crc
    m.local_comp_size = l_comp
    m.local_uncomp_size = l_uncomp
    tags, extra_trunc = _parse_extra(blob, m.local_extra_range)
    if extra_trunc:
        m.findings.append(_finding(
            "extra_field_truncated", "medium",
            f"成员 {m.name!r} 局部头 extra 字段被截断（长度声明越界）",
            member=m.name, candidate=cand.index,
            rng=m.local_extra_range))

    # 局部头名称与中央目录名称比对
    raw_lname = blob[lname_s:lextra_s]
    lname = _decode_name(raw_lname, bool(l_flag & 0x800))
    # 多个中央目录条目指向同一局部头（共享区间）时，名称天然不同，不算矛盾
    if lname != m.name and not _offset_aliased(cand, m):
        m.findings.append(_finding(
            "name_mismatch", "medium",
            f"局部头文件名 {lname!r} 与中央目录 {m.name!r} 不一致",
            member=m.name, candidate=cand.index))
    if bool(l_flag & 0x1) != m.encrypted:
        m.findings.append(_finding(
            "encryption_flag_conflict", "high",
            f"局部头加密位={bool(l_flag & 0x1)} 与中央目录={m.encrypted} 冲突",
            member=m.name, candidate=cand.index))
    if l_method != m.method:
        m.findings.append(_finding(
            "method_mismatch", "low",
            f"局部头压缩方法 {l_method} 与中央目录 {m.method} 不一致",
            member=m.name, candidate=cand.index))

    # bit 3：局部头的 CRC/尺寸零值是占位，绝不能当作真实零尺寸
    if m.bit3_descriptor:
        if l_comp == 0 and l_uncomp == 0 and l_crc == 0:
            m.findings.append(_finding(
                "local_zero_placeholder", "info",
                f"成员 {m.name!r} bit 3 已置位，局部头零 CRC/尺寸为占位值，"
                "布局以中央目录为准",
                member=m.name, candidate=cand.index,
                rng=ByteRange(off + 14, off + 26)))
        comp = m.central_comp_size
    else:
        if (l_comp, l_uncomp, l_crc) != (
                m.central_comp_size, m.central_uncomp_size, m.central_crc):
            m.findings.append(_finding(
                "local_central_size_mismatch", "low",
                f"成员 {m.name!r} 局部头(crc={l_crc:#x},comp={l_comp},"
                f"uncomp={l_uncomp}) 与中央目录(crc={m.central_crc:#x},"
                f"comp={m.central_comp_size},uncomp={m.central_uncomp_size}) 不一致",
                member=m.name, candidate=cand.index))
        comp = m.central_comp_size

    data_end = ldata_s + comp
    if ldata_s > n or data_end > n or data_end < ldata_s:
        m.findings.append(_finding(
            "data_out_of_bounds", "high",
            f"成员 {m.name!r} 压缩数据区间 [{ldata_s},{data_end}) 越界或回绕",
            member=m.name, candidate=cand.index,
            rng=ByteRange(min(ldata_s, n), min(data_end, n))))
        m.data_range = ByteRange(ldata_s, min(data_end, n))
        return

    if m.bit3_descriptor:
        dr, ddr, signed, ambig, note = _analyze_descriptor(
            blob, ldata_s, comp, m.central_uncomp_size, m.central_crc, n)
        m.data_range = dr
        m.descriptor_range = ddr
        m.descriptor_signed = signed
        m.descriptor_ambiguous = ambig
        if note:
            m.findings.append(_finding(
                "descriptor_inconsistent", "medium",
                f"成员 {m.name!r} {note}",
                member=m.name, candidate=cand.index,
                rng=ddr))
        if ambig:
            m.findings.append(_finding(
                "descriptor_signature_ambiguous", "medium",
                f"成员 {m.name!r} descriptor 签名有无存在两种一致解读",
                member=m.name, candidate=cand.index, rng=ddr))
        if signed is False and not note:
            m.findings.append(_finding(
                "descriptor_unsigned", "info",
                f"成员 {m.name!r} 使用无签名字节的 data descriptor",
                member=m.name, candidate=cand.index, rng=ddr))
    else:
        m.data_range = ByteRange(ldata_s, data_end)
        if blob[data_end:data_end + 4] == DD_SIG.to_bytes(4, "little"):
            m.findings.append(_finding(
                "unexpected_descriptor_signature", "low",
                f"成员 {m.name!r} bit 3 未置位但数据后出现 descriptor 签名字节",
                member=m.name, candidate=cand.index,
                rng=ByteRange(data_end, min(n, data_end + 16))))

    _verify_crc(cand, m, blob, n, uncomp_total_left, budget)


def _verify_crc(cand, m, blob, n, uncomp_total_left, budget):
    if m.encrypted:
        m.crc_status = "skipped_encrypted"
        return
    if not m.data_range or m.data_range.end > n:
        m.crc_status = "skipped_no_data"
        return
    if m.central_uncomp_size > budget.max_uncompressed_member:
        m.crc_status = "skipped_budget"
        return
    if m.central_uncomp_size > uncomp_total_left:
        m.findings.append(_finding(
            "uncompressed_total_budget", "high",
            f"累计解压量超过总预算 {budget.max_uncompressed_total}，跳过 {m.name!r} 的 CRC",
            member=m.name, candidate=cand.index))
        m.crc_status = "skipped_budget"
        return
    comp_blob = blob[m.data_range.start:m.data_range.end]
    try:
        if m.method == 0:
            raw = comp_blob
        elif m.method == 8:
            do = zlib.decompressobj(-15)
            raw = do.decompress(comp_blob, budget.max_uncompressed_member + 1)
            raw += do.flush()
        else:
            m.findings.append(_finding(
                "unsupported_compression", "medium",
                f"成员 {m.name!r} 压缩方法 {m.method} 不受支持，跳过 CRC",
                member=m.name, candidate=cand.index, rng=m.data_range))
            m.crc_status = "skipped_method"
            return
    except zlib.error as exc:
        m.crc_status = "mismatch"
        m.findings.append(_finding(
            "crc_decompress_error", "high",
            f"成员 {m.name!r} 压缩流无法解压：{exc}",
            member=m.name, candidate=cand.index, rng=m.data_range))
        return
    if len(raw) != m.central_uncomp_size:
        m.findings.append(_finding(
            "uncompressed_size_mismatch", "high",
            f"成员 {m.name!r} 实际解压 {len(raw)} 字节，"
            f"中央目录声明 {m.central_uncomp_size}",
            member=m.name, candidate=cand.index, rng=m.data_range))
    if len(raw) > budget.max_uncompressed_member:
        m.crc_status = "skipped_budget"
        return
    actual = zlib.crc32(raw) & 0xFFFFFFFF
    if actual != m.central_crc:
        m.crc_status = "mismatch"
        m.findings.append(_finding(
            "crc_mismatch", "high",
            f"成员 {m.name!r} CRC 不匹配：实际 0x{actual:08x} "
            f"中央目录 0x{m.central_crc:08x}",
            member=m.name, candidate=cand.index, rng=m.data_range))
    else:
        m.crc_status = "ok"

def _global_checks(cand, blob):
    members = cand.members
    cd_rng = cand.central_directory_range

    # 目录指向目录内部：局部头落在中央目录区间
    for m in members:
        if m.local_header_range and cd_rng and cd_rng.overlaps(m.local_header_range):
            m.findings.append(_finding(
                "local_header_inside_central_directory", "high",
                f"成员 {m.name!r} 的局部头区间位于中央目录内部，疑似目录伪造",
                member=m.name, candidate=cand.index,
                rng=m.local_header_range))

    # 数据区间与中央目录交叠（压缩数据藏在目录区）
    for m in members:
        if m.data_range and cd_rng and cd_rng.overlaps(m.data_range):
            m.findings.append(_finding(
                "data_inside_central_directory", "high",
                f"成员 {m.name!r} 的压缩数据区间与中央目录交叠",
                member=m.name, candidate=cand.index, rng=m.data_range))

    # 重叠成员（压缩区间共享/交叠）
    ordered = sorted(
        [m for m in members if m.data_range],
        key=lambda x: (x.data_range.start, x.data_range.end))
    for i in range(1, len(ordered)):
        prev, cur = ordered[i - 1], ordered[i]
        if prev.data_range.overlaps(cur.data_range):
            same = prev.data_range.start == cur.data_range.start and \
                prev.data_range.end == cur.data_range.end
            code = "shared_compressed_range" if same else "overlapping_members"
            sev = "critical" if same else "high"
            msg = (f"成员 {prev.name!r} 与 {cur.name!r} 共享同一压缩区间"
                   if same else
                   f"成员 {prev.name!r} 与 {cur.name!r} 压缩区间交叠")
            for m in (prev, cur):
                m.findings.append(_finding(
                    code, sev, msg, member=m.name, candidate=cand.index,
                    rng=cur.data_range))

    # 局部头落在别的成员数据区
    for m in members:
        if not m.local_header_range:
            continue
        for other in members:
            if other is m or not other.data_range:
                continue
            if other.data_range.contains(m.local_header_range):
                m.findings.append(_finding(
                    "local_header_inside_member_data", "high",
                    f"成员 {m.name!r} 的局部头藏在 {other.name!r} 的压缩数据中",
                    member=m.name, candidate=cand.index,
                    rng=m.local_header_range))

    # 重复文件名
    seen = {}
    for m in members:
        key = m.name
        if key in seen:
            msg = f"文件名 {key!r} 在中央目录出现多次（索引 {seen[key]} 与 {m.index}）"
            for idx in (seen[key], m.index):
                members[idx].findings.append(_finding(
                    "duplicate_name", "medium", msg,
                    member=key, candidate=cand.index))
        else:
            seen[key] = m.index

    # 路径穿越
    for m in members:
        name = m.name.replace("\\", "/")
        parts = [p for p in name.split("/") if p not in ("", ".")]
        climbs = sum(1 for p in parts if p == "..")
        if name.startswith("/") or (len(parts) >= 2 and parts[0].endswith(":")):
            m.findings.append(_finding(
                "path_traversal", "high",
                f"成员 {m.name!r} 使用绝对路径或盘符，存在穿越风险",
                member=m.name, candidate=cand.index))
        elif climbs:
            m.findings.append(_finding(
                "path_traversal", "high",
                f"成员 {m.name!r} 含 {climbs} 个 '..' 段，存在目录穿越风险",
                member=m.name, candidate=cand.index))

    # 加密成员归档级汇总
    enc = [m for m in members if m.encrypted]
    if enc:
        cand.findings.append(_finding(
            "encrypted_members", "medium",
            f"{len(enc)} 个成员声明加密，内容无法在无口令情况下验证："
            + ", ".join(m.name for m in enc[:10]),
            candidate=cand.index))


def analyze(blob: bytes, budget: Budget = DEFAULT_BUDGET) -> Analysis:
    """对整包字节做审阅，返回全部 EOCD 候选与每个候选的目录图。"""
    n = len(blob)
    sha = hashlib.sha256(blob).hexdigest()
    findings = []

    if n > budget.max_file_size:
        return Analysis(
            sha256=sha, size=n, rejected=True,
            reject_reason=(f"文件 {n} 字节超过预算 "
                           f"{budget.max_file_size}，拒绝解析"),
            candidates=[], findings=findings, preferred_candidate=None)

    sigs = scan_eocd_signatures(blob, budget)
    if len(sigs) >= budget.max_candidates:
        findings.append(_finding(
            "eocd_candidate_budget", "low",
            f"尾部窗口内 EOCD 签名达到候选上限 {budget.max_candidates}，"
            "只保留前序候选，请人工复核"))

    candidates = []
    for idx, (pos, rec, comment, truncated) in enumerate(sigs):
        cand = _build_candidate(idx, pos, rec, comment, truncated, blob, n, budget)
        candidates.append(cand)
        if not cand.valid and cand.exclusion_reason:
            continue
        members = _parse_central_directory(cand, blob, n, budget)
        if members is False:
            continue
        cand.members = members
        if not members:
            cand.valid = True
            continue
        uncomp_total_left = budget.max_uncompressed_total
        total_declared = sum(m.central_uncomp_size for m in members)
        if total_declared > budget.max_uncompressed_total:
            cand.findings.append(_finding(
                "uncompressed_total_budget", "high",
                f"中央目录声明解压总量 {total_declared} 字节，"
                f"超过总预算 {budget.max_uncompressed_total}，部分成员跳过 CRC",
                candidate=cand.index))
        for m in members:
            before = uncomp_total_left
            _resolve_local(cand, m, blob, n, uncomp_total_left, budget)
            if m.crc_status == "ok":
                uncomp_total_left = max(0, before - m.central_uncomp_size)
            if m.central_uncomp_size > budget.max_uncompressed_member:
                continue
        _global_checks(cand, blob)
        cand.valid = True

    preferred = None
    valid = [c for c in candidates if c.valid]
    if valid:
        # 确定性规则：不选"最后一个能打开的"，而是选 EOCD 位于真实文件尾、
        # 无致命冲突的候选；并列时取 EOCD 最靠后者（规范结构）。
        preferred = max(valid, key=lambda c: c.eocd_range.start).index
    if len(valid) > 1:
        findings.append(_finding(
            "multiple_valid_directories", "high",
            f"存在 {len(valid)} 个互相独立且自洽的中央目录候选，"
            "已全部保留；尾部目录可能是攻击者追加的，请对照审阅"))
    if not valid:
        findings.append(_finding(
            "no_valid_directory", "critical",
            "所有 EOCD 候选都无法形成自洽的中央目录图，归档已损坏或被刻意隐藏"))
    elif len(valid) == 1:
        only = valid[0]
        if any(m.data_range for m in only.members):
            pass

    return Analysis(
        sha256=sha, size=n, rejected=False, reject_reason=None,
        candidates=candidates, findings=findings,
        preferred_candidate=preferred)
