"""Byte-level ZIP structure parsing.

Nothing here ever writes extracted content to disk.  The parser only records
precise byte ranges of every structure it finds (EOCD candidates, ZIP64
records, central directory records, local file headers, extra fields and data
descriptors) so that an archivist can review them later.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

SIG_LFH = b"PK\x03\x04"
SIG_CEN = b"PK\x01\x02"
SIG_EOCD = b"PK\x05\x06"
SIG_Z64_EOCD = b"PK\x06\x06"
SIG_Z64_LOC = b"PK\x06\x07"
SIG_DD = b"PK\x07\x08"

EOCD_LEN = 22
Z64_LOC_LEN = 20
Z64_EOCD_LEN = 56
CEN_LEN = 46
LFH_LEN = 30

SENT16 = 0xFFFF
SENT32 = 0xFFFFFFFF

EXTRA_ZIP64 = 0x0001

FLAG_ENCRYPTED = 0x0001
FLAG_DESCRIPTOR = 0x0008  # bit 3: sizes/crc live in a data descriptor
FLAG_UTF8 = 0x0800        # bit 11: name/comment are UTF-8


@dataclass
class Budgets:
    """Hard resource limits.  Parsing never exceeds them; violations are
    recorded as budget events instead of raising."""

    max_candidates: int = 256
    max_members: int = 10000
    max_decompress_per_member: int = 64 * 1024 * 1024
    max_decompress_total: int = 256 * 1024 * 1024


@dataclass
class ExtraField:
    tag: int
    declared_len: int
    data: bytes
    truncated: bool


def parse_extra(buf: bytes) -> list[ExtraField]:
    fields: list[ExtraField] = []
    pos = 0
    size = len(buf)
    while pos < size:
        if pos + 4 > size:
            fields.append(ExtraField(-1, size - pos, buf[pos:], True))
            break
        tag, dlen = struct.unpack_from("<HH", buf, pos)
        pos += 4
        if pos + dlen > size:
            fields.append(ExtraField(tag, dlen, buf[pos:], True))
            break
        fields.append(ExtraField(tag, dlen, buf[pos:pos + dlen], False))
        pos += dlen
    return fields


def decode_name(raw: bytes, flags: int) -> str:
    encoding = "utf-8" if flags & FLAG_UTF8 else "cp437"
    return raw.decode(encoding, errors="replace")


def _zip64_extra(fields: list[ExtraField]) -> ExtraField | None:
    for fld in fields:
        if fld.tag == EXTRA_ZIP64 and not fld.truncated:
            return fld
    return None


@dataclass
class LocalHeader:
    offset: int
    error: str | None = None
    version_needed: int = 0
    flags: int = 0
    method: int = 0
    crc32: int = 0
    csize: int = 0
    usize: int = 0
    name: str = ""
    name_raw: bytes = b""
    extras: list[ExtraField] = field(default_factory=list)
    header_len: int = 0
    data_start: int = 0
    zip64: bool = False


def parse_local_header(data: bytes, offset: int) -> LocalHeader:
    size = len(data)
    lh = LocalHeader(offset=offset)
    if offset < 0 or offset + LFH_LEN > size:
        lh.error = "local header offset outside file"
        return lh
    if data[offset:offset + 4] != SIG_LFH:
        lh.error = "bad local header signature"
        return lh
    (_, lh.version_needed, lh.flags, lh.method, _mtime, _mdate,
     lh.crc32, lh.csize, lh.usize, nlen, elen) = struct.unpack_from(
        "<4s5H3L2H", data, offset)
    name_start = offset + LFH_LEN
    name_end = name_start + nlen
    extra_end = name_end + elen
    if extra_end > size:
        lh.error = "local header name/extra truncated by end of file"
        lh.name_raw = data[name_start:min(name_end, size)]
        lh.name = decode_name(lh.name_raw, lh.flags)
        lh.extras = [ExtraField(-1, max(0, size - name_end),
                                data[min(name_end, size):size], True)]
        lh.header_len = size - offset
        lh.data_start = size
        return lh
    lh.name_raw = data[name_start:name_end]
    lh.name = decode_name(lh.name_raw, lh.flags)
    lh.extras = parse_extra(data[name_end:extra_end])
    lh.header_len = LFH_LEN + nlen + elen
    lh.data_start = offset + lh.header_len
    if lh.csize == SENT32 or lh.usize == SENT32:
        z64 = _zip64_extra(lh.extras)
        if z64 is not None:
            pos = 0
            if lh.usize == SENT32 and pos + 8 <= len(z64.data):
                lh.usize = struct.unpack_from("<Q", z64.data, pos)[0]
                pos += 8
            if lh.csize == SENT32 and pos + 8 <= len(z64.data):
                lh.csize = struct.unpack_from("<Q", z64.data, pos)[0]
                pos += 8
            lh.zip64 = True
    return lh


@dataclass
class CdRecord:
    index: int
    offset: int
    header_len: int = 0
    version_made_by: int = 0
    version_needed: int = 0
    flags: int = 0
    method: int = 0
    crc32: int = 0
    csize: int = 0
    usize: int = 0
    name: str = ""
    name_raw: bytes = b""
    extras: list[ExtraField] = field(default_factory=list)
    comment: bytes = b""
    disk_start: int = 0
    external_attr: int = 0
    local_header_offset: int = 0
    zip64: bool = False
    error: str | None = None

    @property
    def utf8(self) -> bool:
        return bool(self.flags & FLAG_UTF8)

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & FLAG_ENCRYPTED)

    @property
    def bit3(self) -> bool:
        return bool(self.flags & FLAG_DESCRIPTOR)


def parse_cd_record(data: bytes, offset: int, index: int) -> tuple[CdRecord, int]:
    size = len(data)
    rec = CdRecord(index=index, offset=offset)
    if offset + CEN_LEN > size:
        rec.error = "central directory record truncated by end of file"
        return rec, size
    if data[offset:offset + 4] != SIG_CEN:
        rec.error = "bad central directory signature"
        return rec, offset + 1
    (_, rec.version_made_by, rec.version_needed, rec.flags, rec.method,
     _mtime, _mdate, rec.crc32, rec.csize, rec.usize,
     nlen, elen, clen, rec.disk_start, _iattr, rec.external_attr,
     rec.local_header_offset) = struct.unpack_from("<4s6H3L5H2L", data, offset)
    rec.header_len = CEN_LEN + nlen + elen + clen
    if offset + rec.header_len > size:
        rec.error = "central directory record name/extra/comment truncated"
        rec.header_len = size - offset
        return rec, size
    name_start = offset + CEN_LEN
    rec.name_raw = data[name_start:name_start + nlen]
    rec.name = decode_name(rec.name_raw, rec.flags)
    rec.extras = parse_extra(data[name_start + nlen:name_start + nlen + elen])
    rec.comment = data[name_start + nlen + elen:offset + rec.header_len]
    if (rec.usize == SENT32 or rec.csize == SENT32
            or rec.local_header_offset == SENT32 or rec.disk_start == SENT16):
        z64 = _zip64_extra(rec.extras)
        if z64 is not None:
            pos = 0
            if rec.usize == SENT32 and pos + 8 <= len(z64.data):
                rec.usize = struct.unpack_from("<Q", z64.data, pos)[0]
                pos += 8
            if rec.csize == SENT32 and pos + 8 <= len(z64.data):
                rec.csize = struct.unpack_from("<Q", z64.data, pos)[0]
                pos += 8
            if rec.local_header_offset == SENT32 and pos + 8 <= len(z64.data):
                rec.local_header_offset = struct.unpack_from("<Q", z64.data, pos)[0]
                pos += 8
            if rec.disk_start == SENT16 and pos + 4 <= len(z64.data):
                rec.disk_start = struct.unpack_from("<L", z64.data, pos)[0]
                pos += 4
            rec.zip64 = True
    return rec, offset + rec.header_len


@dataclass
class EocdCandidate:
    offset: int
    disk_no: int = 0
    cd_disk: int = 0
    entries_disk: int = 0
    entries_total: int = 0
    cd_size: int = 0
    cd_offset: int = 0
    comment_len: int = 0
    comment: bytes = b""
    zip64: bool = False
    zip64_locator_offset: int | None = None
    zip64_eocd_offset: int | None = None
    zip64_total_disks: int | None = None
    status: str = "excluded"  # primary | alternative | excluded
    exclusion_reason: str | None = None
    notes: list[str] = field(default_factory=list)
    records: list[CdRecord] = field(default_factory=list)

    @property
    def cd_end(self) -> int:
        return self.cd_offset + self.cd_size


def parse_eocd_candidate(data: bytes, offset: int, budgets: Budgets,
                         events: list[str]) -> EocdCandidate:
    size = len(data)
    cand = EocdCandidate(offset=offset)
    if offset + EOCD_LEN > size:
        cand.exclusion_reason = "EOCD record truncated by end of file"
        return cand
    (_, cand.disk_no, cand.cd_disk, cand.entries_disk, cand.entries_total,
     cand.cd_size, cand.cd_offset, cand.comment_len) = struct.unpack_from(
        "<4s4H2LH", data, offset)
    comment_end = offset + EOCD_LEN + cand.comment_len
    if comment_end > size:
        cand.exclusion_reason = "EOCD comment overruns end of file"
        return cand
    cand.comment = data[offset + EOCD_LEN:comment_end]
    if comment_end != size:
        cand.notes.append(
            f"comment ends at {comment_end}, {size - comment_end} bytes before EOF")

    needs64 = (SENT16 in (cand.disk_no, cand.cd_disk, cand.entries_disk,
                          cand.entries_total)
               or SENT32 in (cand.cd_size, cand.cd_offset))
    if needs64:
        loc_off = offset - Z64_LOC_LEN
        if loc_off < 0 or data[loc_off:loc_off + 4] != SIG_Z64_LOC:
            cand.exclusion_reason = ("ZIP64 sentinel values present but no "
                                     "ZIP64 locator precedes the EOCD")
            return cand
        cand.zip64 = True
        cand.zip64_locator_offset = loc_off
        (_sig, _loc_disk, z64_off, total_disks) = struct.unpack_from(
            "<4sLQL", data, loc_off)
        cand.zip64_eocd_offset = z64_off
        cand.zip64_total_disks = total_disks
        if z64_off + Z64_EOCD_LEN > size or data[z64_off:z64_off + 4] != SIG_Z64_EOCD:
            cand.exclusion_reason = "ZIP64 EOCD record missing at locator offset"
            return cand
        (_s, _rec_size, _vm, _vn, cand.disk_no, cand.cd_disk, cand.entries_disk,
         cand.entries_total, cand.cd_size,
         cand.cd_offset) = struct.unpack_from("<4sQ2H2L4Q", data, z64_off)

    if cand.cd_offset + cand.cd_size > size:
        cand.exclusion_reason = "central directory range outside file"
        return cand
    trailer_start = cand.zip64_eocd_offset if cand.zip64 else offset
    if cand.cd_end > trailer_start:
        cand.exclusion_reason = "central directory overlaps trailer structures"
        return cand
    if cand.cd_end < trailer_start:
        cand.notes.append(
            f"{trailer_start - cand.cd_end} bytes between central directory end "
            f"and trailer")

    pos = cand.cd_offset
    limit = min(cand.entries_total, budgets.max_members)
    for idx in range(limit):
        rec, pos = parse_cd_record(data, pos, idx)
        cand.records.append(rec)
        if rec.error:
            cand.notes.append(f"record {idx}: {rec.error}")
            break
    if cand.entries_total > budgets.max_members:
        events.append(
            f"member budget exceeded: EOCD at {offset} declares "
            f"{cand.entries_total} entries, parsed {budgets.max_members}")
    if len(cand.records) < cand.entries_total and not any(r.error for r in cand.records):
        cand.notes.append(
            f"only {len(cand.records)} of {cand.entries_total} declared records parsed")
    return cand


@dataclass
class ArchiveParse:
    sha256: str
    size: int
    candidates: list[EocdCandidate]
    budget_events: list[str]


def parse_archive(data: bytes, budgets: Budgets | None = None) -> ArchiveParse:
    budgets = budgets or Budgets()
    events: list[str] = []
    offsets: list[int] = []
    pos = data.find(SIG_EOCD)
    while pos != -1:
        offsets.append(pos)
        if len(offsets) >= budgets.max_candidates:
            events.append(
                f"candidate budget exceeded: more than {budgets.max_candidates} "
                "EOCD signatures; remainder ignored")
            break
        pos = data.find(SIG_EOCD, pos + 1)

    candidates = [parse_eocd_candidate(data, off, budgets, events)
                  for off in offsets]
    valid = [c for c in candidates if c.exclusion_reason is None]
    for cand in candidates:
        cand.status = "excluded" if cand.exclusion_reason else "alternative"
    if valid:
        # A candidate whose comment lands exactly on EOF is the strongest
        # primary.  Every other candidate is KEPT as an alternative graph;
        # nothing is silently discarded in favour of the last directory.
        exact = [c for c in valid
                 if c.offset + EOCD_LEN + c.comment_len == len(data)]
        primary = (exact or valid)[-1]
        primary.status = "primary"
    return ArchiveParse(
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        candidates=candidates,
        budget_events=events,
    )
