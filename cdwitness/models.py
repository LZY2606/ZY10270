"""数据模型：审阅结果全部以精确字节区间表达，不触碰解压后的磁盘文件。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ByteRange:
    """半开区间 [start, end)，end 为排他边界。"""

    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: "ByteRange") -> bool:
        return self.start < other.end and other.start < self.end

    def contains(self, other: "ByteRange") -> bool:
        return self.start <= other.start and other.end <= self.end

    def to_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "length": self.length}


@dataclass
class Finding:
    code: str
    severity: str  # info / low / medium / high / critical
    message: str
    member: Optional[str] = None
    candidate: Optional[int] = None
    range: Optional[ByteRange] = None

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "member": self.member,
            "candidate": self.candidate,
            "range": self.range.to_dict() if self.range else None,
        }


@dataclass
class Member:
    index: int
    name: str
    utf8_flag: bool
    encrypted: bool
    method: int
    flags: int
    bit3_descriptor: bool
    central_header_range: ByteRange
    central_extra_range: ByteRange
    central_comment_range: ByteRange
    local_header_range: Optional[ByteRange]
    local_name_range: Optional[ByteRange]
    local_extra_range: Optional[ByteRange]
    data_range: Optional[ByteRange]
    descriptor_range: Optional[ByteRange]
    descriptor_signed: Optional[bool]  # None 表示无 descriptor
    descriptor_ambiguous: bool
    central_crc: int
    central_comp_size: int
    central_uncomp_size: int
    local_crc: Optional[int]
    local_comp_size: Optional[int]
    local_uncomp_size: Optional[int]
    local_offset: int
    local_offset_source: str  # central32 / zip64_extra
    disk_start: int
    crc_status: str  # ok / mismatch / skipped_encrypted / skipped_budget /
    # skipped_method / skipped_no_data
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "name": self.name,
            "utf8_flag": self.utf8_flag,
            "encrypted": self.encrypted,
            "method": self.method,
            "flags": self.flags,
            "bit3_descriptor": self.bit3_descriptor,
            "central_header_range": self.central_header_range.to_dict(),
            "central_extra_range": self.central_extra_range.to_dict(),
            "central_comment_range": self.central_comment_range.to_dict(),
            "local_header_range": self.local_header_range.to_dict() if self.local_header_range else None,
            "local_name_range": self.local_name_range.to_dict() if self.local_name_range else None,
            "local_extra_range": self.local_extra_range.to_dict() if self.local_extra_range else None,
            "data_range": self.data_range.to_dict() if self.data_range else None,
            "descriptor_range": self.descriptor_range.to_dict() if self.descriptor_range else None,
            "descriptor_signed": self.descriptor_signed,
            "descriptor_ambiguous": self.descriptor_ambiguous,
            "central_crc": self.central_crc,
            "central_comp_size": self.central_comp_size,
            "central_uncomp_size": self.central_uncomp_size,
            "local_crc": self.local_crc,
            "local_comp_size": self.local_comp_size,
            "local_uncomp_size": self.local_uncomp_size,
            "local_offset": self.local_offset,
            "local_offset_source": self.local_offset_source,
            "disk_start": self.disk_start,
            "crc_status": self.crc_status,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Candidate:
    index: int
    eocd_range: ByteRange
    comment_range: ByteRange
    comment_len: int
    disk_no: int
    cd_disk: int
    entries_disk: int
    entries_total: int
    cd_size: int
    cd_offset: int
    zip64: bool
    zip64_locator_range: Optional[ByteRange] = None
    zip64_eocd_range: Optional[ByteRange] = None
    central_directory_range: Optional[ByteRange] = None
    valid: bool = False
    exclusion_reason: Optional[str] = None
    exclusion_detail: Optional[str] = None
    members: list[Member] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "eocd_range": self.eocd_range.to_dict(),
            "comment_range": self.comment_range.to_dict(),
            "comment_len": self.comment_len,
            "disk_no": self.disk_no,
            "cd_disk": self.cd_disk,
            "entries_disk": self.entries_disk,
            "entries_total": self.entries_total,
            "cd_size": self.cd_size,
            "cd_offset": self.cd_offset,
            "zip64": self.zip64,
            "zip64_locator_range": self.zip64_locator_range.to_dict() if self.zip64_locator_range else None,
            "zip64_eocd_range": self.zip64_eocd_range.to_dict() if self.zip64_eocd_range else None,
            "central_directory_range": self.central_directory_range.to_dict() if self.central_directory_range else None,
            "valid": self.valid,
            "exclusion_reason": self.exclusion_reason,
            "exclusion_detail": self.exclusion_detail,
            "members": [m.to_dict() for m in self.members],
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Analysis:
    sha256: str
    size: int
    rejected: bool
    reject_reason: Optional[str]
    candidates: list[Candidate]
    findings: list[Finding]  # 归档级
    preferred_candidate: Optional[int]

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "size": self.size,
            "rejected": self.rejected,
            "reject_reason": self.reject_reason,
            "candidates": [c.to_dict() for c in self.candidates],
            "findings": [f.to_dict() for f in self.findings],
            "preferred_candidate": self.preferred_candidate,
        }
