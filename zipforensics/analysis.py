"""Cross-checking layer: turns a raw parse into a review report.

For every central-directory record we confront three sources of truth:
the central directory claim, the local header claim, and the actual byte
range of the compressed data.  CRCs are verified in memory only.
"""

from __future__ import annotations

import bisect
import struct
import zlib

from .parser import (SIG_DD, ArchiveParse, Budgets, CdRecord, EocdCandidate,
                     parse_archive, parse_local_header)


def is_traversal(name: str) -> bool:
    if name.startswith(("/", "\\")):
        return True
    if len(name) >= 2 and name[1] == ":":
        return True
    return ".." in name.replace("\\", "/").split("/")


def _extras_dict(extras) -> list[dict]:
    return [{"tag": f.tag, "declared_len": f.declared_len,
             "len": len(f.data), "truncated": f.truncated} for f in extras]


def resolve_descriptor(data: bytes, dd_off: int, cd_crc: int, cd_csize: int,
                       cd_usize: int) -> dict:
    """Decide whether a data descriptor carries the PK\\x07\\x08 signature by
    consistency constraints: the decoded values must equal the central
    directory claims and the byte after the descriptor must be a plausible
    next structure (PK signature or EOF)."""
    size = len(data)
    options: list[tuple[bool, int, int, int, int]] = []  # sig, len, crc, cs, us
    if data[dd_off:dd_off + 4] == SIG_DD:
        if dd_off + 16 <= size:
            crc, cs, us = struct.unpack_from("<LLL", data, dd_off + 4)
            options.append((True, 16, crc, cs, us))
        if dd_off + 28 <= size:
            crc = struct.unpack_from("<L", data, dd_off + 4)[0]
            cs, us = struct.unpack_from("<QQ", data, dd_off + 8)
            options.append((True, 28, crc, cs, us))
    if dd_off + 12 <= size:
        crc, cs, us = struct.unpack_from("<LLL", data, dd_off)
        options.append((False, 12, crc, cs, us))
    if dd_off + 24 <= size:
        crc = struct.unpack_from("<L", data, dd_off)[0]
        cs, us = struct.unpack_from("<QQ", data, dd_off + 4)
        options.append((False, 24, crc, cs, us))

    def next_ok(pos: int) -> bool:
        return pos >= size or data[pos:pos + 2] == b"PK"

    perfect = [o for o in options
               if (o[2], o[3], o[4]) == (cd_crc, cd_csize, cd_usize)
               and next_ok(dd_off + o[1])]
    rationale = ""
    consistent = True
    if len(perfect) == 1:
        chosen = perfect[0]
        rationale = ("descriptor values match central directory and the "
                     "following structure is aligned")
    elif len(perfect) > 1:
        signed = [o for o in perfect if o[0]]
        chosen = signed[0] if signed else perfect[0]
        rationale = ("ambiguous layout; preferred the signature form that "
                     "matches central directory values")
    else:
        value_match = [o for o in options
                       if (o[2], o[3], o[4]) == (cd_crc, cd_csize, cd_usize)]
        if value_match:
            chosen = value_match[0]
            rationale = ("values match central directory but the following "
                         "structure is misaligned")
        elif options:
            signed = [o for o in options if o[0]]
            chosen = signed[0] if signed else options[0]
            rationale = "descriptor values contradict the central directory"
        else:
            return {"offset": dd_off, "length": 0, "has_signature": None,
                    "crc32": None, "csize": None, "usize": None,
                    "consistent": False,
                    "rationale": "no room for a data descriptor"}
        consistent = False
    has_sig, length, crc, cs, us = chosen
    return {"offset": dd_off, "length": length, "has_signature": has_sig,
            "crc32": crc, "csize": cs, "usize": us,
            "consistent": consistent, "rationale": rationale}


def verify_crc(data: bytes, start: int, end: int, method: int,
               expected_crc: int, expected_usize: int, budgets: Budgets,
               state: dict, events: list[str]) -> tuple[str, int | None]:
    """Decompress in memory (never to disk) and verify CRC-32 + size."""
    if method not in (0, 8):
        return f"skipped: unsupported method {method}", None
    remaining_member = budgets.max_decompress_per_member
    remaining_total = budgets.max_decompress_total - state["decompressed_total"]
    limit = min(remaining_member, remaining_total)
    if limit <= 0:
        events.append("decompression budget exhausted; CRC check skipped")
        return "skipped: budget", None
    comp = data[start:end]
    if method == 0:
        out = comp
        if len(out) > limit:
            events.append(
                f"stored member of {len(out)} bytes exceeds decompression "
                "budget; CRC check skipped")
            return "skipped: budget", None
    else:
        decomp = zlib.decompressobj(-15)
        try:
            out = decomp.decompress(comp, limit + 1)
            if decomp.unconsumed_tail:
                events.append("member output exceeds decompression budget; "
                              "CRC check skipped")
                return "skipped: budget", None
            out += decomp.flush()
        except zlib.error as exc:
            return f"error: deflate stream invalid ({exc})", None
        if len(out) > limit:
            events.append("member output exceeds decompression budget; "
                          "CRC check skipped")
            return "skipped: budget", None
    state["decompressed_total"] += len(out)
    actual = zlib.crc32(out) & 0xFFFFFFFF
    if actual != expected_crc or len(out) != expected_usize:
        return "mismatch", actual
    return "ok", actual


def _anomaly(candidate: int | None, kind: str, detail: str) -> dict:
    return {"candidate": candidate, "kind": kind, "detail": detail}


def _build_member(data: bytes, cand: EocdCandidate, rec: CdRecord,
                  budgets: Budgets, state: dict, events: list[str],
                  anomalies: list[dict], ci: int) -> dict:
    notes: list[str] = []
    lh = parse_local_header(data, rec.local_header_offset)
    local_dict = None
    data_start = data_end = None
    if lh.error:
        notes.append(f"local header: {lh.error}")
    else:
        local_dict = {
            "offset": lh.offset, "header_len": lh.header_len,
            "flags": lh.flags, "method": lh.method, "crc32": lh.crc32,
            "csize": lh.csize, "usize": lh.usize, "name": lh.name,
            "zip64": lh.zip64, "extras": _extras_dict(lh.extras),
        }
        data_start = lh.data_start
        data_end = data_start + rec.csize
        if rec.bit3:
            # Bit 3: zero sizes in the local header MUST NOT be trusted;
            # the central directory is authoritative.
            if (lh.crc32, lh.csize, lh.usize) == (0, 0, 0):
                notes.append("bit 3 set: local header sizes are zero; "
                             "trusting central directory values")
            elif (lh.crc32, lh.csize, lh.usize) != (rec.crc32, rec.csize, rec.usize):
                notes.append("bit 3 set: local header values ignored in "
                             "favour of the central directory")
        else:
            if (lh.crc32, lh.csize, lh.usize) != (rec.crc32, rec.csize, rec.usize):
                notes.append(
                    f"local/central mismatch: local crc={lh.crc32:#x} "
                    f"csize={lh.csize} usize={lh.usize}")
                anomalies.append(_anomaly(
                    ci, "size_mismatch",
                    f"member {rec.name!r}: local and central headers disagree"))
        if lh.name != rec.name:
            notes.append(f"name mismatch: local {lh.name!r} vs "
                         f"central {rec.name!r}")
        if any(f.truncated for f in lh.extras):
            anomalies.append(_anomaly(
                ci, "extra_truncated",
                f"member {rec.name!r}: local header extra field truncated"))

    descriptor = None
    if rec.bit3 and data_start is not None and data_end <= len(data):
        descriptor = resolve_descriptor(data, data_end, rec.crc32,
                                        rec.csize, rec.usize)
        if not descriptor["consistent"]:
            anomalies.append(_anomaly(
                ci, "descriptor_inconsistent",
                f"member {rec.name!r}: {descriptor['rationale']}"))

    if rec.encrypted:
        crc_status, crc_actual = "skipped: encrypted", None
    elif data_start is None:
        crc_status, crc_actual = "skipped: no local header", None
    elif data_end > len(data):
        crc_status, crc_actual = "skipped: data range outside file", None
    else:
        crc_status, crc_actual = verify_crc(
            data, data_start, data_end, rec.method, rec.crc32, rec.usize,
            budgets, state, events)

    return {
        "index": rec.index, "name": rec.name,
        "method": rec.method, "utf8": rec.utf8, "encrypted": rec.encrypted,
        "bit3": rec.bit3, "zip64": rec.zip64,
        "cd": {"offset": rec.offset, "header_len": rec.header_len,
               "flags": rec.flags, "crc32": rec.crc32, "csize": rec.csize,
               "usize": rec.usize, "local_header_offset": rec.local_header_offset,
               "disk_start": rec.disk_start, "extras": _extras_dict(rec.extras)},
        "local": local_dict,
        "data_start": data_start, "data_end": data_end,
        "descriptor": descriptor,
        "crc_status": crc_status, "crc_expected": rec.crc32,
        "crc_actual": crc_actual,
        "notes": notes,
    }


def analyze(data: bytes, parse: ArchiveParse,
            budgets: Budgets | None = None, name: str | None = None) -> dict:
    budgets = budgets or Budgets()
    events = list(parse.budget_events)
    anomalies: list[dict] = []
    state = {"decompressed_total": 0}
    size = len(data)
    candidates_out: list[dict] = []

    for ci, cand in enumerate(parse.candidates):
        cout = {
            "offset": cand.offset,
            "kind": "zip64" if cand.zip64 else "classic",
            "status": cand.status,
            "exclusion_reason": cand.exclusion_reason,
            "disk_no": cand.disk_no, "cd_disk": cand.cd_disk,
            "entries_disk": cand.entries_disk,
            "entries_total": cand.entries_total,
            "cd_offset": cand.cd_offset, "cd_size": cand.cd_size,
            "cd_end": cand.cd_end,
            "comment_len": cand.comment_len,
            "comment_text": cand.comment.decode("utf-8", errors="replace"),
            "zip64_locator_offset": cand.zip64_locator_offset,
            "zip64_eocd_offset": cand.zip64_eocd_offset,
            "notes": list(cand.notes),
            "members": [],
        }
        candidates_out.append(cout)
        if cand.status == "excluded":
            continue

        if cand.disk_no or cand.cd_disk or cand.entries_disk != cand.entries_total:
            anomalies.append(_anomaly(
                ci, "multi_disk",
                f"EOCD declares disk {cand.disk_no}, CD disk {cand.cd_disk}, "
                f"entries {cand.entries_disk}/{cand.entries_total}"))

        seen_names: dict[str, int] = {}
        ranges: list[tuple[int, int, str, int]] = []
        for rec in cand.records:
            view = _build_member(data, cand, rec, budgets, state, events,
                                 anomalies, ci)
            cout["members"].append(view)
            if rec.name in seen_names:
                anomalies.append(_anomaly(
                    ci, "duplicate_name",
                    f"name {rec.name!r} used by members "
                    f"{seen_names[rec.name]} and {rec.index}"))
            else:
                seen_names[rec.name] = rec.index
            if is_traversal(rec.name):
                anomalies.append(_anomaly(
                    ci, "path_traversal",
                    f"member name {rec.name!r} escapes the extraction root"))
            if rec.encrypted:
                anomalies.append(_anomaly(
                    ci, "encrypted",
                    f"member {rec.name!r} is encrypted (flag bit 0)"))
            if rec.disk_start:
                anomalies.append(_anomaly(
                    ci, "multi_disk",
                    f"member {rec.name!r} starts on disk {rec.disk_start}"))
            if any(f.truncated for f in rec.extras):
                anomalies.append(_anomaly(
                    ci, "extra_truncated",
                    f"member {rec.name!r}: central directory extra field truncated"))
            if view["data_start"] is not None:
                ranges.append((view["data_start"], view["data_end"],
                               rec.name, rec.index))
                if view["data_end"] > size:
                    anomalies.append(_anomaly(
                        ci, "range_overflow",
                        f"member {rec.name!r}: compressed data ends at "
                        f"{view['data_end']}, beyond archive size {size} "
                        "(truncated or wrapped offset)"))
            if rec.local_header_offset >= size:
                anomalies.append(_anomaly(
                    ci, "range_overflow",
                    f"member {rec.name!r}: local header offset "
                    f"{rec.local_header_offset} beyond archive size {size}"))
            elif cand.cd_offset <= rec.local_header_offset < cand.cd_end:
                anomalies.append(_anomaly(
                    ci, "pointer_into_central_directory",
                    f"member {rec.name!r}: local header offset points into "
                    "the central directory"))

        ranges.sort()
        for i, (s1, e1, n1, _i1) in enumerate(ranges):
            for s2, e2, n2, _i2 in ranges[i + 1:]:
                if s2 >= e1:
                    break
                anomalies.append(_anomaly(
                    ci, "overlap",
                    f"members {n1!r} and {n2!r} share compressed bytes "
                    f"[{max(s1, s2)}, {min(e1, e2)})"))
        starts = [r[0] for r in ranges]
        for rec in cand.records:
            lho = rec.local_header_offset
            pos = bisect.bisect_right(starts, lho) - 1
            if pos >= 0:
                s, e, nm, idx = ranges[pos]
                if idx != rec.index and s <= lho < e:
                    anomalies.append(_anomaly(
                        ci, "pointer_into_member_data",
                        f"local header of {rec.name!r} points inside "
                        f"compressed data of {nm!r}"))
        for s, e, nm, _idx in ranges:
            if s <= cand.cd_offset < e:
                anomalies.append(_anomaly(
                    ci, "central_directory_inside_member_data",
                    f"central directory starts inside compressed data of {nm!r}"))

    return {
        "sha256": parse.sha256,
        "size": parse.size,
        "name": name,
        "budget_events": events,
        "candidates": candidates_out,
        "anomalies": anomalies,
    }


def build_report(data: bytes, name: str | None = None,
                 budgets: Budgets | None = None) -> dict:
    budgets = budgets or Budgets()
    parse = parse_archive(data, budgets)
    return analyze(data, parse, budgets, name)
