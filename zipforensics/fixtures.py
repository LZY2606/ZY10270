"""Built-in sample archives.

Each builder hand-crafts a ZIP that exercises one forensic edge case.
Run ``python -m zipforensics.fixtures --out fixtures/`` to dump them.
"""

from __future__ import annotations

import struct
import zlib

from .parser import (FLAG_DESCRIPTOR, FLAG_UTF8, SENT16, SENT32, SIG_CEN,
                     SIG_EOCD, SIG_LFH, SIG_Z64_EOCD, SIG_Z64_LOC)


def _lfh(name: bytes, flags: int, method: int, crc: int, csize: int,
         usize: int, extra: bytes = b"", version: int = 20) -> bytes:
    return (struct.pack("<4s5H3L2H", SIG_LFH, version, flags, method, 0, 0,
                        crc, csize, usize, len(name), len(extra))
            + name + extra)


def _cen(name: bytes, flags: int, method: int, crc: int, csize: int,
         usize: int, lho: int, extra: bytes = b"", comment: bytes = b"",
         version: int = 20, disk_start: int = 0) -> bytes:
    return (struct.pack("<4s6H3L5H2L", SIG_CEN, version, version, flags,
                        method, 0, 0, crc, csize, usize, len(name),
                        len(extra), len(comment), disk_start, 0, 0, lho)
            + name + extra + comment)


def _eocd(entries: int, cd_size: int, cd_offset: int, comment: bytes = b"",
          disk_no: int = 0, cd_disk: int = 0,
          entries_disk: int | None = None) -> bytes:
    if entries_disk is None:
        entries_disk = entries
    return (struct.pack("<4s4H2LH", SIG_EOCD, disk_no, cd_disk, entries_disk,
                        entries, cd_size, cd_offset, len(comment))
            + comment)


def build_zip64_sentinel() -> bytes:
    """Classic EOCD carries only 0xFFFF/0xFFFFFFFF sentinels; the real
    directory geometry lives in the ZIP64 EOCD + locator."""
    name = b"hello.txt"
    payload = b"hello zip64\n"
    crc = zlib.crc32(payload)
    z64_lfh_extra = struct.pack("<HHQQ", 0x0001, 16, len(payload), len(payload))
    lfh = _lfh(name, 0, 0, crc, SENT32, SENT32, extra=z64_lfh_extra, version=45)
    z64_cen_extra = struct.pack("<HHQQQ", 0x0001, 24, len(payload),
                                len(payload), 0)
    cen = _cen(name, 0, 0, crc, SENT32, SENT32, SENT32, extra=z64_cen_extra,
               version=45)
    cd_offset = len(lfh) + len(payload)
    cd_size = len(cen)
    z64_eocd_offset = cd_offset + cd_size
    z64_eocd = struct.pack("<4sQ2H2L4Q", SIG_Z64_EOCD, 44, 45, 45, 0, 0, 1, 1,
                           cd_size, cd_offset)
    locator = struct.pack("<4sLQL", SIG_Z64_LOC, 0, z64_eocd_offset, 1)
    eocd = _eocd(SENT16, SENT32, SENT32, entries_disk=SENT16)
    return lfh + payload + cen + z64_eocd + locator + eocd


def build_nosig_descriptor() -> bytes:
    """Bit 3 set, local sizes zero, data descriptor WITHOUT the PK\\x07\\x08
    signature.  Signature absence must be inferred from consistency."""
    name = "流式.txt".encode("utf-8")
    payload = b"streaming data, no signature descriptor\n" * 3
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    cdata = comp.compress(payload) + comp.flush()
    crc = zlib.crc32(payload)
    flags = FLAG_DESCRIPTOR | FLAG_UTF8
    lfh = _lfh(name, flags, 8, 0, 0, 0)
    descriptor = struct.pack("<LLL", crc, len(cdata), len(payload))
    cen = _cen(name, flags, 8, crc, len(cdata), len(payload), 0)
    cd_offset = len(lfh) + len(cdata) + len(descriptor)
    return lfh + cdata + descriptor + cen + _eocd(1, len(cen), cd_offset)


def build_fake_eocd_comment() -> bytes:
    """The real EOCD comment embeds a forged EOCD record.  Both candidates
    must be kept; the forged one is excluded with a reason."""
    name = b"note.txt"
    payload = b"real contents\n"
    crc = zlib.crc32(payload)
    lfh = _lfh(name, 0, 0, crc, len(payload), len(payload))
    cen = _cen(name, 0, 0, crc, len(payload), len(payload), 0)
    cd_offset = len(lfh) + len(payload)
    forged = _eocd(7, 0x1000, 0x2000)  # points far outside the file
    comment = b"see also " + forged
    eocd = _eocd(1, len(cen), cd_offset, comment=comment)
    return lfh + payload + cen + eocd


def build_shared_range() -> bytes:
    """Two members share a compressed extent: b.txt's local header is
    embedded inside a.txt's data, so their byte ranges overlap."""
    b_name = b"b.txt"
    b_payload = b"shared!\n"
    b_crc = zlib.crc32(b_payload)
    b_lfh = _lfh(b_name, 0, 0, b_crc, len(b_payload), len(b_payload))
    a_name = b"a.txt"
    a_payload = b"AA" + b_lfh + b_payload + b"ZZ"
    a_crc = zlib.crc32(a_payload)
    a_lfh = _lfh(a_name, 0, 0, a_crc, len(a_payload), len(a_payload))
    b_lho = len(a_lfh) + 2
    cen_a = _cen(a_name, 0, 0, a_crc, len(a_payload), len(a_payload), 0)
    cen_b = _cen(b_name, 0, 0, b_crc, len(b_payload), len(b_payload), b_lho)
    cd = cen_a + cen_b
    cd_offset = len(a_lfh) + len(a_payload)
    return a_lfh + a_payload + cd + _eocd(2, len(cd), cd_offset)


def build_truncated_extra() -> bytes:
    """Extra field whose internal field header declares 100 bytes while only
    2 are present."""
    name = b"extra.bin"
    payload = b"x" * 16
    crc = zlib.crc32(payload)
    bad_extra = struct.pack("<HH", 0xCAFE, 100) + b"ab"
    lfh = _lfh(name, 0, 0, crc, len(payload), len(payload), extra=bad_extra)
    cen = _cen(name, 0, 0, crc, len(payload), len(payload), 0, extra=bad_extra)
    cd_offset = len(lfh) + len(payload)
    return lfh + payload + cen + _eocd(1, len(cen), cd_offset)


FIXTURES = {
    "zip64-sentinel": build_zip64_sentinel,
    "nosig-descriptor": build_nosig_descriptor,
    "fake-eocd-comment": build_fake_eocd_comment,
    "shared-range": build_shared_range,
    "truncated-extra": build_truncated_extra,
}


def fixture_names() -> list[str]:
    return sorted(FIXTURES)


def build(name: str) -> bytes:
    return FIXTURES[name]()


if __name__ == "__main__":
    import argparse
    import pathlib

    parser = argparse.ArgumentParser(description="dump built-in fixtures")
    parser.add_argument("--out", default="fixtures")
    args = parser.parse_args()
    outdir = pathlib.Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    for fixture_name in fixture_names():
        path = outdir / f"{fixture_name}.zip"
        path.write_bytes(build(fixture_name))
        print(f"wrote {path} ({path.stat().st_size} bytes)")
