"""Structural validators for the built-in formats."""

from __future__ import annotations

import sqlite3
import struct
import zlib
from collections.abc import Callable
from pathlib import Path

from lupaxa.magic_bytes.errors import LimitError
from lupaxa.magic_bytes.io import Blob, temporary_copy
from lupaxa.magic_bytes.models import Budget, Check, Region, Validation, finish_status

Validator = Callable[[Blob, int, str, Budget], Validation]


def _check(
    name: str,
    passed: bool,
    detail: str,
    start: int = 0,
    end: int = 0,
    *,
    severity: str = "error",
) -> Check:
    return Check(name, passed, detail, start, end, severity)


def _region(
    start: int,
    end: int,
    region_type: str,
    name: str,
    description: str,
    parent: str | None,
    status: str,
) -> Region:
    return Region(start, end, region_type, name, description, parent, status, [])


def _done(result: Validation, budget: Budget, *, strict: bool) -> Validation:
    if strict and result.warnings and result.status == "passed":
        result.checks.append(_check("strict", False, "Strict mode treats warnings as failures."))
        result.status = "failed"
    if budget.incomplete and result.status == "passed":
        result.status = "partial"
    attributes: list[str] = []
    if result.status == "passed":
        attributes.append("validated")
    elif result.status == "partial":
        attributes.append("plausible")
    else:
        attributes.append("invalid")
    if any("truncat" in item.detail.lower() for item in result.checks):
        attributes.append("truncated")
    if result.carving and result.boundary == "exact" and "validated" in attributes:
        attributes.append("recoverable")
    result.attributes = attributes
    return result


def _u16(data: bytes, offset: int = 0, endian: str = "<") -> int:
    value = struct.unpack_from(endian + "H", data, offset)[0]
    return value if isinstance(value, int) else 0


def _u32(data: bytes, offset: int = 0, endian: str = "<") -> int:
    value = struct.unpack_from(endian + "I", data, offset)[0]
    return value if isinstance(value, int) else 0


def validate_png(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate a PNG signature, chunks, CRCs, and IEND."""
    checks: list[Check] = []
    regions: list[Region] = []
    signature = blob.read_at(origin, 8)
    ok = signature == b"\x89PNG\r\n\x1a\n"
    checks.append(_check("signature", ok, "PNG signature", origin, origin + 8))
    if not ok:
        return _failed("png", level, checks, regions)
    regions.append(_region(origin, origin + 8, "header", "signature", "PNG signature", "png", "passed"))
    offset = origin + 8
    saw_ihdr = False
    logical: int | None = None
    while offset + 12 <= blob.size:
        budget.tick(12)
        header = blob.read_at(offset, 8)
        if len(header) < 8:
            break
        length = _u32(header, 0, ">")
        marker = header[4:8]
        if length > blob.size or offset + 12 + length > blob.size:
            checks.append(_check("chunk-length", False, f"{marker!r} length runs past the file", offset, blob.size))
            checks.append(_check("truncated", False, "PNG is truncated", offset, blob.size))
            break
        payload = blob.read_at(offset + 8, length)
        crc_bytes = blob.read_at(offset + 8 + length, 4)
        stored = _u32(crc_bytes, 0, ">")
        actual = zlib.crc32(marker + payload) & 0xFFFFFFFF
        end = offset + 12 + length
        crc_ok = stored == actual
        if level == "deep" or level == "standard":
            checks.append(_check(f"crc-{marker.decode('latin1')}", crc_ok, f"CRC at 0x{offset:08x}", offset, end))
        if marker == b"IHDR":
            ihdr_ok = offset == origin + 8 and length == 13
            checks.append(_check("ihdr", ihdr_ok, "IHDR is the first chunk and is 13 bytes", offset, end))
            saw_ihdr = ihdr_ok
            if length == 13:
                width, height, depth, colour = struct.unpack(">IIBB", payload[:10])
                consistent = width > 0 and height > 0 and depth in {1, 2, 4, 8, 16} and colour in {0, 2, 3, 4, 6}
                checks.append(_check("ihdr-fields", consistent, f"{width}x{height} depth {depth}", offset, end))
        elif marker == b"IEND":
            checks.append(_check("iend", length == 0, "IEND chunk", offset, end))
            logical = end
            regions.append(_region(offset, end, "trailer", "IEND", "PNG end chunk", "png", "passed"))
            break
        regions.append(_region(offset, end, "chunk", marker.decode("latin1", "replace"), "PNG chunk", "png", "passed"))
        offset = end
    else:
        checks.append(_check("iend", False, "IEND chunk is missing", offset, blob.size))
    if not saw_ihdr:
        checks.append(_check("ihdr", False, "IHDR chunk is missing", origin, offset))
    if logical is None:
        checks.append(_check("truncated", False, "PNG ended before IEND", origin, blob.size))
    trailing = blob.size - logical if logical is not None else 0
    if trailing:
        checks.append(
            _check("trailing", True, f"{trailing} bytes follow IEND", logical or origin, blob.size, severity="warning")
        )
    status = finish_status(checks, incomplete=budget.incomplete)
    return _done(
        Validation(
            "png",
            level,
            status,
            checks,
            regions,
            logical,
            "exact" if logical else "estimated",
            logical is not None,
            [item.detail for item in checks if item.severity == "warning"],
        ),
        budget,
        strict=False,
    )


def validate_jpeg(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate JPEG markers, segment lengths, and the entropy-coded scan."""
    checks: list[Check] = []
    regions: list[Region] = []
    soi = blob.read_at(origin, 2) == b"\xff\xd8"
    checks.append(_check("soi", soi, "Start of image", origin, origin + 2))
    if not soi:
        return _failed("jpeg", level, checks, regions)
    regions.append(_region(origin, origin + 2, "header", "SOI", "JPEG start", "jpeg", "passed"))
    offset = origin + 2
    logical: int | None = None
    standalone = {0x01, *range(0xD0, 0xD8)}
    while offset + 1 < blob.size:
        budget.tick(2)
        if blob.read_at(offset, 1) != b"\xff":
            checks.append(_check("marker", False, "Expected a marker", offset, offset + 1))
            break
        while offset < blob.size and blob.read_at(offset, 1) == b"\xff":
            offset += 1
        if offset >= blob.size:
            checks.append(_check("truncated", False, "Marker byte is missing", offset, blob.size))
            break
        marker = blob.read_at(offset, 1)[0]
        marker_at = offset - 1
        offset += 1
        if marker == 0xD9:
            logical = offset
            regions.append(_region(marker_at, offset, "trailer", "EOI", "JPEG end", "jpeg", "passed"))
            checks.append(_check("eoi", True, "End of image", marker_at, offset))
            break
        if marker == 0xD8:
            checks.append(_check("marker", False, "Unexpected extra SOI", marker_at, offset))
            break
        if marker in standalone or marker == 0x00:
            continue
        if offset + 2 > blob.size:
            checks.append(_check("truncated", False, "Segment length is missing", marker_at, blob.size))
            break
        length = _u16(blob.read_at(offset, 2), 0, ">")
        if length < 2 or marker_at + 2 + length > blob.size:
            checks.append(
                _check("segment-length", False, f"Marker {marker:#04x} length is invalid", marker_at, blob.size)
            )
            checks.append(_check("truncated", False, "JPEG segment is truncated", marker_at, blob.size))
            break
        end = marker_at + 2 + length
        regions.append(_region(marker_at, end, "segment", f"FF{marker:02X}", "JPEG segment", "jpeg", "passed"))
        offset = end
        if marker == 0xDA:
            scanned = _jpeg_scan(blob, offset, checks, budget)
            if scanned is None:
                break
            offset = scanned
    if logical is None:
        checks.append(_check("eoi", False, "EOI marker is missing", origin, blob.size))
    elif logical < blob.size:
        checks.append(
            _check("trailing", True, f"{blob.size - logical} bytes follow EOI", logical, blob.size, severity="warning")
        )
    status = finish_status(checks, incomplete=budget.incomplete)
    return _done(
        Validation(
            "jpeg",
            level,
            status,
            checks,
            regions,
            logical,
            "exact" if logical else "estimated",
            logical is not None,
            [item.detail for item in checks if item.severity == "warning"],
        ),
        budget,
        strict=False,
    )


def _jpeg_scan(blob: Blob, offset: int, checks: list[Check], budget: Budget) -> int | None:
    while offset < blob.size:
        budget.tick(1)
        if blob.read_at(offset, 1) != b"\xff":
            offset += 1
            continue
        nxt = blob.read_at(offset + 1, 1)
        if not nxt:
            checks.append(_check("truncated", False, "Scan ended inside a marker", offset, blob.size))
            return None
        code = nxt[0]
        if code == 0x00 or 0xD0 <= code <= 0xD7:
            offset += 2
            continue
        return offset
    checks.append(_check("truncated", False, "Scan reached the end of the file", offset, blob.size))
    return None


def validate_gif(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate GIF87a and GIF89a blocks through the trailer."""
    checks: list[Check] = []
    regions: list[Region] = []
    header = blob.read_at(origin, 6)
    variant = "GIF87a" if header == b"GIF87a" else "GIF89a" if header == b"GIF89a" else ""
    checks.append(_check("signature", bool(variant), "GIF signature", origin, origin + 6))
    if not variant:
        return _failed("gif", level, checks, regions)
    screen = blob.read_at(origin + 6, 7)
    if len(screen) < 7:
        checks.append(_check("truncated", False, "Logical screen descriptor is truncated", origin, blob.size))
        return _failed("gif", level, checks, regions)
    packed = screen[4]
    offset = origin + 13
    if packed & 0x80:
        offset += 3 * (2 ** ((packed & 0x07) + 1))
    checks.append(
        _check("screen", offset <= blob.size, "Logical screen descriptor", origin + 6, min(offset, blob.size))
    )
    logical: int | None = None
    while offset < blob.size:
        budget.tick(1)
        sentinel = blob.read_at(offset, 1)
        if not sentinel:
            break
        kind = sentinel[0]
        if kind == 0x3B:
            logical = offset + 1
            regions.append(_region(offset, logical, "trailer", "trailer", "GIF trailer", "gif", "passed"))
            checks.append(_check("trailer", True, "GIF trailer", offset, logical))
            break
        if kind == 0x2C:
            moved = _gif_image(blob, offset, checks)
        elif kind == 0x21:
            moved = _gif_subblocks(blob, offset + 2, checks)
        else:
            checks.append(_check("block", False, f"Unknown GIF block {kind:#04x}", offset, offset + 1))
            break
        if moved is None or moved > blob.size:
            checks.append(_check("truncated", False, "GIF block is truncated", origin, blob.size))
            break
        offset = moved
    if logical is None:
        checks.append(_check("trailer", False, "GIF trailer is missing", origin, blob.size))
    elif logical < blob.size:
        checks.append(
            _check(
                "trailing",
                True,
                f"{blob.size - logical} bytes follow the trailer",
                logical,
                blob.size,
                severity="warning",
            )
        )
    status = finish_status(checks, incomplete=budget.incomplete)
    result = Validation(
        "gif",
        level,
        status,
        checks,
        regions,
        logical,
        "exact" if logical else "estimated",
        logical is not None,
        [item.detail for item in checks if item.severity == "warning"],
        variant=variant,
    )
    return _done(result, budget, strict=False)


def _gif_image(blob: Blob, offset: int, checks: list[Check]) -> int | None:
    descriptor = blob.read_at(offset, 10)
    if len(descriptor) < 10:
        checks.append(_check("image", False, "Image descriptor is truncated", offset, blob.size))
        return None
    cursor = offset + 10
    if descriptor[9] & 0x80:
        cursor += 3 * (2 ** ((descriptor[9] & 0x07) + 1))
    if cursor >= blob.size:
        return None
    cursor += 1
    return _gif_subblocks(blob, cursor, checks)


def _gif_subblocks(blob: Blob, offset: int, checks: list[Check]) -> int | None:
    cursor = offset
    while cursor < blob.size:
        size = blob.read_at(cursor, 1)
        if not size:
            return None
        if size[0] == 0:
            return cursor + 1
        cursor += 1 + size[0]
        if cursor > blob.size:
            checks.append(_check("sub-block", False, "GIF sub-block runs past the file", offset, blob.size))
            return None
    return None


def validate_bmp(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate a BMP file header and DIB header."""
    budget.tick(26)
    checks: list[Check] = []
    regions: list[Region] = []
    header = blob.read_at(origin, 18)
    ok = len(header) >= 18 and header[:2] == b"BM"
    checks.append(_check("signature", ok, "BM signature", origin, origin + 2))
    if not ok:
        return _failed("bmp", level, checks, regions)
    declared, _reserved, pixel_offset = struct.unpack_from("<III", header, 2)
    dib_size = _u32(header, 14)
    known = {12, 16, 40, 52, 56, 64, 108, 124}
    checks.append(
        _check("dib", dib_size in known, f"DIB header size {dib_size}", origin + 14, origin + 14 + min(dib_size, 124))
    )
    if dib_size not in known or origin + 14 + dib_size > blob.size:
        checks.append(_check("truncated", False, "DIB header is truncated or unknown", origin, blob.size))
        return _failed("bmp", level, checks, regions)
    info = blob.read_at(origin + 14, dib_size)
    if dib_size == 12 and len(info) >= 12:
        _width, _height, planes, depth = struct.unpack_from("<HHHH", info, 4)
    elif dib_size >= 16 and len(info) >= 16:
        _width, _height = struct.unpack_from("<ii", info, 4)
        planes, depth = struct.unpack_from("<HH", info, 12)
    else:
        planes, depth = 0, 0
    checks.append(_check("planes", planes == 1, f"Planes {planes}", origin + 14, origin + 14 + dib_size))
    checks.append(_check("depth", depth in {1, 2, 4, 8, 16, 24, 32}, f"Bit depth {depth}", origin, origin + 4))
    logical = declared if origin + declared <= blob.size and declared >= pixel_offset else None
    if pixel_offset > blob.size or pixel_offset < 14 + dib_size:
        checks.append(_check("pixels", False, "Pixel offset is outside the file", origin, blob.size))
    else:
        checks.append(_check("pixels", True, f"Pixel data at {pixel_offset}", origin + pixel_offset, blob.size))
        regions.append(
            _region(origin + pixel_offset, logical or blob.size, "pixels", "pixels", "BMP pixel data", "bmp", "passed")
        )
    if declared != blob.size - origin:
        severity = "error" if declared > blob.size - origin else "warning"
        detail = (
            "Declared BMP size is larger than the file" if severity == "error" else "Bytes follow the declared BMP size"
        )
        checks.append(_check("declared-size", severity == "warning", detail, origin, blob.size, severity=severity))
        if severity == "error":
            checks.append(_check("truncated", False, "BMP is truncated", origin, blob.size))
    regions.append(_region(origin, origin + 14, "header", "file-header", "BMP file header", "bmp", "passed"))
    status = finish_status(checks, incomplete=budget.incomplete)
    end = origin + declared if declared and origin + declared <= blob.size else None
    return _done(
        Validation(
            "bmp",
            level,
            status,
            checks,
            regions,
            end,
            "exact" if end else "estimated",
            end is not None,
            [c.detail for c in checks if c.severity == "warning"],
        ),
        budget,
        strict=False,
    )


def validate_zip(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate ZIP local headers, the central directory, and ZIP64 where present."""
    checks: list[Check] = []
    regions: list[Region] = []
    eocd = _find_eocd(blob, budget)
    if eocd is None:
        walked = _walk_locals(blob, origin, checks, regions, budget)
        checks.append(_check("eocd", False, "End of central directory was not found", origin, blob.size))
        if walked is None:
            checks.append(_check("truncated", False, "ZIP local headers are truncated", origin, blob.size))
        return _failed("zip", level, checks, regions)
    checks.append(_check("eocd", True, "End of central directory", eocd, min(blob.size, eocd + 22)))
    tail = blob.read_at(eocd, 22)
    total = _u16(tail, 10)
    cd_size = _u32(tail, 12)
    cd_offset = _u32(tail, 16)
    comment = _u16(tail, 20)
    logical = eocd + 22 + comment
    if cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF or total == 0xFFFF:
        locator = blob.read_at(max(0, eocd - 20), 20)
        if locator[:4] == b"PK\x06\x07":
            checks.append(_check("zip64", True, "ZIP64 locator is present", eocd - 20, eocd, severity="warning"))
            result_note = "ZIP64 locator found; full ZIP64 parsing is reported and not treated as corruption"
            checks.append(_check("zip64-detail", True, result_note, eocd - 20, eocd, severity="warning"))
        else:
            checks.append(_check("zip64", False, "ZIP64 values are present without a locator", eocd, logical))
    if cd_offset != 0xFFFFFFFF and (cd_offset > blob.size or cd_offset + cd_size > blob.size):
        checks.append(_check("central-directory", False, "Central directory is outside the file", cd_offset, blob.size))
        checks.append(_check("truncated", False, "ZIP central directory is truncated", origin, blob.size))
    else:
        checks.append(
            _check("central-directory", True, f"{total} central-directory entries", cd_offset, cd_offset + cd_size)
        )
        regions.append(
            _region(
                cd_offset,
                cd_offset + cd_size,
                "directory",
                "central-directory",
                "ZIP central directory",
                "zip",
                "passed",
            )
        )
        if level == "deep" and cd_offset != 0xFFFFFFFF:
            _zip_entries(blob, cd_offset, cd_size, total, checks, budget)
    if origin < cd_offset < blob.size and blob.read_at(origin, 4) != b"PK\x03\x04":
        checks.append(
            _check("prefix", True, f"{cd_offset - origin} byte ZIP prefix", origin, cd_offset, severity="warning")
        )
    if logical < blob.size:
        checks.append(
            _check(
                "trailing",
                True,
                f"{blob.size - logical} bytes follow the ZIP comment",
                logical,
                blob.size,
                severity="warning",
            )
        )
    regions.append(
        _region(eocd, min(blob.size, logical), "trailer", "EOCD", "End of central directory", "zip", "passed")
    )
    status = finish_status(checks, incomplete=budget.incomplete)
    exact = status != "failed" and cd_offset != 0xFFFFFFFF
    return _done(
        Validation(
            "zip",
            level,
            status,
            checks,
            regions,
            logical if logical <= blob.size else None,
            "exact" if exact else "estimated",
            exact,
            [c.detail for c in checks if c.severity == "warning"],
        ),
        budget,
        strict=False,
    )


def _find_eocd(blob: Blob, budget: Budget) -> int | None:
    window_start = max(0, blob.size - (65535 + 22))
    window = blob.read_at(window_start, blob.size - window_start)
    budget.tick(len(window))
    marker = window.rfind(b"PK\x05\x06")
    if marker < 0:
        return None
    return window_start + marker


def _walk_locals(blob: Blob, origin: int, checks: list[Check], regions: list[Region], budget: Budget) -> int | None:
    offset = origin
    if blob.read_at(offset, 4) != b"PK\x03\x04":
        return None
    while offset + 30 <= blob.size and blob.read_at(offset, 4) == b"PK\x03\x04":
        budget.tick(30)
        header = blob.read_at(offset, 30)
        compressed = _u32(header, 18)
        name_len = _u16(header, 26)
        extra_len = _u16(header, 28)
        data_start = offset + 30 + name_len + extra_len
        if data_start + compressed > blob.size:
            return None
        regions.append(_region(offset, data_start + compressed, "entry", "local", "ZIP local file", "zip", "passed"))
        offset = data_start + compressed
    checks.append(_check("local-headers", True, "Local headers walked", origin, offset, severity="warning"))
    return offset


def _zip_entries(blob: Blob, offset: int, size: int, count: int, checks: list[Check], budget: Budget) -> None:
    cursor = offset
    end = offset + size
    seen = 0
    ranges: list[tuple[int, int]] = []
    while cursor + 46 <= end and seen < count + 1:
        budget.tick(46)
        header = blob.read_at(cursor, 46)
        if header[:4] != b"PK\x01\x02":
            checks.append(_check("central-entry", False, "Central directory entry signature mismatch", cursor, end))
            return
        method = _u16(header, 10)
        crc = _u32(header, 16)
        compressed = _u32(header, 20)
        name_len = _u16(header, 28)
        extra_len = _u16(header, 30)
        comment_len = _u16(header, 32)
        local_off = _u32(header, 42)
        local = blob.read_at(local_off, 30)
        if local[:4] != b"PK\x03\x04":
            checks.append(
                _check("local-link", False, f"Entry {seen} local header is missing", local_off, local_off + 4)
            )
        else:
            data_at = local_off + 30 + _u16(local, 26) + _u16(local, 28)
            ranges.append((data_at, data_at + compressed))
            if method == 0 and compressed < 8 * 1024 * 1024:
                payload = blob.read_at(data_at, compressed)
                if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
                    checks.append(_check("crc", False, f"Entry {seen} CRC mismatch", data_at, data_at + compressed))
            elif method == 8:
                _inflate_check(blob, data_at, compressed, crc, seen, checks, budget)
        cursor += 46 + name_len + extra_len + comment_len
        seen += 1
    ranges.sort()
    for earlier, later in zip(ranges, ranges[1:], strict=False):
        if later[0] < earlier[1]:
            checks.append(_check("overlap", False, "ZIP entry ranges overlap", earlier[0], later[1]))
            return
    checks.append(_check("entries", seen == count, f"Read {seen} of {count} entries", offset, end))


def _inflate_check(
    blob: Blob, offset: int, compressed: int, crc: int, index: int, checks: list[Check], budget: Budget
) -> None:
    if compressed > 8 * 1024 * 1024:
        checks.append(
            _check(
                "inflate",
                True,
                f"Entry {index} skipped: compressed size is large",
                offset,
                offset + compressed,
                severity="warning",
            )
        )
        return
    source = blob.read_at(offset, compressed)
    try:
        stream = zlib.decompressobj(-15)
        out = stream.decompress(source, budget.max_decompressed)
        budget.take_decompressed(len(out))
        if stream.unconsumed_tail:
            raise LimitError("Decompression limit exceeded.")
        out += stream.flush()
    except (zlib.error, LimitError):
        checks.append(
            _check("inflate", False, f"Entry {index} could not be inflated within limits", offset, offset + compressed)
        )
        return
    if (zlib.crc32(out) & 0xFFFFFFFF) != crc:
        checks.append(_check("crc", False, f"Entry {index} CRC mismatch", offset, offset + compressed))


def validate_pdf(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate a PDF header, EOF marker, and startxref. This is not a full semantic parse."""
    budget.tick(1024)
    checks: list[Check] = []
    regions: list[Region] = []
    window = blob.read_at(origin, min(1024, blob.size - origin))
    header_at = window.find(b"%PDF-")
    checks.append(_check("header", header_at >= 0, "PDF header", origin, origin + max(header_at, 0) + 8))
    if header_at < 0:
        return _failed("pdf", level, checks, regions)
    absolute = origin + header_at
    if header_at:
        checks.append(_check("prefix", True, f"{header_at} byte PDF prefix", origin, absolute, severity="warning"))
    version = blob.read_at(absolute + 5, 3)
    checks.append(
        _check(
            "version",
            len(version) >= 3 and version[0:1].isdigit(),
            f"Version {version.decode('latin1', 'replace')}",
            absolute,
            absolute + 8,
        )
    )
    tail_start = max(absolute, blob.size - 2048)
    tail = blob.read_at(tail_start, blob.size - tail_start)
    eof_at = tail.rfind(b"%%EOF")
    checks.append(_check("eof", eof_at >= 0, "EOF marker", tail_start, blob.size))
    logical = tail_start + eof_at + 5 if eof_at >= 0 else None
    startxref = tail.rfind(b"startxref")
    if startxref >= 0:
        digits = tail[startxref + len(b"startxref") :].lstrip(b"\r\n\t ")
        number = bytearray()
        for byte in digits:
            if 48 <= byte <= 57:
                number.append(byte)
            else:
                break
        if number:
            xref_at = int(number)
            body = blob.read_at(xref_at, 4)
            supported = body.startswith(b"xref")
            detail = (
                "Classic xref table"
                if supported
                else "startxref does not point at a classic xref table; streams are unsupported, not corrupt"
            )
            checks.append(
                _check(
                    "startxref", True, detail, xref_at, xref_at + 4, severity="warning" if not supported else "error"
                )
            )
            if not supported:
                checks[-1].passed = True
        else:
            checks.append(_check("startxref", False, "startxref has no offset", tail_start + startxref, blob.size))
    else:
        checks.append(_check("startxref", False, "startxref is missing", tail_start, blob.size))
    if tail.count(b"%%EOF") > 1:
        checks.append(
            _check(
                "incremental",
                True,
                "More than one EOF marker; incremental updates are allowed",
                tail_start,
                blob.size,
                severity="warning",
            )
        )
    if logical is not None and logical < blob.size:
        checks.append(
            _check(
                "trailing", True, f"{blob.size - logical} bytes follow %%EOF", logical, blob.size, severity="warning"
            )
        )
    checks.append(
        _check(
            "semantic-parse",
            True,
            "A complete semantic PDF parse was not performed",
            absolute,
            logical or blob.size,
            severity="warning",
        )
    )
    regions.append(_region(absolute, absolute + 8, "header", "header", "PDF header", "pdf", "passed"))
    status = finish_status(checks, incomplete=budget.incomplete)
    return _done(
        Validation(
            "pdf",
            level,
            status,
            checks,
            regions,
            logical,
            "estimated" if logical else "unknown",
            False,
            [c.detail for c in checks if c.severity == "warning"],
        ),
        budget,
        strict=False,
    )


def validate_wav(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate RIFF, RIFX, or RF64 WAVE chunks."""
    checks: list[Check] = []
    regions: list[Region] = []
    header = blob.read_at(origin, 12)
    kind = header[:4]
    ok = kind in {b"RIFF", b"RIFX", b"RF64"} and header[8:12] == b"WAVE"
    checks.append(_check("signature", ok, "WAVE container", origin, origin + 12))
    if not ok:
        return _failed("wav", level, checks, regions)
    endian = ">" if kind == b"RIFX" else "<"
    declared = struct.unpack_from(endian + "I", header, 4)[0]
    offset = origin + 12
    saw_fmt = False
    saw_data = False
    data_end = offset
    while offset + 8 <= blob.size and offset < origin + 8 + declared:
        budget.tick(8)
        chunk = blob.read_at(offset, 8)
        size = struct.unpack_from(endian + "I", chunk, 4)[0]
        end = offset + 8 + size + (size & 1)
        if end > blob.size:
            checks.append(_check("truncated", False, f"Chunk {chunk[:4]!r} is truncated", offset, blob.size))
            break
        name = chunk[:4].decode("latin1", "replace")
        regions.append(_region(offset, end, "chunk", name, "WAVE chunk", "wav", "passed"))
        if chunk[:4] == b"fmt ":
            saw_fmt = True
            fmt = blob.read_at(offset + 8, min(size, 16))
            if len(fmt) >= 16:
                audio_format, channels, rate, _byte_rate, block, bits = struct.unpack_from(endian + "HHIIHH", fmt)
                consistent = channels > 0 and rate > 0 and bits > 0 and block == channels * ((bits + 7) // 8)
                checks.append(
                    _check(
                        "fmt",
                        consistent or audio_format != 1,
                        f"Format {audio_format} {channels}ch {rate}Hz",
                        offset,
                        end,
                    )
                )
        if chunk[:4] == b"data":
            saw_data = True
            data_end = offset + 8 + size
        offset = end
    checks.append(_check("fmt-present", saw_fmt, "fmt chunk", origin, offset))
    checks.append(_check("data-present", saw_data, "data chunk", origin, data_end))
    logical = origin + 8 + declared
    if logical > blob.size:
        checks.append(_check("truncated", False, "Declared RIFF size is larger than the file", origin, blob.size))
        logical_end = None
    else:
        logical_end = logical
        if logical_end < blob.size:
            checks.append(
                _check(
                    "trailing",
                    True,
                    f"{blob.size - logical_end} bytes follow the RIFF size",
                    logical_end,
                    blob.size,
                    severity="warning",
                )
            )
    status = finish_status(checks, incomplete=budget.incomplete)
    return _done(
        Validation(
            "wav",
            level,
            status,
            checks,
            regions,
            logical_end,
            "exact" if logical_end else "estimated",
            logical_end is not None,
            [c.detail for c in checks if c.severity == "warning"],
            variant=kind.decode(),
        ),
        budget,
        strict=False,
    )


def validate_mp3(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate an ID3 tag and a run of MPEG audio frames."""
    checks: list[Check] = []
    regions: list[Region] = []
    offset = origin
    if blob.read_at(origin, 3) == b"ID3":
        header = blob.read_at(origin, 10)
        if len(header) < 10:
            checks.append(_check("truncated", False, "ID3 header is truncated", origin, blob.size))
            return _failed("mp3", level, checks, regions)
        size = _synchsafe(header[6:10])
        offset = origin + 10 + size
        if offset > blob.size:
            checks.append(_check("truncated", False, "ID3 tag is truncated", origin, blob.size))
            return _failed("mp3", level, checks, regions)
        regions.append(_region(origin, offset, "metadata", "ID3v2", "ID3v2 tag", "mp3", "passed"))
        checks.append(_check("id3", True, "ID3v2 tag", origin, offset))
    frames = 0
    cursor = offset
    logical = cursor
    while cursor + 4 <= blob.size and frames < 64:
        budget.tick(4)
        header = blob.read_at(cursor, 4)
        length = _mp3_frame_length(header)
        if length is None or cursor + length > blob.size:
            break
        frames += 1
        logical = cursor + length
        cursor = logical
    checks.append(_check("frames", frames > 0, f"{frames} MPEG frames", offset, logical))
    if frames == 0:
        checks.append(_check("truncated", False, "No complete MPEG frame", origin, blob.size))
    elif logical < blob.size:
        trailer = blob.read_at(logical, 3)
        detail = (
            "ID3v1 or other trailing bytes"
            if trailer == b"TAG"
            else f"{blob.size - logical} bytes follow the last frame"
        )
        checks.append(_check("trailing", True, detail, logical, blob.size, severity="warning"))
    status = finish_status(checks, incomplete=budget.incomplete)
    return _done(
        Validation(
            "mp3",
            level,
            status,
            checks,
            regions,
            logical if frames else None,
            "estimated" if frames else "unknown",
            False,
            [c.detail for c in checks if c.severity == "warning"],
        ),
        budget,
        strict=False,
    )


def _synchsafe(data: bytes) -> int:
    return ((data[0] & 0x7F) << 21) | ((data[1] & 0x7F) << 14) | ((data[2] & 0x7F) << 7) | (data[3] & 0x7F)


def _mp3_frame_length(header: bytes) -> int | None:
    if len(header) < 4 or header[0] != 0xFF or (header[1] & 0xE0) != 0xE0:
        return None
    version = (header[1] >> 3) & 0x03
    layer = (header[1] >> 1) & 0x03
    bitrate_index = (header[2] >> 4) & 0x0F
    sample_index = (header[2] >> 2) & 0x03
    padding = (header[2] >> 1) & 0x01
    if version == 1 or layer == 0 or bitrate_index in {0, 15} or sample_index == 3:
        return None
    rates = {
        3: (44100, 48000, 32000),
        2: (22050, 24000, 16000),
        0: (11025, 12000, 8000),
    }
    bitrate_table = {
        3: (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
        2: (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384),
        1: (0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448),
    }
    layer_key = {3: 1, 2: 2, 1: 3}[layer]
    rate = rates[version][sample_index]
    bitrate = bitrate_table[layer_key][bitrate_index] * 1000
    if layer_key == 1:
        return ((12 * bitrate // rate) + padding) * 4
    scale = 144 if version == 3 else 72
    return (scale * bitrate // rate) + padding


def validate_elf(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate an ELF header and the program and section tables."""
    budget.tick(64)
    checks: list[Check] = []
    regions: list[Region] = []
    ident = blob.read_at(origin, 16)
    ok = ident[:4] == b"\x7fELF"
    checks.append(_check("signature", ok, "ELF signature", origin, origin + 4))
    if not ok or len(ident) < 16:
        return _failed("elf", level, checks, regions)
    elf_class = ident[4]
    data = ident[5]
    checks.append(_check("class", elf_class in {1, 2}, "ELF class", origin + 4, origin + 5))
    checks.append(_check("endian", data in {1, 2}, "ELF data encoding", origin + 5, origin + 6))
    if elf_class not in {1, 2} or data not in {1, 2}:
        return _failed("elf", level, checks, regions)
    endian = "<" if data == 1 else ">"
    header_size = 52 if elf_class == 1 else 64
    header = blob.read_at(origin, header_size)
    if len(header) < header_size:
        checks.append(_check("truncated", False, "ELF header is truncated", origin, blob.size))
        return _failed("elf", level, checks, regions)
    if elf_class == 1:
        phoff, shoff = struct.unpack_from(endian + "II", header, 28)
        ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(endian + "HHHHH", header, 40)
    else:
        phoff, shoff = struct.unpack_from(endian + "QQ", header, 32)
        ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(endian + "HHHHH", header, 52)
    checks.append(_check("header-size", ehsize == header_size, f"Header size {ehsize}", origin, origin + ehsize))
    _table_bounds(blob, origin, phoff, phentsize, phnum, "program", checks, regions)
    _table_bounds(blob, origin, shoff, shentsize, shnum, "section", checks, regions)
    status = finish_status(checks, incomplete=budget.incomplete)
    end = blob.size if status != "failed" else None
    return _done(
        Validation(
            "elf",
            level,
            status,
            checks,
            regions,
            end,
            "exact" if end else "unknown",
            False,
            [c.detail for c in checks if c.severity == "warning"],
        ),
        budget,
        strict=False,
    )


def _table_bounds(
    blob: Blob, origin: int, offset: int, entry: int, count: int, name: str, checks: list[Check], regions: list[Region]
) -> None:
    if count == 0 or offset == 0:
        checks.append(_check(f"{name}-table", True, f"No {name} headers", origin, origin, severity="warning"))
        return
    start = origin + offset
    size = entry * count
    inside = entry > 0 and start >= 0 and start + size <= blob.size
    checks.append(
        _check(f"{name}-table", inside, f"{count} {name} headers", start, start + size if inside else blob.size)
    )
    if inside:
        regions.append(_region(start, start + size, "table", name, f"ELF {name} header table", "elf", "passed"))


def validate_pe(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate a DOS header, PE signature, COFF header, and section table."""
    budget.tick(128)
    checks: list[Check] = []
    regions: list[Region] = []
    dos = blob.read_at(origin, 64)
    ok = len(dos) >= 64 and dos[:2] == b"MZ"
    checks.append(_check("dos", ok, "DOS header", origin, origin + 2))
    if not ok:
        return _failed("pe", level, checks, regions)
    e_lfanew = _u32(dos, 0x3C)
    pe_at = origin + e_lfanew
    signature = blob.read_at(pe_at, 4)
    checks.append(_check("pe", signature == b"PE\x00\x00", "PE signature", pe_at, pe_at + 4))
    if signature != b"PE\x00\x00" or pe_at + 24 > blob.size:
        checks.append(_check("truncated", False, "PE header is missing or truncated", origin, blob.size))
        return _failed("pe", level, checks, regions)
    coff = blob.read_at(pe_at + 4, 20)
    sections = _u16(coff, 2)
    optional_size = _u16(coff, 16)
    optional = blob.read_at(pe_at + 24, optional_size)
    if len(optional) < optional_size:
        checks.append(_check("truncated", False, "Optional header is truncated", pe_at, blob.size))
        return _failed("pe", level, checks, regions)
    magic = _u16(optional, 0)
    checks.append(
        _check(
            "optional", magic in {0x10B, 0x20B}, f"Optional magic {magic:#06x}", pe_at + 24, pe_at + 24 + optional_size
        )
    )
    section_at = pe_at + 24 + optional_size
    raw_end = section_at
    for index in range(sections):
        budget.tick(40)
        entry = blob.read_at(section_at + index * 40, 40)
        if len(entry) < 40:
            checks.append(_check("sections", False, "Section table is truncated", section_at, blob.size))
            checks.append(_check("truncated", False, "PE section table is truncated", origin, blob.size))
            return _failed("pe", level, checks, regions)
        raw_size = _u32(entry, 16)
        raw_ptr = _u32(entry, 20)
        if raw_size and (raw_ptr > blob.size or raw_ptr + raw_size > blob.size):
            checks.append(
                _check(
                    "section-bounds",
                    False,
                    f"Section {index} raw data is outside the file",
                    origin + raw_ptr,
                    blob.size,
                )
            )
        else:
            raw_end = max(raw_end, origin + raw_ptr + raw_size)
            regions.append(
                _region(
                    origin + raw_ptr,
                    origin + raw_ptr + raw_size,
                    "section",
                    entry[:8].split(b"\x00", 1)[0].decode("latin1", "replace") or f"section-{index}",
                    "PE section",
                    "pe",
                    "passed",
                )
            )
    checks.append(_check("sections", True, f"{sections} sections", section_at, section_at + sections * 40))
    if raw_end < blob.size:
        checks.append(
            _check(
                "overlay",
                True,
                f"{blob.size - raw_end} overlay bytes. Overlay data is a normal PE feature",
                raw_end,
                blob.size,
                severity="warning",
            )
        )
        regions.append(_region(raw_end, blob.size, "overlay", "overlay", "PE overlay", "pe", "passed"))
    status = finish_status(checks, incomplete=budget.incomplete)
    return _done(
        Validation(
            "pe",
            level,
            status,
            checks,
            regions,
            blob.size,
            "exact",
            False,
            [c.detail for c in checks if c.severity == "warning"],
        ),
        budget,
        strict=False,
    )


def validate_sqlite(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate a SQLite header. Deep mode may run a read-only integrity check."""
    budget.tick(100)
    checks: list[Check] = []
    regions: list[Region] = []
    header = blob.read_at(origin, 100)
    ok = header[:16] == b"SQLite format 3\x00"
    checks.append(_check("signature", ok, "SQLite signature", origin, origin + 16))
    if not ok or len(header) < 100:
        checks.append(_check("truncated", False, "SQLite header is truncated", origin, blob.size))
        return _failed("sqlite", level, checks, regions)
    page_size = _u16(header, 16, ">")
    if page_size == 1:
        page_size = 65536
    page_count = _u32(header, 28, ">")
    usable = page_size in {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536} or (
        page_size >= 512 and page_size <= 65536 and page_size & (page_size - 1) == 0
    )
    checks.append(_check("page-size", usable, f"Page size {page_size}", origin + 16, origin + 18))
    expected = page_size * page_count
    available = blob.size - origin
    if expected and available < expected:
        checks.append(_check("truncated", False, "Database is smaller than the declared page count", origin, blob.size))
    elif expected and available > expected:
        checks.append(
            _check(
                "trailing",
                True,
                f"{available - expected} bytes follow the declared database",
                origin + expected,
                blob.size,
                severity="warning",
            )
        )
    else:
        checks.append(_check("page-count", True, f"{page_count} pages", origin, origin + expected))
    aligned = page_size > 0 and available % page_size == 0
    checks.append(
        _check(
            "alignment",
            aligned or available > expected,
            "File length is a multiple of the page size",
            origin,
            blob.size,
            severity="warning" if not aligned else "error",
        )
    )
    if not aligned:
        checks[-1].passed = True
    if level == "deep":
        _sqlite_integrity(blob, checks, budget)
    logical = origin + expected if expected and origin + expected <= blob.size else None
    status = finish_status(checks, incomplete=budget.incomplete)
    return _done(
        Validation(
            "sqlite",
            level,
            status,
            checks,
            regions,
            logical,
            "exact" if logical else "estimated",
            logical is not None,
            [c.detail for c in checks if c.severity == "warning"],
        ),
        budget,
        strict=False,
    )


def _sqlite_integrity(blob: Blob, checks: list[Check], budget: Budget) -> None:
    path: Path | None = blob.path if blob._data is None else None
    temporary: Path | None = None
    if path is None:
        if blob._data is None or len(blob._data) > 32 * 1024 * 1024:
            checks.append(
                _check("integrity", True, "Deep integrity check skipped for this input", 0, 0, severity="warning")
            )
            return
        temporary = temporary_copy(blob._data)
        path = temporary
    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True)
        try:
            connection.execute("PRAGMA query_only = ON")
            row = connection.execute("PRAGMA integrity_check(1)").fetchone()
            ok = bool(row) and row[0] == "ok"
            checks.append(
                _check("integrity", ok, "SQLite integrity_check", 0, blob.size, severity="error" if not ok else "error")
            )
        finally:
            connection.close()
    except sqlite3.Error as exc:
        checks.append(_check("integrity", False, f"SQLite integrity_check failed: {exc}", 0, blob.size))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    budget.tick(blob.size)


def validate_gzip(blob: Blob, origin: int, level: str, budget: Budget) -> Validation:
    """Validate GZIP members, including concatenated members."""
    checks: list[Check] = []
    regions: list[Region] = []
    offset = origin
    members = 0
    logical: int | None = None
    while offset + 18 <= blob.size and blob.read_at(offset, 2) == b"\x1f\x8b":
        budget.tick(10)
        header = blob.read_at(offset, 10)
        if len(header) < 10 or header[2] != 8:
            checks.append(_check("method", False, "GZIP method is not deflate", offset, offset + 3))
            break
        flags = header[3]
        cursor = offset + 10
        if flags & 0x04:
            extra_len = _u16(blob.read_at(cursor, 2))
            cursor += 2 + extra_len
        if flags & 0x08:
            named = _cstring(blob, cursor)
            cursor = blob.size if named is None else named
        if flags & 0x10:
            commented = _cstring(blob, cursor)
            cursor = blob.size if commented is None else commented
        if flags & 0x02:
            cursor += 2
        if cursor >= blob.size:
            checks.append(_check("truncated", False, "GZIP header is truncated", offset, blob.size))
            break
        end, crc_ok, isize_ok = _gzip_member(blob, cursor, checks, budget, members)
        if end is None:
            checks.append(_check("truncated", False, "GZIP member is truncated", offset, blob.size))
            break
        regions.append(_region(offset, end, "member", f"member-{members}", "GZIP member", "gzip", "passed"))
        if level != "basic":
            checks.append(_check(f"crc-{members}", crc_ok, f"Member {members} CRC32", offset, end))
            checks.append(_check(f"isize-{members}", isize_ok, f"Member {members} size", offset, end))
        members += 1
        logical = end
        offset = end
        if members > 64:
            break
    checks.append(_check("members", members > 0, f"{members} GZIP members", origin, logical or blob.size))
    if logical is not None and logical < blob.size:
        checks.append(
            _check(
                "trailing",
                True,
                f"{blob.size - logical} bytes follow the last member",
                logical,
                blob.size,
                severity="warning",
            )
        )
    status = finish_status(checks, incomplete=budget.incomplete)
    return _done(
        Validation(
            "gzip",
            level,
            status,
            checks,
            regions,
            logical,
            "exact" if logical and status != "failed" else "estimated",
            logical is not None and status != "failed",
            [c.detail for c in checks if c.severity == "warning"],
        ),
        budget,
        strict=False,
    )


def _cstring(blob: Blob, offset: int) -> int | None:
    cursor = offset
    while cursor < blob.size:
        if blob.read_at(cursor, 1) == b"\x00":
            return cursor + 1
        cursor += 1
        if cursor - offset > 1024 * 1024:
            return None
    return None


def _gzip_member(
    blob: Blob, offset: int, checks: list[Check], budget: Budget, index: int
) -> tuple[int | None, bool, bool]:
    del index
    stream = zlib.decompressobj(-15)
    cursor = offset
    produced = bytearray()
    try:
        while cursor < blob.size and not stream.eof:
            budget.tick(4096)
            chunk = blob.read_at(cursor, min(4096, blob.size - cursor))
            if not chunk:
                break
            room = budget.max_decompressed - budget.decompressed
            if room <= 0:
                raise LimitError("Decompression limit exceeded.")
            piece = stream.decompress(chunk, room)
            if not piece and not stream.eof:
                raise LimitError("Decompression limit exceeded.")
            produced.extend(piece)
            budget.decompressed += len(piece)
            if stream.eof:
                unused = stream.unused_data
                consumed = len(chunk) - len(unused)
                cursor += consumed
                trailer = unused if len(unused) >= 8 else unused + blob.read_at(cursor + len(unused), 8 - len(unused))
                if len(trailer) < 8:
                    return None, False, False
                crc, isize = struct.unpack("<II", trailer[:8])
                actual = zlib.crc32(produced) & 0xFFFFFFFF
                return cursor + 8, actual == crc, (len(produced) & 0xFFFFFFFF) == isize
            cursor += len(chunk)
    except (zlib.error, LimitError):
        checks.append(
            _check("inflate", False, "GZIP inflate exceeded its limits or the stream is invalid", offset, blob.size)
        )
        return None, False, False
    return None, False, False


def _failed(format_id: str, level: str, checks: list[Check], regions: list[Region]) -> Validation:
    return Validation(format_id, level, "failed", checks, regions, None, "unknown", False, [], ["invalid"])


VALIDATORS: dict[str, Validator] = {
    "png": validate_png,
    "jpeg": validate_jpeg,
    "gif": validate_gif,
    "bmp": validate_bmp,
    "zip": validate_zip,
    "pdf": validate_pdf,
    "wav": validate_wav,
    "mp3": validate_mp3,
    "elf": validate_elf,
    "pe": validate_pe,
    "sqlite": validate_sqlite,
    "gzip": validate_gzip,
}


def validate_format(
    format_id: str, blob: Blob, origin: int, level: str, budget: Budget, *, strict: bool
) -> Validation | None:
    """Run one registered validator."""
    validator = VALIDATORS.get(format_id)
    if validator is None:
        return None
    result = validator(blob, origin, level, budget)
    if strict and result.warnings and result.status == "passed":
        result = _done(result, budget, strict=True)
    return result
