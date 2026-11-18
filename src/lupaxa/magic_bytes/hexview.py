"""Hexadecimal inspection and bounded byte search."""

from __future__ import annotations

from lupaxa.magic_bytes.errors import ArgumentError, NotFoundError
from lupaxa.magic_bytes.io import Blob


def parse_pattern(text: str) -> tuple[bytes, bytes]:
    """Parse a hex pattern with ?? wildcards, or a UTF-8 string."""
    compact = text.strip()
    pieces = compact.split()
    hex_like = all(
        len(part) == 2 and (part == "??" or all(char in "0123456789abcdefABCDEF" for char in part)) for part in pieces
    )
    if " " in compact and hex_like:
        return _from_parts(pieces)
    continuous = compact.replace(" ", "")
    if continuous and len(continuous) % 2 == 0 and all(char in "0123456789abcdefABCDEF?" for char in continuous):
        parts = [continuous[index : index + 2] for index in range(0, len(continuous), 2)]
        if all(part == "??" or "?" not in part for part in parts):
            return _from_parts(parts)
    encoded = compact.encode("utf-8")
    return encoded, b"\xff" * len(encoded)


def _from_parts(parts: list[str]) -> tuple[bytes, bytes]:
    pattern = bytearray()
    mask = bytearray()
    for part in parts:
        if part == "??":
            pattern.append(0)
            mask.append(0)
        else:
            pattern.append(int(part, 16))
            mask.append(0xFF)
    if not pattern:
        raise ArgumentError("The search pattern is empty.")
    return bytes(pattern), bytes(mask)


def search(blob: Blob, pattern: bytes, mask: bytes, *, start: int = 0, limit: int = 64) -> list[int]:
    """Find a masked pattern. The scan is capped."""
    if not pattern:
        raise ArgumentError("The search pattern is empty.")
    found: list[int] = []
    offset = max(0, start)
    while offset < blob.size and len(found) < limit:
        window = blob.read_at(offset, min(1024 * 1024, blob.size - offset))
        if len(window) < len(pattern):
            break
        for index in range(0, len(window) - len(pattern) + 1):
            if _equal(window[index : index + len(pattern)], pattern, mask):
                found.append(offset + index)
                if len(found) >= limit:
                    break
        if len(window) < 1024 * 1024:
            break
        offset += max(1, len(window) - len(pattern) + 1)
    return found


def _equal(window: bytes, pattern: bytes, mask: bytes) -> bool:
    return all(
        (got & mask_byte) == (expected & mask_byte)
        for got, expected, mask_byte in zip(window, pattern, mask, strict=True)
    )


def hexdump(blob: Blob, offset: int, length: int, width: int) -> str:
    """Render a classic hex and ASCII dump."""
    if width < 1 or width > 64:
        raise ArgumentError("Width must be from 1 to 64.")
    if offset < 0 or length < 0:
        raise ArgumentError("Offset and length must be zero or positive.")
    length = min(length, max(0, blob.size - offset))
    lines: list[str] = []
    cursor = offset
    remain = length
    while remain:
        chunk = blob.read_at(cursor, min(width, remain))
        if not chunk:
            break
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{cursor:08x}  {hex_part:<{width * 3}} {ascii_part}")
        cursor += len(chunk)
        remain -= len(chunk)
    return "\n".join(lines)


def require_hits(hits: list[int]) -> list[int]:
    """Raise when a search finds nothing."""
    if not hits:
        raise NotFoundError("The pattern was not found.")
    return hits
