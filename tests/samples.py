"""Minimal synthetic files for the structural validators."""

from __future__ import annotations

import io
import sqlite3
import struct
import zipfile
import zlib
from pathlib import Path


def png_bytes() -> bytes:
    """Return a 1x1 PNG."""

    def chunk(marker: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(marker + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + marker + payload + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IEND", b"")


def jpeg_bytes() -> bytes:
    """Return a JPEG with one APP0 segment and an EOI marker."""
    payload = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    segment = b"\xff\xe0" + struct.pack(">H", len(payload) + 2) + payload
    return b"\xff\xd8" + segment + b"\xff\xd9"


def gif_bytes() -> bytes:
    """Return a 1x1 GIF89a with a trailer and no colour table."""
    return b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0, 0, 0) + b"\x3b"


def bmp_bytes() -> bytes:
    """Return a 1x1 24-bit BMP."""
    pixel_offset = 54
    pixels = b"\x00\x00\x00\x00"
    declared = pixel_offset + len(pixels)
    header = struct.pack("<2sIHHI", b"BM", declared, 0, 0, pixel_offset)
    info = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, len(pixels), 0, 0, 0, 0)
    return header + info + pixels


def zip_bytes() -> bytes:
    """Return a stored ZIP with one text entry."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("a.txt", "hello")
    return buffer.getvalue()


def pdf_bytes() -> bytes:
    """Return a small PDF with a classic xref table."""
    header = b"%PDF-1.4\n"
    obj = b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    xref_at = len(header) + len(obj)
    xref = b"xref\n0 2\n0000000000 65535 f \n" + f"{len(header):010d} 00000 n \n".encode()
    trailer = f"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode()
    return header + obj + xref + trailer


def wav_bytes() -> bytes:
    """Return a mono 8-bit WAV."""
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8)
    data = b"\x80\x80"

    def chunk(marker: bytes, payload: bytes) -> bytes:
        pad = b"\x00" if len(payload) % 2 else b""
        return marker + struct.pack("<I", len(payload)) + payload + pad

    body = b"WAVE" + chunk(b"fmt ", fmt) + chunk(b"data", data)
    return b"RIFF" + struct.pack("<I", len(body)) + body


def mp3_bytes() -> bytes:
    """Return one MPEG1 Layer III frame."""
    header = bytes((0xFF, 0xFB, 0x90, 0x00))
    bitrate = 128000
    rate = 44100
    length = 144 * bitrate // rate
    return header + bytes(length - 4)


def elf_bytes() -> bytes:
    """Return an empty little-endian ELF64 header."""
    data = bytearray(64)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[6] = 1
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 0x3E, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    return bytes(data)


def pe_bytes() -> bytes:
    """Return a PE with no sections and no overlay."""
    e_lfanew = 0x80
    optional = 96
    data = bytearray(e_lfanew + 4 + 20 + optional)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, e_lfanew + 4, 0x14C, 0, 0, 0, 0, optional, 0x102)
    struct.pack_into("<H", data, e_lfanew + 24, 0x10B)
    return bytes(data)


def sqlite_bytes(directory: Path) -> bytes:
    """Return a real SQLite database created in directory."""
    path = directory / "sample.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("create table items(value text)")
    connection.execute("insert into items values ('ok')")
    connection.commit()
    connection.close()
    return path.read_bytes()


def gzip_bytes(payload: bytes = b"hello") -> bytes:
    """Return one GZIP member."""
    compressor = zlib.compressobj(wbits=-15)
    body = compressor.compress(payload) + compressor.flush()
    header = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"
    trailer = struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload) & 0xFFFFFFFF)
    return header + body + trailer
