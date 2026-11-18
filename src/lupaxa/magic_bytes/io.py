"""Bounded reads, hashing, and atomic output."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

from lupaxa.magic_bytes.errors import ArgumentError, FilesystemError, LimitError


class Blob:
    """Random-access view of an untrusted file. The source is never opened for writing."""

    def __init__(self, data: bytes | None, path: Path | None, max_size: int) -> None:
        self.path = path
        self._data = data
        self._handle: BinaryIO | None = None
        if data is not None:
            if len(data) > max_size:
                raise LimitError(f"Input exceeds the {max_size}-byte limit.")
            self.size = len(data)
            self.label = "<memory>" if path is None else str(path)
            return
        if path is None:
            raise ArgumentError("A path or a byte string is required.")
        try:
            self.size = path.stat().st_size
        except OSError as exc:
            raise FilesystemError(f"Cannot stat {path}: {exc}") from exc
        if self.size > max_size:
            raise LimitError(f"{path} exceeds the {max_size}-byte limit.")
        try:
            self._handle = path.open("rb")
        except OSError as exc:
            raise FilesystemError(f"Cannot read {path}: {exc}") from exc
        self.label = str(path)

    def close(self) -> None:
        """Close a file-backed blob."""
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def read_at(self, offset: int, length: int) -> bytes:
        """Read a window. Declared lengths are clipped to the file."""
        if offset < 0 or length < 0:
            raise ArgumentError("Offsets and lengths must be zero or positive.")
        if length > 64 * 1024 * 1024:
            raise LimitError("Refusing a single read larger than 64 MiB.")
        if offset >= self.size or length == 0:
            return b""
        end = min(self.size, offset + length)
        if self._data is not None:
            return self._data[offset:end]
        if self._handle is None:
            raise FilesystemError("The input is closed.")
        self._handle.seek(offset)
        return self._handle.read(end - offset)

    def find(self, needle: bytes, start: int, end: int, *, limit: int, alignment: int = 1) -> list[int]:
        """Find a byte string with a streaming overlap. Results are capped."""
        if not needle:
            return []
        start = max(0, start)
        end = min(self.size, end)
        found: list[int] = []
        window = 1024 * 1024
        overlap = len(needle) - 1
        pos = start
        while pos < end and len(found) < limit:
            chunk = self.read_at(pos, min(window, end - pos))
            if not chunk:
                break
            base = pos
            search_from = 0
            while len(found) < limit:
                hit = chunk.find(needle, search_from)
                if hit < 0:
                    break
                absolute = base + hit
                if alignment <= 1 or absolute % alignment == 0:
                    found.append(absolute)
                search_from = hit + 1
            if len(chunk) < window:
                break
            pos += max(1, len(chunk) - overlap)
        return found

    def sha256(self) -> str:
        """Hash the file in chunks."""
        digest = hashlib.sha256()
        offset = 0
        while offset < self.size:
            chunk = self.read_at(offset, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            offset += len(chunk)
        return digest.hexdigest()


def open_input(path: Path | None, *, max_size: int, use_stdin: bool = False) -> Blob:
    """Open a path, or spool standard input up to the size limit."""
    if use_stdin:
        payload = sys.stdin.buffer.read(max_size + 1)
        if len(payload) > max_size:
            raise LimitError(f"Standard input exceeds the {max_size}-byte limit.")
        return Blob(payload, None, max_size)
    return Blob(None, path, max_size)


def atomic_write(path: Path, payload: bytes, *, force: bool) -> None:
    """Write a new file. Existing files stay in place unless force is set."""
    if path.exists() and not force:
        raise FilesystemError(f"Refusing to overwrite {path}.")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = f".{path.name}.magic-bytes-tmp"
    tmp = path.with_name(tmp_name)
    try:
        tmp.write_bytes(payload)
        os.replace(tmp, path)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        raise FilesystemError(str(exc)) from exc


def stream_range(blob: Blob, start: int, length: int, dest: Path, *, force: bool) -> str:
    """Copy a range to a new file and return its SHA-256."""
    if start < 0 or length < 0 or start > blob.size:
        raise ArgumentError("The requested range is outside the file.")
    length = min(length, blob.size - start)
    if dest.exists() and not force:
        raise FilesystemError(f"Refusing to overwrite {dest}.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.magic-bytes-tmp")
    digest = hashlib.sha256()
    try:
        with tmp.open("wb") as handle:
            offset = start
            remain = length
            while remain:
                chunk = blob.read_at(offset, min(1024 * 1024, remain))
                if not chunk:
                    break
                handle.write(chunk)
                digest.update(chunk)
                offset += len(chunk)
                remain -= len(chunk)
        os.replace(tmp, dest)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        raise FilesystemError(str(exc)) from exc
    return digest.hexdigest()


def safe_name(stem: str) -> str:
    """Return a single path segment with no traversal."""
    cleaned = Path(stem).name
    if cleaned in {"", ".", ".."} or "/" in stem or "\\" in stem:
        raise FilesystemError("The output name is not a single safe path segment.")
    return cleaned


def temporary_copy(payload: bytes) -> Path:
    """Write bytes to a private temporary file that the caller deletes."""
    descriptor, name = tempfile.mkstemp(prefix="magic-bytes-")
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
    return Path(name)
