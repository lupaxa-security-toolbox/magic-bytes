"""Directory scanning with a bounded worker pool."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from lupaxa.magic_bytes.analyse import extension_note, identify, make_budget, trailing_region
from lupaxa.magic_bytes.config import Settings
from lupaxa.magic_bytes.errors import MagicError
from lupaxa.magic_bytes.io import Blob


def scan_path(
    root: Path,
    settings: Settings,
    *,
    recursive: bool,
    level: str,
    jobs: int,
    follow_symlinks: bool,
    include_hidden: bool,
    minimum: int | None,
    maximum: int | None,
    only_format: str | None,
    mismatches: bool,
    invalid: bool,
    embedded: bool,
    trailing: bool,
) -> dict[str, object]:
    """Examine files under a directory. Symlinks are skipped unless requested."""
    paths = _collect(root, recursive, include_hidden, follow_symlinks)
    workers = max(1, jobs)

    def examine(path: Path) -> dict[str, object]:
        return _one(path, settings, level, minimum, maximum)

    if workers == 1:
        rows = [examine(path) for path in paths]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            rows = list(pool.map(examine, paths))
    kept = [row for row in rows if _keep(row, only_format, mismatches, invalid, embedded, trailing)]
    errors = [row for row in kept if row.get("error")]
    examined = [row for row in kept if not row.get("skipped")]
    return {
        "files": len(examined),
        "bytes": _byte_total(examined),
        "errors": len(errors),
        "results": kept,
        "formats": _distribution(kept),
    }


def _collect(root: Path, recursive: bool, include_hidden: bool, follow_symlinks: bool) -> list[Path]:
    if root.is_file():
        return [root]
    found: list[Path] = []
    if not recursive:
        for path in sorted(root.iterdir()):
            if not include_hidden and path.name.startswith("."):
                continue
            if path.is_symlink() and not follow_symlinks:
                continue
            if path.is_file():
                found.append(path)
        return found
    for directory, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        if not include_hidden:
            dirnames[:] = [name for name in dirnames if not name.startswith(".")]
            filenames = [name for name in filenames if not name.startswith(".")]
        for name in filenames:
            path = Path(directory) / name
            if path.is_symlink() and not follow_symlinks:
                continue
            if path.is_file():
                found.append(path)
    return sorted(found)


def _one(path: Path, settings: Settings, level: str, minimum: int | None, maximum: int | None) -> dict[str, object]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return {"path": str(path), "error": str(exc), "exit_code": 4}
    if minimum is not None and size < minimum:
        return {"path": str(path), "size": size, "skipped": True, "reason": "min-size"}
    if maximum is not None and size > maximum:
        return {"path": str(path), "size": size, "skipped": True, "reason": "max-size"}
    blob = None
    try:
        blob = Blob(None, path, settings.max_file_size)
        budget = make_budget(settings)
        candidates = identify(blob, settings, budget, level=level, deep=False)
        primary = next((item for item in candidates if item.primary), None)
        note = extension_note(str(path), primary)
        trail = trailing_region(blob, primary)
        embedded_count = len([item for item in candidates if item.offset])
        return {
            "path": str(path),
            "size": size,
            "format": None if primary is None else primary.format_id,
            "confidence": None if primary is None else primary.confidence,
            "validation": None if primary is None or primary.validation is None else primary.validation.status,
            "mismatch": note,
            "embedded": embedded_count,
            "trailing": 0 if trail is None else trail.length,
            "incomplete": budget.incomplete,
        }
    except MagicError as exc:
        return {"path": str(path), "size": size, "error": exc.message, "exit_code": exc.exit_code}
    finally:
        if blob is not None:
            blob.close()


def _keep(
    row: dict[str, object],
    only_format: str | None,
    mismatches: bool,
    invalid: bool,
    embedded: bool,
    trailing: bool,
) -> bool:
    if row.get("skipped"):
        return False
    if only_format and row.get("format") != only_format and not row.get("error"):
        return False
    if mismatches and not row.get("mismatch"):
        return False
    if invalid and row.get("validation") != "failed":
        return False
    if embedded and not row.get("embedded"):
        return False
    return not (trailing and not row.get("trailing"))


def _byte_total(rows: list[dict[str, object]]) -> int:
    total = 0
    for row in rows:
        if row.get("error"):
            continue
        size = row.get("size", 0)
        if isinstance(size, int) and not isinstance(size, bool):
            total += size
    return total


def _distribution(rows: list[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        name = row.get("format")
        if isinstance(name, str):
            counts[name] = counts.get(name, 0) + 1
        elif row.get("error"):
            counts["error"] = counts.get("error", 0) + 1
        else:
            counts["unknown"] = counts.get("unknown", 0) + 1
    return dict(sorted(counts.items()))
