"""Bounded byte and structural comparison."""

from __future__ import annotations

from lupaxa.magic_bytes.analyse import identify, make_budget, select_candidate
from lupaxa.magic_bytes.config import Settings
from lupaxa.magic_bytes.errors import MagicError
from lupaxa.magic_bytes.io import Blob
from lupaxa.magic_bytes.models import Candidate


def byte_ranges(left: Blob, right: Blob) -> dict[str, object]:
    """Compare two files in blocks, then refine each differing block."""
    block = 4096 if max(left.size, right.size) > 256 * 1024 else 1
    ranges: list[dict[str, int]] = []
    offset = 0
    limit = max(left.size, right.size)
    matched = 0
    first: int | None = None
    while offset < limit:
        size = min(block, limit - offset)
        same = left.read_at(offset, size) == right.read_at(offset, size)
        if same:
            matched += min(size, left.size - offset, right.size - offset)
        else:
            start, end, local_match = _refine(left, right, offset, size)
            matched += local_match
            if first is None:
                first = start
            if ranges and ranges[-1]["end"] == start:
                ranges[-1]["end"] = end
            else:
                ranges.append({"start": start, "end": end, "length": end - start})
        offset += size
    for item in ranges:
        item["length"] = item["end"] - item["start"]
    total = max(left.size, right.size, 1)
    return {
        "left_size": left.size,
        "right_size": right.size,
        "left_sha256": left.sha256(),
        "right_sha256": right.sha256(),
        "first_difference": first,
        "matching_bytes": matched,
        "match_ratio": matched / total,
        "ranges": ranges,
        "size_delta": right.size - left.size,
    }


def _refine(left: Blob, right: Blob, offset: int, size: int) -> tuple[int, int, int]:
    end = offset + size
    start = offset
    matched = 0
    while (
        start < end and start < left.size and start < right.size and left.read_at(start, 1) == right.read_at(start, 1)
    ):
        start += 1
        matched += 1
    stop = end
    while (
        stop > start
        and stop - 1 < left.size
        and stop - 1 < right.size
        and left.read_at(stop - 1, 1) == right.read_at(stop - 1, 1)
    ):
        stop -= 1
        matched += 1
    return start, max(start, min(end, max(left.size, right.size) if stop == start else stop)), matched


def structural(left: Blob, right: Blob, settings: Settings, level: str) -> dict[str, object]:
    """Compare validated structure, separate from raw byte differences."""
    budget_left = make_budget(settings)
    budget_right = make_budget(settings)
    left_items = identify(left, settings, budget_left, level=level)
    right_items = identify(right, settings, budget_right, level=level)
    left_primary = _primary(left_items)
    right_primary = _primary(right_items)
    return {
        "left_format": None if left_primary is None else left_primary.format_id,
        "right_format": None if right_primary is None else right_primary.format_id,
        "same_format": left_primary is not None
        and right_primary is not None
        and left_primary.format_id == right_primary.format_id,
        "left_validation": None
        if left_primary is None or left_primary.validation is None
        else left_primary.validation.status,
        "right_validation": None
        if right_primary is None or right_primary.validation is None
        else right_primary.validation.status,
        "left_regions": _names(left_primary),
        "right_regions": _names(right_primary),
        "left_trailing": _trailing(left, left_primary),
        "right_trailing": _trailing(right, right_primary),
    }


def _primary(items: list[Candidate]) -> Candidate | None:
    if not items:
        return None
    try:
        return select_candidate(items, None)
    except MagicError:
        return items[0]


def _names(candidate: Candidate | None) -> list[str]:
    if candidate is None or candidate.validation is None:
        return []
    return [region.name for region in candidate.validation.regions]


def _trailing(blob: Blob, candidate: Candidate | None) -> int:
    if candidate is None or candidate.validation is None or candidate.validation.logical_end is None:
        return 0
    return max(0, blob.size - candidate.validation.logical_end)
