"""Identification, inspection, and carving decisions."""

from __future__ import annotations

import math
from pathlib import Path

from lupaxa.magic_bytes.config import Settings
from lupaxa.magic_bytes.errors import ArgumentError, ExtractionError, LimitError, NotFoundError
from lupaxa.magic_bytes.formats import VALIDATORS, validate_format
from lupaxa.magic_bytes.io import Blob
from lupaxa.magic_bytes.models import Budget, Candidate, Region, Validation
from lupaxa.magic_bytes.signatures import Signature, catalogue, evidence_lines, matches

RANK = {"confirmed": 5, "high": 4, "medium": 3, "low": 2, "unknown": 1}


def make_budget(settings: Settings, timeout: float | None = None) -> Budget:
    """Build a budget from settings and an optional CLI timeout."""
    return Budget(
        timeout_seconds=settings.timeout_seconds if timeout is None else timeout,
        max_candidates=settings.max_candidates,
        max_bytes=settings.max_scan_bytes,
        max_depth=settings.max_depth,
        max_decompressed=settings.max_decompressed_bytes,
    )


def identify(
    blob: Blob,
    settings: Settings,
    budget: Budget,
    *,
    level: str,
    deep: bool = False,
    signatures_only: bool = False,
    base_offset: int | None = None,
    strict: bool = False,
) -> list[Candidate]:
    """Return every relevant format candidate, strongest first."""
    found: list[Candidate] = []
    seen: set[tuple[str, int]] = set()
    for signature in catalogue(settings):
        for base in _bases(blob, signature, settings, budget, deep, base_offset):
            key = (signature.id, base)
            if key in seen:
                continue
            seen.add(key)
            if not matches(blob, signature, base) and not _container_hit(blob, signature, base):
                continue
            try:
                budget.take_candidate()
            except LimitError:
                break
            found.append(_candidate(blob, signature, base, settings, budget, level, signatures_only, strict))
        if budget.incomplete:
            break
    if not found:
        return []
    found.sort(key=lambda item: (-RANK[item.confidence], -_priority(item, settings), item.offset != 0, item.offset))
    found[0].primary = True
    return found


def _bases(
    blob: Blob,
    signature: Signature,
    settings: Settings,
    budget: Budget,
    deep: bool,
    forced: int | None,
) -> list[int]:
    if forced is not None:
        return [forced]
    if not signature.needle:
        return [0] if matches(blob, signature, 0) else []
    if signature.id == "zip":
        tail = blob.find(b"PK\x05\x06", max(0, blob.size - 65557), blob.size, limit=1)
        if tail:
            return [0]
    if not deep and not signature.scan:
        return [0] if matches(blob, signature, 0) else []
    end = (
        blob.size
        if deep
        else min(blob.size, max(settings.header_window, signature.needle_bias + len(signature.needle) + 64))
    )
    if deep:
        end = min(end, settings.max_scan_bytes)
    limit = 16 if not signature.scan else min(64, budget.max_candidates)
    hits = blob.find(signature.needle, 0, end, limit=limit, alignment=max(1, signature.alignment))
    bases = [hit - signature.needle_bias for hit in hits if hit >= signature.needle_bias]
    if matches(blob, signature, 0) and 0 not in bases:
        bases.insert(0, 0)
    return list(dict.fromkeys(bases))


def _container_hit(blob: Blob, signature: Signature, base: int) -> bool:
    if signature.id == "zip" and base == 0:
        return bool(blob.find(b"PK\x05\x06", max(0, blob.size - 65557), blob.size, limit=1))
    if signature.id == "pdf":
        return b"%PDF-" in blob.read_at(base, 1024)
    return False


def _priority(candidate: Candidate, settings: Settings) -> int:
    for signature in catalogue(settings):
        if signature.id == candidate.format_id:
            return signature.priority
    return 0


def _candidate(
    blob: Blob,
    signature: Signature,
    base: int,
    settings: Settings,
    budget: Budget,
    level: str,
    signatures_only: bool,
    strict: bool,
) -> Candidate:
    validation: Validation | None = None
    if not signatures_only and signature.id in VALIDATORS:
        try:
            validation = validate_format(signature.id, blob, base, level, budget, strict=strict)
        except LimitError:
            budget.incomplete = True
    confidence = _confidence(signature, validation, signatures_only)
    attributes = list(validation.attributes) if validation else ["signature-only"]
    if validation is None:
        attributes = ["signature-only"]
    contradictions = []
    if validation and validation.status == "failed":
        contradictions = [item.detail for item in validation.checks if not item.passed and item.severity == "error"]
    return Candidate(
        format_id=signature.id,
        name=signature.name,
        mime=signature.mime,
        extensions=list(signature.extensions),
        offset=base,
        confidence=confidence,
        evidence=evidence_lines(blob, signature, base) or [f"{signature.name} signature"],
        contradictions=contradictions,
        validation=validation,
        variant=validation.variant if validation else signature.variant,
        warnings=list(validation.warnings) if validation else [],
        attributes=attributes,
    )


def _confidence(signature: Signature, validation: Validation | None, signatures_only: bool) -> str:
    if validation and validation.status == "passed":
        return "confirmed"
    if validation and validation.status == "partial":
        return "high"
    if signatures_only or validation is None:
        return "high" if signature.strength == "strong" else signature.strength
    if signature.strength == "strong":
        return "high"
    return "medium" if signature.strength == "medium" else "low"


def extension_note(path: str, candidate: Candidate | None) -> str | None:
    """Describe an extension mismatch. A mismatch is an observation, not malice."""
    if candidate is None:
        return None
    suffix = Path(path).suffix.lower()
    if not suffix:
        return "The filename has no extension."
    if suffix not in candidate.extensions:
        expected = ", ".join(candidate.extensions) or "none"
        return f"Extension {suffix} is not a usual extension for {candidate.name} ({expected})."
    return None


def trailing_region(blob: Blob, candidate: Candidate | None) -> Region | None:
    """Return bytes after a validator's logical end, when one was established."""
    if candidate is None or candidate.validation is None or candidate.validation.logical_end is None:
        return None
    end = candidate.validation.logical_end
    if end >= blob.size:
        return None
    kind = "overlay" if candidate.format_id == "pe" else "trailing"
    description = (
        "PE overlay is a normal place for appended data." if kind == "overlay" else "Bytes outside the logical file."
    )
    return Region(end, blob.size, kind, kind, description, candidate.format_id, "passed", [])


def shannon(blob: Blob, start: int, length: int) -> float:
    """Shannon entropy in bits per byte, from 0 to 8."""
    if length < 0 or start < 0:
        raise ArgumentError("Entropy ranges must be zero or positive.")
    counts = [0] * 256
    remain = min(length, max(0, blob.size - start))
    offset = start
    total = 0
    while remain:
        chunk = blob.read_at(offset, min(1024 * 1024, remain))
        if not chunk:
            break
        for byte in chunk:
            counts[byte] += 1
        total += len(chunk)
        offset += len(chunk)
        remain -= len(chunk)
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


def block_entropy(blob: Blob, start: int, length: int, block_size: int) -> list[tuple[int, float]]:
    """Entropy of successive fixed blocks."""
    if block_size < 1:
        raise ArgumentError("Block size must be positive.")
    rows: list[tuple[int, float]] = []
    offset = start
    end = min(blob.size, start + length)
    while offset < end:
        size = min(block_size, end - offset)
        rows.append((offset, shannon(blob, offset, size)))
        offset += size
    return rows


def select_candidate(candidates: list[Candidate], format_id: str | None) -> Candidate:
    """Choose the requested format, or the primary candidate."""
    if format_id:
        for candidate in candidates:
            if candidate.format_id == format_id:
                return candidate
        raise NotFoundError(f"No {format_id} candidate was found.")
    if not candidates:
        raise NotFoundError("No recognised format.")
    return next(item for item in candidates if item.primary)


def carving_objects(candidates: list[Candidate], blob: Blob) -> list[dict[str, object]]:
    """List objects that can be copied out without running them."""
    objects: list[dict[str, object]] = []
    index = 1
    for candidate in candidates:
        validation = candidate.validation
        if validation is None or validation.logical_end is None:
            continue
        length = validation.logical_end - candidate.offset
        if length <= 0:
            continue
        boundary = "exact" if validation.boundary == "exact" and validation.status == "passed" else validation.boundary
        objects.append(
            {
                "id": index,
                "format": candidate.format_id,
                "offset": candidate.offset,
                "length": length,
                "boundary": boundary,
                "validated": validation.status == "passed" and validation.boundary == "exact",
                "attributes": list(candidate.attributes),
            }
        )
        index += 1
    if blob.size and not objects:
        return objects
    return objects


def require_extract_length(length: int, settings: Settings) -> None:
    """Reject an extraction that exceeds the configured limit."""
    if length > settings.max_extract_size:
        raise ExtractionError(f"Extraction of {length} bytes exceeds the limit.")
