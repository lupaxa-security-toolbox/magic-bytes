"""Shared result objects."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from lupaxa.magic_bytes.errors import LimitError

CATALOGUE_VERSION = "1"
VALIDATOR_VERSION = "1"


@dataclass
class Budget:
    """Bounds for scanning, parsing, and decompression."""

    timeout_seconds: float
    max_candidates: int
    max_bytes: int
    max_depth: int
    max_decompressed: int
    started: float = field(default_factory=time.monotonic)
    candidates: int = 0
    processed: int = 0
    decompressed: int = 0
    incomplete: bool = False
    notes: list[str] = field(default_factory=list)

    def tick(self, amount: int = 0) -> None:
        """Count work and stop when a limit is exceeded."""
        self.processed += amount
        if self.timeout_seconds and time.monotonic() - self.started > self.timeout_seconds:
            self._stop("Timed out.")
        if self.max_bytes and self.processed > self.max_bytes:
            self._stop("Scan byte limit exceeded.")

    def take_candidate(self) -> None:
        """Record one embedded candidate."""
        self.candidates += 1
        if self.candidates > self.max_candidates:
            self._stop("Candidate limit exceeded.")

    def take_decompressed(self, amount: int) -> None:
        """Record decompressed bytes."""
        self.decompressed += amount
        if self.decompressed > self.max_decompressed:
            self._stop("Decompression limit exceeded.")

    def _stop(self, message: str) -> None:
        self.incomplete = True
        if message not in self.notes:
            self.notes.append(message)
        raise LimitError(message)


@dataclass
class Check:
    """One structural check."""

    name: str
    passed: bool
    detail: str
    start: int = 0
    end: int = 0
    severity: str = "error"

    def to_dict(self) -> dict[str, object]:
        """Serialise the check."""
        return {
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
            "start": self.start,
            "end": self.end,
            "severity": self.severity,
        }


@dataclass
class Region:
    """A mapped byte range. Overlaps are kept."""

    start: int
    end: int
    region_type: str
    name: str
    description: str
    parent: str | None
    status: str
    evidence: list[str] = field(default_factory=list)

    @property
    def length(self) -> int:
        """Return the exclusive-end length."""
        return max(0, self.end - self.start)

    def to_dict(self) -> dict[str, object]:
        """Serialise the region."""
        return {
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "type": self.region_type,
            "name": self.name,
            "description": self.description,
            "parent": self.parent,
            "status": self.status,
            "evidence": list(self.evidence),
        }


@dataclass
class Validation:
    """Result of one format validator."""

    format_id: str
    level: str
    status: str
    checks: list[Check] = field(default_factory=list)
    regions: list[Region] = field(default_factory=list)
    logical_end: int | None = None
    boundary: str = "unknown"
    carving: bool = False
    warnings: list[str] = field(default_factory=list)
    attributes: list[str] = field(default_factory=list)
    variant: str = ""

    def to_dict(self) -> dict[str, object]:
        """Serialise the validation result."""
        return {
            "format": self.format_id,
            "level": self.level,
            "status": self.status,
            "logical_end": self.logical_end,
            "boundary": self.boundary,
            "carving": self.carving,
            "variant": self.variant,
            "warnings": list(self.warnings),
            "attributes": list(self.attributes),
            "checks": [item.to_dict() for item in self.checks],
            "regions": [item.to_dict() for item in self.regions],
        }


@dataclass
class Candidate:
    """One format interpretation of a file or embedded range."""

    format_id: str
    name: str
    mime: str
    extensions: list[str]
    offset: int
    confidence: str
    evidence: list[str]
    contradictions: list[str]
    validation: Validation | None
    variant: str
    warnings: list[str]
    attributes: list[str]
    primary: bool = False

    def to_dict(self) -> dict[str, object]:
        """Serialise the candidate."""
        validation = self.validation.to_dict() if self.validation else None
        return {
            "format": self.format_id,
            "name": self.name,
            "mime": self.mime,
            "extensions": list(self.extensions),
            "offset": self.offset,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "contradictions": list(self.contradictions),
            "validation": validation,
            "variant": self.variant,
            "warnings": list(self.warnings),
            "attributes": list(self.attributes),
            "primary": self.primary,
        }


def finish_status(checks: list[Check], *, incomplete: bool) -> str:
    """Derive passed, failed, or partial from checks."""
    hard = [item for item in checks if not item.passed and item.severity == "error"]
    if hard:
        return "failed"
    if incomplete:
        return "partial"
    return "passed"
