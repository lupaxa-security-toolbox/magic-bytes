"""Validator and identification tests."""

from pathlib import Path

import pytest
from tests.samples import (
    bmp_bytes,
    elf_bytes,
    gif_bytes,
    gzip_bytes,
    jpeg_bytes,
    mp3_bytes,
    pdf_bytes,
    pe_bytes,
    png_bytes,
    sqlite_bytes,
    wav_bytes,
    zip_bytes,
)

from lupaxa.magic_bytes.analyse import extension_note, identify, make_budget, shannon, trailing_region
from lupaxa.magic_bytes.compare import byte_ranges
from lupaxa.magic_bytes.config import Settings
from lupaxa.magic_bytes.errors import RuleError
from lupaxa.magic_bytes.io import Blob
from lupaxa.magic_bytes.signatures import matches, parse_rules


def _primary(payload: bytes, level: str = "standard") -> str:
    blob = Blob(payload, None, 10_000_000)
    found = identify(blob, Settings(), make_budget(Settings()), level=level)
    assert found
    assert found[0].primary
    return found[0].format_id


def test_each_structural_format(tmp_path: Path) -> None:
    samples = {
        "png": png_bytes(),
        "jpeg": jpeg_bytes(),
        "gif": gif_bytes(),
        "bmp": bmp_bytes(),
        "zip": zip_bytes(),
        "pdf": pdf_bytes(),
        "wav": wav_bytes(),
        "mp3": mp3_bytes(),
        "elf": elf_bytes(),
        "pe": pe_bytes(),
        "sqlite": sqlite_bytes(tmp_path),
        "gzip": gzip_bytes(),
    }
    for format_id, payload in samples.items():
        assert _primary(payload) == format_id
        blob = Blob(payload, None, 10_000_000)
        candidate = identify(blob, Settings(), make_budget(Settings()), level="deep")[0]
        assert candidate.validation is not None
        assert candidate.validation.status == "passed"
        assert candidate.confidence == "confirmed"


def test_extension_mismatch_and_trailing() -> None:
    payload = png_bytes() + b"EXTRA"
    blob = Blob(payload, None, 10_000_000)
    candidate = identify(blob, Settings(), make_budget(Settings()), level="standard")[0]
    note = extension_note("mystery.dat", candidate)
    assert note is not None
    assert ".dat" in note
    region = trailing_region(blob, candidate)
    assert region is not None
    assert region.length == 5


def test_embedded_zip_is_kept() -> None:
    payload = png_bytes() + zip_bytes()
    blob = Blob(payload, None, 10_000_000)
    found = identify(blob, Settings(), make_budget(Settings()), level="standard", deep=True)
    formats = {item.format_id for item in found}
    assert "png" in formats
    assert "zip" in formats


def test_custom_rule_matches_and_rejects_code() -> None:
    rules = parse_rules(
        """
[[signature]]
id = "custom-data"
name = "Custom Data File"
mime = "application/x-custom"
extensions = [".dat"]
min_size = 8
hex = "4C 55 50 41"
"""
    )
    blob = Blob(b"LUPAxxxx", None, 1000)
    assert matches(blob, rules[0], 0)
    with pytest.raises(RuleError, match="declarative"):
        parse_rules("command = \"rm -rf /\"\n[[signature]]\nid='x'\nname='x'\nhex='00'\n")


def test_entropy_and_compare() -> None:
    blob = Blob(b"\x00" * 64, None, 1000)
    assert shannon(blob, 0, 64) == 0
    same = byte_ranges(blob, Blob(b"\x00" * 64, None, 1000))
    assert same["first_difference"] is None
    changed = byte_ranges(blob, Blob(b"\x00" * 63 + b"\xff", None, 1000))
    assert changed["first_difference"] == 63
