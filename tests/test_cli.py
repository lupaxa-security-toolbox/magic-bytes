"""Command-line behaviour."""

import json
from pathlib import Path

from tests.samples import png_bytes, zip_bytes

from lupaxa.magic_bytes.cli import main


def test_identify_json_and_mismatch(tmp_path: Path, capsys) -> None:
    sample = tmp_path / "mystery.dat"
    sample.write_bytes(png_bytes())
    code = main(["--json", "identify", str(sample)])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert payload["success"] is True
    assert payload["reports"][0]["results"][0]["format"] == "png"
    assert payload["reports"][0]["results"][0]["confidence"] == "confirmed"


def test_validate_failure_exit(tmp_path: Path) -> None:
    sample = tmp_path / "broken.png"
    sample.write_bytes(b"\x89PNG\r\n\x1a\n" + b"not-a-chunk")
    code = main(["validate", str(sample), "--level", "basic"])
    assert code == 6


def test_carve_and_hash(tmp_path: Path, capsys) -> None:
    source = tmp_path / "both.bin"
    source.write_bytes(png_bytes() + zip_bytes())
    listed = main(["carve", str(source), "--list"])
    assert listed == 0
    output = tmp_path / "out.bin"
    code = main(["carve", str(source), "--id", "1", "--output", str(output), "--force"])
    assert code == 0
    assert output.is_file()
    assert output.read_bytes().startswith(b"\x89PNG")
    capsys.readouterr()


def test_existing_output_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "picture.png"
    source.write_bytes(png_bytes())
    output = tmp_path / "copy.png"
    output.write_bytes(b"keep")
    code = main(["carve", str(source), "--id", "1", "--output", str(output)])
    assert code == 4
    assert output.read_bytes() == b"keep"


def test_missing_file_and_version(capsys) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip().count(".") >= 2
    assert main(["identify", "missing-file.bin"]) == 4


def test_hexdump_find_and_entropy(tmp_path: Path, capsys) -> None:
    sample = tmp_path / "blob.bin"
    sample.write_bytes(b"AAAA" + b"PK\x03\x04" + b"BBBB")
    assert main(["hexdump", str(sample), "--find", "50 4B 03 04"]) == 0
    captured = capsys.readouterr().out
    assert "match at 4" in captured
    assert main(["entropy", str(sample)]) == 0
