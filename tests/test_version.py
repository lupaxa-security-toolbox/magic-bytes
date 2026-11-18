"""Version format tests."""

import re

from lupaxa.magic_bytes.version import __version__, get_version


def test_version_is_semantic() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", __version__)
    assert get_version() == __version__
