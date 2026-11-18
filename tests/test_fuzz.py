"""Reproducible parser fuzzing."""

from hypothesis import given, settings
from hypothesis import strategies as st

from lupaxa.magic_bytes.analyse import identify, make_budget
from lupaxa.magic_bytes.config import Settings
from lupaxa.magic_bytes.errors import MagicError
from lupaxa.magic_bytes.io import Blob


@settings(derandomize=True, max_examples=25)
@given(st.binary(max_size=2048))
def test_random_input_does_not_escape(payload: bytes) -> None:
    blob = Blob(payload, None, 10_000_000)
    try:
        identify(blob, Settings(), make_budget(Settings()), level="basic", deep=False)
    except MagicError:
        return
