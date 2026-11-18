"""Stable error types and exit codes."""


class MagicError(Exception):
    """Base failure. Subclasses carry a stable exit code."""

    exit_code = 1
    code = "error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ArgumentError(MagicError):
    """Invalid arguments or configuration."""

    exit_code = 2
    code = "argument"


class UnsupportedError(MagicError):
    """Unsupported format or operation."""

    exit_code = 3
    code = "unsupported"


class FilesystemError(MagicError):
    """Input or output failure."""

    exit_code = 4
    code = "io"


class NotFoundError(MagicError):
    """No recognised format or match."""

    exit_code = 5
    code = "not_found"


class ValidationFailed(MagicError):
    """A validator ran and the structure failed."""

    exit_code = 6
    code = "validation"


class ExtractionError(MagicError):
    """Carving or extraction failed."""

    exit_code = 7
    code = "extraction"


class LimitError(MagicError):
    """A configured resource limit was hit."""

    exit_code = 8
    code = "limit"


class RuleError(MagicError):
    """A custom signature rule is invalid."""

    exit_code = 9
    code = "rule"


class PartialBatchError(MagicError):
    """Some files in a batch failed and some succeeded."""

    exit_code = 10
    code = "partial"
