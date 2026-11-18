"""TOML configuration, environment variables, and defaults."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

import platformdirs

from lupaxa.magic_bytes.errors import ArgumentError, FilesystemError

APP_NAME = "magic-bytes"
APP_AUTHOR = "Lupaxa"
ENV_PREFIX = "MAGIC_BYTES_"


@dataclass
class Settings:
    """Resolved settings. CLI overrides win over the environment and the file."""

    validation_level: str = "standard"
    max_file_size: int = 512 * 1024 * 1024
    max_scan_bytes: int = 512 * 1024 * 1024
    max_depth: int = 4
    max_candidates: int = 256
    max_extract_size: int = 256 * 1024 * 1024
    max_decompressed_bytes: int = 256 * 1024 * 1024
    workers: int = 4
    entropy_block_size: int = 4096
    colour: bool = True
    follow_symlinks: bool = False
    include_hidden: bool = False
    timeout_seconds: float = 60
    custom_signature_dir: str = ""
    header_window: int = 4096
    tail_window: int = 65557


def user_config_path() -> Path:
    """Return the platform user configuration file."""
    return Path(platformdirs.user_config_dir(APP_NAME, APP_AUTHOR)) / "config.toml"


def user_signature_dir(settings: Settings) -> Path:
    """Return the directory that holds custom signature files."""
    if settings.custom_signature_dir:
        return Path(settings.custom_signature_dir)
    return Path(platformdirs.user_data_dir(APP_NAME, APP_AUTHOR)) / "signatures"


def _as_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArgumentError(f"{name} must be an integer.")
    return value


def _as_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ArgumentError(f"{name} must be true or false.")
    return value


def _as_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ArgumentError(f"{name} must be a string.")
    return value


def _apply_mapping(settings: Settings, raw: dict[str, object]) -> None:
    if "validation_level" in raw:
        level = _as_str(raw["validation_level"], "validation_level")
        if level not in {"basic", "standard", "deep"}:
            raise ArgumentError("validation_level must be basic, standard, or deep.")
        settings.validation_level = level
    for key in (
        "max_file_size",
        "max_scan_bytes",
        "max_depth",
        "max_candidates",
        "max_extract_size",
        "max_decompressed_bytes",
        "workers",
        "entropy_block_size",
    ):
        if key in raw:
            setattr(settings, key, _as_int(raw[key], key))
    if "timeout_seconds" in raw:
        value = raw["timeout_seconds"]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ArgumentError("timeout_seconds must be a number.")
        settings.timeout_seconds = float(value)
    for key in ("colour", "follow_symlinks", "include_hidden"):
        if key in raw:
            setattr(settings, key, _as_bool(raw[key], key))
    if "custom_signature_dir" in raw:
        settings.custom_signature_dir = _as_str(raw["custom_signature_dir"], "custom_signature_dir")
    if settings.workers < 1 or settings.max_depth < 0 or settings.entropy_block_size < 1:
        raise ArgumentError("Worker, depth, and block-size settings must be positive.")
    if settings.max_file_size < 1 or settings.max_scan_bytes < 1:
        raise ArgumentError("Size limits must be positive.")


def _env_mapping() -> dict[str, object]:
    found: dict[str, object] = {}
    integer_keys = {
        "MAX_FILE_SIZE",
        "MAX_SCAN_BYTES",
        "MAX_DEPTH",
        "MAX_CANDIDATES",
        "MAX_EXTRACT_SIZE",
        "MAX_DECOMPRESSED_BYTES",
        "WORKERS",
        "ENTROPY_BLOCK_SIZE",
    }
    bool_keys = {"COLOUR", "FOLLOW_SYMLINKS", "INCLUDE_HIDDEN"}
    for key, value in os.environ.items():
        if not key.startswith(ENV_PREFIX):
            continue
        name = key[len(ENV_PREFIX) :]
        field = name.lower()
        if name in integer_keys:
            found[field] = int(value, 0)
        elif name == "TIMEOUT_SECONDS":
            found[field] = float(value)
        elif name in bool_keys:
            found[field] = value.strip().lower() in {"1", "true", "yes", "on"}
        elif name in {"VALIDATION_LEVEL", "CUSTOM_SIGNATURE_DIR"}:
            found[field] = value
    return found


def load_settings(path: Path | None = None) -> Settings:
    """Load defaults, then a TOML file, then MAGIC_BYTES_* variables."""
    settings = Settings()
    chosen = path if path is not None else user_config_path()
    if chosen.is_file():
        try:
            raw = tomllib.loads(chosen.read_text(encoding="utf-8"))
        except OSError as exc:
            raise FilesystemError(f"Cannot read {chosen}: {exc}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ArgumentError(f"Invalid configuration: {exc}") from exc
        if not isinstance(raw, dict):
            raise ArgumentError("Configuration must be a TOML table.")
        _apply_mapping(settings, raw)
    elif path is not None:
        raise FilesystemError(f"Configuration not found: {path}")
    env = _env_mapping()
    if env:
        _apply_mapping(settings, env)
    return settings
