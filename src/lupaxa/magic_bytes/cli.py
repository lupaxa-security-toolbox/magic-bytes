"""Command-line interface."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import NoReturn

import typer
from click import ClickException
from rich.console import Console
from rich.table import Table

from lupaxa.magic_bytes import __version__
from lupaxa.magic_bytes.analyse import (
    block_entropy,
    carving_objects,
    extension_note,
    identify,
    make_budget,
    require_extract_length,
    select_candidate,
    shannon,
    trailing_region,
)
from lupaxa.magic_bytes.compare import byte_ranges, structural
from lupaxa.magic_bytes.config import Settings, load_settings
from lupaxa.magic_bytes.errors import (
    ArgumentError,
    ExtractionError,
    FilesystemError,
    MagicError,
    NotFoundError,
    RuleError,
    UnsupportedError,
)
from lupaxa.magic_bytes.formats import VALIDATORS
from lupaxa.magic_bytes.hexview import hexdump, parse_pattern, require_hits, search
from lupaxa.magic_bytes.htmlreport import entropy_chart, escape, page, region_table
from lupaxa.magic_bytes.io import Blob, atomic_write, open_input, safe_name, stream_range
from lupaxa.magic_bytes.models import CATALOGUE_VERSION, VALIDATOR_VERSION, Candidate, Region
from lupaxa.magic_bytes.scan import scan_path
from lupaxa.magic_bytes.signatures import Signature, catalogue, load_rule_file, matches, remove_rule, save_rules

app = typer.Typer(add_completion=False, no_args_is_help=True)
signatures_app = typer.Typer(add_completion=False, no_args_is_help=True)
app.add_typer(signatures_app, name="signatures")


class State:
    """Options shared by every command."""

    def __init__(self) -> None:
        self.settings = Settings()
        self.json = False
        self.quiet = False
        self.verbose = False
        self.debug = False
        self.no_colour = False
        self.no_progress = False
        self.force = False
        self.jobs: int | None = None
        self.max_file_size: int | None = None
        self.max_scan_bytes: int | None = None
        self.timeout: float | None = None


def _version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


def _state(ctx: typer.Context) -> State:
    if not isinstance(ctx.obj, State):
        ctx.obj = State()
    return ctx.obj


def _settings(ctx: typer.Context) -> Settings:
    state = _state(ctx)
    settings = state.settings
    if state.jobs is not None:
        settings.workers = state.jobs
    if state.max_file_size is not None:
        settings.max_file_size = state.max_file_size
    if state.max_scan_bytes is not None:
        settings.max_scan_bytes = state.max_scan_bytes
    if state.timeout is not None:
        settings.timeout_seconds = state.timeout
    if state.no_colour:
        settings.colour = False
    return settings


def _emit(
    ctx: typer.Context,
    command: str,
    payload: Mapping[str, object],
    *,
    code: int = 0,
    warnings: list[str] | None = None,
) -> None:
    state = _state(ctx)
    document = {
        "schema_version": 1,
        "command": command,
        "success": code == 0,
        "incomplete": bool(payload.get("incomplete", False)),
        "catalogue_version": CATALOGUE_VERSION,
        "validator_version": VALIDATOR_VERSION,
        "warnings": warnings or [],
        "errors": [] if code == 0 else [{"code": "command", "message": payload.get("message", ""), "exit_code": code}],
    }
    document.update(payload)
    if state.json:
        sys.stdout.write(json.dumps(document, sort_keys=True) + "\n")
    elif not state.quiet or code != 0:
        text = payload.get("text")
        if isinstance(text, str) and text:
            typer.echo(text)
    if code:
        raise typer.Exit(code)


def _fail(ctx: typer.Context, command: str, exc: MagicError) -> NoReturn:
    payload: dict[str, object] = {"message": exc.message, "text": exc.message}
    if _state(ctx).json:
        _emit(ctx, command, payload, code=exc.exit_code)
    typer.echo(exc.message, err=True)
    raise typer.Exit(exc.exit_code)


def _open(path: Path | None, settings: Settings, *, stdin: bool) -> Blob:
    return open_input(path, max_size=settings.max_file_size, use_stdin=stdin)


def _quantity(text: str | None) -> int | None:
    if text is None:
        return None
    raw = text.strip().lower().replace("_", "")
    if raw.startswith("0x"):
        return int(raw, 16)
    suffixes = (("gb", 1024**3), ("g", 1024**3), ("mb", 1024**2), ("m", 1024**2), ("kb", 1024), ("k", 1024))
    for suffix, scale in suffixes:
        if raw.endswith(suffix) and raw[: -len(suffix)].isdigit():
            return int(raw[: -len(suffix)]) * scale
    if raw.isdigit():
        return int(raw)
    raise ArgumentError(f"Cannot parse quantity {text!r}.")


def _render_candidate(path: str, blob: Blob, candidate: Candidate | None, others: int) -> str:
    lines = [f"File: {path}", f"Size: {blob.size} bytes", f"SHA-256: {blob.sha256()}"]
    suffix = Path(path).suffix or "(none)"
    lines.append(f"Extension: {suffix}")
    if candidate is None:
        lines.append("")
        lines.append("Primary identification:")
        lines.append("  Format: unknown")
        lines.append("  Confidence: unknown")
        return "\n".join(lines)
    validation = "not available" if candidate.validation is None else candidate.validation.status
    lines.extend(
        [
            "",
            "Primary identification:",
            f"  Format: {candidate.name}",
            f"  MIME: {candidate.mime}",
            f"  Confidence: {candidate.confidence}",
            f"  Validation: {validation}",
            f"  Offset: {candidate.offset}",
            "",
            "Evidence:",
        ]
    )
    lines.extend(f"  - {item}" for item in candidate.evidence)
    for item in candidate.contradictions:
        lines.append(f"  - contradiction: {item}")
    note = extension_note(path, candidate)
    if note:
        lines.extend(["", "Extension:", f"  {note}"])
    if others:
        lines.append("")
        lines.append(f"Other candidates: {others}")
    return "\n".join(lines)


@app.callback()
def main_callback(
    ctx: typer.Context,
    config: Path | None = typer.Option(None, "--config", help="Load a TOML configuration file."),
    json_output: bool = typer.Option(False, "--json", help="Print a JSON document."),
    quiet: bool = typer.Option(False, "--quiet"),
    verbose: bool = typer.Option(False, "--verbose"),
    debug: bool = typer.Option(False, "--debug"),
    no_colour: bool = typer.Option(False, "--no-colour"),
    no_progress: bool = typer.Option(False, "--no-progress"),
    jobs: int | None = typer.Option(None, "--jobs"),
    max_file_size: str | None = typer.Option(None, "--max-file-size"),
    max_scan_bytes: str | None = typer.Option(None, "--max-scan-bytes"),
    timeout: float | None = typer.Option(None, "--timeout"),
    force: bool = typer.Option(False, "--force"),
    version: bool = typer.Option(False, "--version", is_eager=True, is_flag=True, callback=_version),
) -> None:
    """Identify, validate, and extract binary file structures."""
    if version:
        return
    state = State()
    state.settings = load_settings(config)
    state.json = json_output
    state.quiet = quiet
    state.verbose = verbose
    state.debug = debug
    state.no_colour = no_colour
    state.no_progress = no_progress
    state.force = force
    state.jobs = jobs
    state.max_file_size = _quantity(max_file_size)
    state.max_scan_bytes = _quantity(max_scan_bytes)
    state.timeout = timeout
    ctx.obj = state


def identify_cmd(
    ctx: typer.Context,
    paths: list[Path] = typer.Argument(None),
    show_all: bool = typer.Option(False, "--all"),
    deep: bool = typer.Option(False, "--deep"),
    offset: str | None = typer.Option(None, "--offset"),
    signatures_only: bool = typer.Option(False, "--signatures-only"),
    do_validate: bool = typer.Option(True, "--validate/--no-validate"),
) -> None:
    """Identify probable file formats."""
    _identify(ctx, paths, show_all, deep, offset, signatures_only or not do_validate)


def _identify(
    ctx: typer.Context,
    paths: list[Path] | None,
    show_all: bool,
    deep: bool,
    offset: str | None,
    signatures_only: bool,
) -> None:
    settings = _settings(ctx)
    chosen = paths or []
    use_stdin = not chosen
    targets = chosen or [Path("-")]
    reports: list[dict[str, object]] = []
    texts: list[str] = []
    failures = 0
    base = _quantity(offset)
    for path in targets:
        blob = None
        try:
            blob = _open(None if use_stdin else path, settings, stdin=use_stdin)
            budget = make_budget(settings)
            candidates = identify(
                blob,
                settings,
                budget,
                level=settings.validation_level,
                deep=deep,
                signatures_only=signatures_only,
                base_offset=base,
            )
            primary = next((item for item in candidates if item.primary), None)
            shown = candidates if show_all else candidates[:1]
            label = "stdin" if use_stdin else str(path)
            texts.append(_render_candidate(label, blob, primary, max(0, len(candidates) - 1)))
            reports.append(
                {
                    "file": {"path": label, "size": blob.size, "sha256": blob.sha256()},
                    "results": [item.to_dict() for item in (candidates if show_all or _state(ctx).json else shown)],
                    "incomplete": budget.incomplete,
                }
            )
            if primary is None:
                failures += 1
        except MagicError as exc:
            _fail(ctx, "identify", exc)
        finally:
            if blob is not None:
                blob.close()
    code = 5 if failures == len(targets) else 10 if failures else 0
    _emit(
        ctx,
        "identify",
        {
            "text": "\n\n".join(texts),
            "reports": reports,
            "incomplete": any(bool(item.get("incomplete")) for item in reports),
        },
        code=code,
    )


@app.command()
def validate(
    ctx: typer.Context,
    path: Path = typer.Argument(...),
    format_id: str | None = typer.Option(None, "--format"),
    level: str = typer.Option("standard", "--level"),
    strict: bool = typer.Option(False, "--strict"),
    report: Path | None = typer.Option(None, "--report"),
) -> None:
    """Validate a recognised file structure."""
    if level not in {"basic", "standard", "deep"}:
        _fail(ctx, "validate", ArgumentError("Level must be basic, standard, or deep."))
    settings = _settings(ctx)
    blob = None
    try:
        blob = _open(path, settings, stdin=str(path) == "-")
        budget = make_budget(settings)
        candidates = identify(blob, settings, budget, level=level, deep=False, strict=strict)
        candidate = select_candidate(candidates, format_id)
        if candidate.validation is None:
            _fail(ctx, "validate", UnsupportedError(f"{candidate.format_id} has no structural validator."))
        text = _render_candidate(str(path), blob, candidate, 0)
        payload = {
            "text": text,
            "file": {"path": str(path), "size": blob.size, "sha256": blob.sha256()},
            "results": [candidate.to_dict()],
            "incomplete": budget.incomplete,
        }
        if report is not None:
            _write_report(report, payload, _state(ctx).force)
        code = 6 if candidate.validation.status == "failed" else 0
        if code:
            payload["message"] = "Structural validation failed."
        _emit(ctx, "validate", payload, code=code, warnings=candidate.warnings)
    except MagicError as exc:
        _fail(ctx, "validate", exc)
    finally:
        if blob is not None:
            blob.close()


@app.command()
def inspect(
    ctx: typer.Context,
    path: Path = typer.Argument(...),
    deep: bool = typer.Option(False, "--deep"),
    embedded: bool = typer.Option(False, "--embedded"),
    trailing: bool = typer.Option(False, "--trailing"),
    entropy: bool = typer.Option(False, "--entropy"),
    structure: bool = typer.Option(False, "--structure"),
    max_depth: int | None = typer.Option(None, "--max-depth"),
    report: Path | None = typer.Option(None, "--report"),
) -> None:
    """Investigate signatures, structure, trailing bytes, and embedded objects."""
    settings = _settings(ctx)
    if max_depth is not None:
        settings.max_depth = max_depth
    blob = None
    try:
        blob = _open(path, settings, stdin=str(path) == "-")
        budget = make_budget(settings)
        want_deep = deep or embedded
        candidates = identify(blob, settings, budget, level=settings.validation_level, deep=want_deep)
        primary = next((item for item in candidates if item.primary), None)
        trail = trailing_region(blob, primary)
        regions = (
            []
            if primary is None or primary.validation is None
            else [item.to_dict() for item in primary.validation.regions]
        )
        if trail is not None and (trailing or structure or deep):
            regions.append(trail.to_dict())
        trail_entropy = None if trail is None or not (entropy or trailing) else shannon(blob, trail.start, trail.length)
        text = _render_candidate(str(path), blob, primary, max(0, len(candidates) - 1))
        if trail is not None:
            text += f"\n\nTrailing bytes: {trail.length} at offset {trail.start}"
            if trail_entropy is not None:
                text += f"\nTrailing entropy: {trail_entropy:.3f} bits/byte"
        payload = {
            "text": text,
            "file": {"path": str(path), "size": blob.size, "sha256": blob.sha256()},
            "results": [item.to_dict() for item in candidates],
            "regions": regions,
            "trailing_entropy": trail_entropy,
            "incomplete": budget.incomplete,
            "max_depth": settings.max_depth,
        }
        if report is not None:
            _write_report(report, payload, _state(ctx).force)
        code = 0 if primary is not None else 5
        _emit(ctx, "inspect", payload, code=code)
    except MagicError as exc:
        _fail(ctx, "inspect", exc)
    finally:
        if blob is not None:
            blob.close()


@app.command("scan")
def scan_cmd(
    ctx: typer.Context,
    path: Path = typer.Argument(...),
    recursive: bool = typer.Option(False, "--recursive"),
    mismatches: bool = typer.Option(False, "--mismatches"),
    invalid: bool = typer.Option(False, "--invalid"),
    embedded: bool = typer.Option(False, "--embedded"),
    trailing: bool = typer.Option(False, "--trailing"),
    format_id: str | None = typer.Option(None, "--format"),
    min_size: str | None = typer.Option(None, "--min-size"),
    max_size: str | None = typer.Option(None, "--max-size"),
    include_hidden: bool = typer.Option(False, "--include-hidden"),
    follow_symlinks: bool = typer.Option(False, "--follow-symlinks"),
    jobs: int | None = typer.Option(None, "--jobs"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Analyse a directory of files."""
    settings = _settings(ctx)
    summary = scan_path(
        path,
        settings,
        recursive=recursive,
        level=settings.validation_level,
        jobs=jobs or settings.workers,
        follow_symlinks=follow_symlinks or settings.follow_symlinks,
        include_hidden=include_hidden or settings.include_hidden,
        minimum=_quantity(min_size),
        maximum=_quantity(max_size),
        only_format=format_id,
        mismatches=mismatches,
        invalid=invalid,
        embedded=embedded,
        trailing=trailing,
    )
    lines = [
        f"Files: {summary['files']}",
        f"Bytes: {summary['bytes']}",
        f"Errors: {summary['errors']}",
        "Formats: " + _format_counts(summary.get("formats")),
    ]
    payload = {"text": "\n".join(lines), **summary}
    if output is not None:
        atomic_write(output, (json.dumps(payload, sort_keys=True) + "\n").encode(), force=_state(ctx).force)
    successes = _as_int(summary.get("files")) - _as_int(summary.get("errors"))
    code = 10 if summary["errors"] and successes else (4 if summary["errors"] else 0)
    _emit(ctx, "scan", payload, code=code)


@app.command()
def carve(
    ctx: typer.Context,
    path: Path = typer.Argument(...),
    list_only: bool = typer.Option(False, "--list"),
    object_id: int | None = typer.Option(None, "--id"),
    extract_all: bool = typer.Option(False, "--all"),
    offset: str | None = typer.Option(None, "--offset"),
    length: str | None = typer.Option(None, "--length"),
    validated_only: bool = typer.Option(False, "--validated-only"),
    output: Path | None = typer.Option(None, "--output"),
    output_dir: Path | None = typer.Option(None, "--output-dir"),
    verify: bool = typer.Option(False, "--verify"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    """Extract embedded or selected bytes. Extracted files are never executed."""
    settings = _settings(ctx)
    blob = None
    try:
        blob = _open(path, settings, stdin=False)
        budget = make_budget(settings)
        candidates = identify(blob, settings, budget, level="deep", deep=True)
        objects = carving_objects(candidates, blob)
        if list_only or (object_id is None and not extract_all and offset is None):
            lines = [
                f"{item['id']}: {item['format']} at {item['offset']} length {item['length']} ({item['boundary']})"
                for item in objects
            ]
            _emit(
                ctx,
                "carve",
                {"text": "\n".join(lines) or "No carved objects.", "objects": objects, "incomplete": budget.incomplete},
            )
            return
        chosen = _select_objects(objects, object_id, extract_all, validated_only, offset, length, blob.size)
        records = []
        for item in chosen:
            start = _as_int(item.get("offset"))
            size = _as_int(item.get("length"))
            require_extract_length(size, settings)
            destination = _carve_destination(output, output_dir, item, force or _state(ctx).force)
            digest = stream_range(blob, start, size, destination, force=force or _state(ctx).force)
            record = {**item, "output": str(destination), "sha256": digest, "source": str(path)}
            if verify and item.get("validated") and destination.stat().st_size != size:
                raise ExtractionError(f"Carved size does not match {destination}.")
            records.append(record)
        text = "\n".join(f"{item['output']} {item['sha256']}" for item in records)
        _emit(ctx, "carve", {"text": text, "objects": records, "incomplete": budget.incomplete})
    except MagicError as exc:
        _fail(ctx, "carve", exc)
    finally:
        if blob is not None:
            blob.close()


def _select_objects(
    objects: list[dict[str, object]],
    object_id: int | None,
    extract_all: bool,
    validated_only: bool,
    offset: str | None,
    length: str | None,
    file_size: int,
) -> list[dict[str, object]]:
    if offset is not None:
        start = _quantity(offset) or 0
        size = file_size - start if length is None else (_quantity(length) or 0)
        return [
            {
                "id": 0,
                "format": "range",
                "offset": start,
                "length": size,
                "boundary": "user-selected",
                "validated": False,
                "attributes": ["user-selected"],
            }
        ]
    pool = objects
    if validated_only:
        pool = [item for item in pool if item.get("validated")]
    if object_id is not None:
        pool = [item for item in pool if item.get("id") == object_id]
        if not pool:
            raise NotFoundError(f"No carved object with id {object_id}.")
        return pool
    if extract_all:
        if not pool:
            raise NotFoundError("No carved objects matched.")
        return pool
    raise ArgumentError("Choose --list, --id, --all, or --offset.")


def _carve_destination(output: Path | None, output_dir: Path | None, item: dict[str, object], force: bool) -> Path:
    del force
    if output is not None and output_dir is None:
        return output
    directory = output_dir or Path.cwd()
    name = safe_name(f"{item['id']}-{item['format']}.bin")
    return directory / name


@app.command()
def compare(
    ctx: typer.Context,
    left: Path = typer.Argument(...),
    right: Path = typer.Argument(...),
    structural_compare: bool = typer.Option(False, "--structural"),
    bytewise: bool = typer.Option(True, "--bytewise/--no-bytewise"),
    regions: bool = typer.Option(False, "--regions"),
    report_format: str = typer.Option("text", "--format"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Compare two files byte by byte and, optionally, by structure."""
    settings = _settings(ctx)
    left_blob = right_blob = None
    try:
        left_blob = _open(left, settings, stdin=False)
        right_blob = _open(right, settings, stdin=False)
        payload: dict[str, object] = {}
        if bytewise:
            payload["bytes"] = byte_ranges(left_blob, right_blob)
        if structural_compare or regions:
            payload["structure"] = structural(left_blob, right_blob, settings, settings.validation_level)
        text = _compare_text(payload)
        payload["text"] = text
        if output is not None:
            body = (
                page("Comparison", f"<pre>{text}</pre>")
                if report_format == "html"
                else (json.dumps(payload, sort_keys=True) if report_format == "json" else text).encode()
            )
            if report_format == "html":
                atomic_write(output, body.encode() if isinstance(body, str) else body, force=_state(ctx).force)
            else:
                data = body if isinstance(body, bytes) else body.encode()
                atomic_write(output, data, force=_state(ctx).force)
        _emit(ctx, "compare", payload)
    except MagicError as exc:
        _fail(ctx, "compare", exc)
    finally:
        if left_blob is not None:
            left_blob.close()
        if right_blob is not None:
            right_blob.close()


def _compare_text(payload: dict[str, object]) -> str:
    lines: list[str] = []
    raw = payload.get("bytes")
    if isinstance(raw, dict):
        lines.append(f"Sizes: {raw['left_size']} / {raw['right_size']}")
        lines.append(f"First difference: {raw['first_difference']}")
        ratio = raw.get("match_ratio")
        shown = float(ratio) if isinstance(ratio, (int, float)) else 0.0
        lines.append(f"Match ratio: {shown:.4f}")
        ranges = raw.get("ranges")
        if isinstance(ranges, list):
            for item in ranges[:20]:
                if isinstance(item, dict):
                    lines.append(f"  {item['start']}-{item['end']}")
    structure = payload.get("structure")
    if isinstance(structure, dict):
        lines.append(f"Formats: {structure.get('left_format')} / {structure.get('right_format')}")
        lines.append(f"Validation: {structure.get('left_validation')} / {structure.get('right_validation')}")
    return "\n".join(lines)


@app.command()
def entropy(
    ctx: typer.Context,
    path: Path = typer.Argument(...),
    block_size: str | None = typer.Option(None, "--block-size"),
    window_size: str | None = typer.Option(None, "--window-size"),
    step: str | None = typer.Option(None, "--step"),
    offset: str | None = typer.Option(None, "--offset"),
    length: str | None = typer.Option(None, "--length"),
    chart: bool = typer.Option(False, "--chart"),
    report_format: str = typer.Option("text", "--format"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Calculate Shannon entropy. High entropy is not evidence of encryption."""
    settings = _settings(ctx)
    blob = None
    try:
        blob = _open(path, settings, stdin=str(path) == "-")
        start = _quantity(offset) or 0
        size = blob.size - start if length is None else min(_quantity(length) or 0, blob.size - start)
        whole = shannon(blob, start, size)
        block = _quantity(block_size) or (_quantity(window_size) or settings.entropy_block_size)
        rows = block_entropy(blob, start, size, block)
        if step is not None and window_size is not None:
            rows = _windows(blob, start, size, _quantity(window_size) or block, _quantity(step) or block)
        text = f"Entropy: {whole:.4f} bits/byte\n" + "\n".join(f"{item[0]:08x}  {item[1]:.3f}" for item in rows[:32])
        payload: dict[str, object] = {
            "text": text,
            "entropy": whole,
            "blocks": [{"offset": item[0], "entropy": item[1]} for item in rows],
        }
        if chart or report_format == "html" or output is not None:
            body = entropy_chart(rows) if report_format == "html" or chart else text
            if output is not None:
                data = page("Entropy", body).encode() if report_format == "html" or chart else text.encode()
                atomic_write(output, data, force=_state(ctx).force)
        _emit(ctx, "entropy", payload)
    except MagicError as exc:
        _fail(ctx, "entropy", exc)
    finally:
        if blob is not None:
            blob.close()


def _windows(blob: Blob, start: int, size: int, window: int, step_size: int) -> list[tuple[int, float]]:
    rows: list[tuple[int, float]] = []
    offset = start
    end = start + size
    while offset < end:
        rows.append((offset, shannon(blob, offset, min(window, end - offset))))
        offset += step_size
    return rows


def hexdump_cmd(
    ctx: typer.Context,
    path: Path = typer.Argument(...),
    offset: str | None = typer.Option(None, "--offset"),
    length: str | None = typer.Option(None, "--length"),
    width: int = typer.Option(16, "--width"),
    find: str | None = typer.Option(None, "--find"),
    highlight_signatures: bool = typer.Option(False, "--highlight-signatures"),
    highlight_regions: bool = typer.Option(False, "--highlight-regions"),
    ascii_text: bool = typer.Option(True, "--ascii/--no-ascii"),
    utf8: bool = typer.Option(False, "--utf8"),
) -> None:
    """Inspect bytes as hexadecimal."""
    del highlight_signatures, highlight_regions, ascii_text
    settings = _settings(ctx)
    blob = None
    try:
        blob = _open(path, settings, stdin=str(path) == "-")
        start = _quantity(offset) or 0
        size = 256 if length is None else (_quantity(length) or 0)
        text = hexdump(blob, start, size, width)
        hits: list[int] = []
        if find:
            pattern, mask = parse_pattern(find)
            hits = require_hits(search(blob, pattern, mask, start=start))
            text += "\n" + "\n".join(f"match at {item}" for item in hits)
        if utf8:
            sample = blob.read_at(start, min(size, 256))
            text += "\n" + sample.decode("utf-8", "replace")
        _emit(ctx, "hexdump", {"text": text, "matches": hits, "offset": start, "length": size})
    except MagicError as exc:
        _fail(ctx, "hexdump", exc)
    finally:
        if blob is not None:
            blob.close()


def map_cmd(
    ctx: typer.Context,
    path: Path = typer.Argument(...),
    report_format: str = typer.Option("terminal", "--format"),
    output: Path | None = typer.Option(None, "--output"),
    show_offsets: bool = typer.Option(True, "--show-offsets/--no-offsets"),
    show_entropy: bool = typer.Option(False, "--show-entropy"),
    show_embedded: bool = typer.Option(False, "--show-embedded"),
    max_depth: int = typer.Option(2, "--max-depth"),
) -> None:
    """Show the layout of a binary file."""
    del max_depth
    settings = _settings(ctx)
    blob = None
    try:
        blob = _open(path, settings, stdin=str(path) == "-")
        budget = make_budget(settings)
        candidates = identify(blob, settings, budget, level=settings.validation_level, deep=show_embedded)
        primary = next((item for item in candidates if item.primary), None)
        regions = [] if primary is None or primary.validation is None else list(primary.validation.regions)
        trail = trailing_region(blob, primary)
        if trail is not None:
            regions.append(trail)
        if show_embedded:
            for candidate in candidates:
                if candidate.offset:
                    regions.append(candidate_region(candidate))
        lines = []
        for region in regions:
            entropy_note = f" entropy={shannon(blob, region.start, region.length):.2f}" if show_entropy else ""
            offset_note = f"{region.start:08x}-{region.end:08x} " if show_offsets else ""
            lines.append(f"{offset_note}{region.length:8d}  {region.region_type}  {region.name}{entropy_note}")
        text = "\n".join(lines) or "No regions."
        if report_format == "html":
            body = page(f"Map {path.name}", region_table(regions))
            if output is None:
                text = body
            else:
                atomic_write(output, body.encode(), force=_state(ctx).force)
        elif output is not None:
            data = (
                json.dumps({"regions": [item.to_dict() for item in regions]}, sort_keys=True).encode()
                if report_format == "json"
                else text.encode()
            )
            atomic_write(output, data, force=_state(ctx).force)
        _emit(
            ctx, "map", {"text": text, "regions": [item.to_dict() for item in regions], "incomplete": budget.incomplete}
        )
    except MagicError as exc:
        _fail(ctx, "map", exc)
    finally:
        if blob is not None:
            blob.close()


def candidate_region(candidate: Candidate) -> Region:
    """Adapt an embedded candidate to a region when a boundary exists."""
    end = candidate.offset
    if candidate.validation and candidate.validation.logical_end:
        end = candidate.validation.logical_end
    return Region(
        candidate.offset,
        end,
        "embedded",
        candidate.format_id,
        candidate.name,
        None,
        candidate.confidence,
        candidate.evidence,
    )


@signatures_app.command("list")
def signatures_list(ctx: typer.Context) -> None:
    """List built-in and user signatures."""
    settings = _settings(ctx)
    rows = catalogue(settings)
    if _tty(ctx):
        table = Table(title="Signatures")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Source")
        for item in rows:
            table.add_row(item.id, item.name, "built-in" if item.builtin else "user")
        Console(no_color=_state(ctx).no_colour).print(table)
    text = "\n".join(f"{item.id}\t{item.name}\t{'built-in' if item.builtin else 'user'}" for item in rows)
    _emit(ctx, "signatures-list", {"text": text, "signatures": [_signature_dict(item) for item in rows]})


@signatures_app.command("show")
def signatures_show(ctx: typer.Context, ident: str = typer.Argument(...)) -> None:
    """Show one signature."""
    for item in catalogue(_settings(ctx)):
        if item.id == ident:
            extensions = ", ".join(item.extensions)
            validator = item.id in VALIDATORS
            text = f"{item.id}: {item.name}\nMIME: {item.mime}\nExtensions: {extensions}\nValidator: {validator}"
            _emit(ctx, "signatures-show", {"text": text, "signature": _signature_dict(item)})
            return
    _fail(ctx, "signatures-show", NotFoundError(f"No signature named {ident}."))


@signatures_app.command("add")
def signatures_add(ctx: typer.Context, path: Path = typer.Argument(...)) -> None:
    """Install a declarative TOML signature file."""
    try:
        rules = load_rule_file(path)
        destination = save_rules(_settings(ctx), rules, path, force=_state(ctx).force)
    except (RuleError, FilesystemError) as exc:
        _fail(ctx, "signatures-add", exc)
        return
    _emit(ctx, "signatures-add", {"text": str(destination), "path": str(destination)})


@signatures_app.command("remove")
def signatures_remove(ctx: typer.Context, ident: str = typer.Argument(...)) -> None:
    """Remove a user signature. Built-in signatures stay installed."""
    try:
        remove_rule(_settings(ctx), ident)
    except (RuleError, FilesystemError) as exc:
        _fail(ctx, "signatures-remove", exc)
        return
    _emit(ctx, "signatures-remove", {"text": f"Removed {ident}.", "id": ident})


@signatures_app.command("validate")
def signatures_validate(ctx: typer.Context, path: Path = typer.Argument(...)) -> None:
    """Validate a signature file without installing it."""
    try:
        rules = load_rule_file(path)
    except (RuleError, FilesystemError) as exc:
        _fail(ctx, "signatures-validate", exc)
        return
    _emit(
        ctx,
        "signatures-validate",
        {"text": f"Valid: {', '.join(item.id for item in rules)}", "ids": [item.id for item in rules]},
    )


@signatures_app.command("test")
def signatures_test(
    ctx: typer.Context, rule_path: Path = typer.Argument(...), sample: Path = typer.Argument(...)
) -> None:
    """Test a signature file against one sample."""
    settings = _settings(ctx)
    blob = None
    try:
        rules = load_rule_file(rule_path)
        blob = _open(sample, settings, stdin=False)
        hits = [rule.id for rule in rules if matches(blob, rule, 0)]
        if not hits:
            raise NotFoundError("The sample did not match the signature file.")
        _emit(ctx, "signatures-test", {"text": "Matched " + ", ".join(hits), "matches": hits})
    except MagicError as exc:
        _fail(ctx, "signatures-test", exc)
    finally:
        if blob is not None:
            blob.close()


def _signature_dict(signature: Signature) -> dict[str, object]:
    return {
        "id": signature.id,
        "name": signature.name,
        "mime": signature.mime,
        "extensions": list(signature.extensions),
        "builtin": signature.builtin,
        "description": signature.description,
    }


def _tty(ctx: typer.Context) -> bool:
    state = _state(ctx)
    return sys.stdout.isatty() and not state.json and not state.no_colour and state.settings.colour


def _as_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArgumentError("Expected an integer field.")
    return value


def _format_counts(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    return ", ".join(f"{name}={count}" for name, count in value.items())


def _write_report(path: Path, payload: Mapping[str, object], force: bool) -> None:
    if path.suffix.lower() == ".html":
        body = page(path.stem, f"<pre>{escape(payload.get('text', ''))}</pre>")
        atomic_write(path, body.encode(), force=force)
        return
    atomic_write(path, (json.dumps(payload, sort_keys=True) + "\n").encode(), force=force)


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface."""
    try:
        result = app(args=argv, standalone_mode=False)
    except ClickException as exc:
        exc.show()
        return int(exc.exit_code or 2)
    except MagicError as exc:
        typer.echo(exc.message, err=True)
        return exc.exit_code
    except Exception as exc:
        state_debug = "--debug" in (argv or sys.argv)
        if state_debug:
            raise
        typer.echo(f"Unexpected failure: {exc}", err=True)
        return 1
    if isinstance(result, int):
        return result
    return 0


app.command("identify")(identify_cmd)
app.command("hexdump")(hexdump_cmd)
app.command("map")(map_cmd)
