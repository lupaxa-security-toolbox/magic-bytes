"""Built-in catalogue and declarative TOML signature rules."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from lupaxa.magic_bytes.config import Settings, user_signature_dir
from lupaxa.magic_bytes.errors import FilesystemError, RuleError
from lupaxa.magic_bytes.io import Blob

MAX_RULE_OFFSET = 16 * 1024 * 1024


@dataclass
class Match:
    """One byte condition relative to a candidate, or to the end of the file."""

    offset: int
    pattern: bytes
    mask: bytes
    required: bool
    end_relative: bool


@dataclass
class MatchGroup:
    """Every match in the group must succeed. Groups are alternatives."""

    matches: list[Match]


@dataclass
class Signature:
    """A declarative format signature. Rules never carry executable code."""

    id: str
    name: str
    mime: str
    extensions: list[str]
    groups: list[MatchGroup]
    min_size: int = 0
    max_size: int | None = None
    alignment: int = 1
    priority: int = 100
    description: str = ""
    variant: str = ""
    builtin: bool = False
    strength: str = "strong"
    scan: bool = True
    needle: bytes = b""
    needle_bias: int = 0


def _hex_bytes(text: str, label: str) -> tuple[bytes, bytes]:
    parts = text.replace(",", " ").split()
    if not parts:
        raise RuleError(f"{label} is empty.")
    pattern = bytearray()
    mask = bytearray()
    for part in parts:
        if part in {"??", "?"}:
            pattern.append(0)
            mask.append(0)
            continue
        if len(part) != 2:
            raise RuleError(f"{label} has an invalid byte {part!r}.")
        try:
            pattern.append(int(part, 16))
        except ValueError as exc:
            raise RuleError(f"{label} has an invalid byte {part!r}.") from exc
        mask.append(0xFF)
    return bytes(pattern), bytes(mask)


def _apply_mask(mask_text: str, pattern: bytes, mask: bytes) -> bytes:
    parsed, _explicit = _hex_bytes(mask_text, "mask")
    if len(parsed) != len(pattern):
        raise RuleError("A mask must be the same length as its pattern.")
    combined = bytearray(mask)
    for index, value in enumerate(parsed):
        combined[index] &= value
    return bytes(combined)


def parse_rules(text: str, *, builtin: bool = False) -> list[Signature]:
    """Parse a declarative TOML signature document."""
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise RuleError(f"Invalid signature TOML: {exc}") from exc
    forbidden = {"command", "exec", "script", "python", "shell", "code"}
    if forbidden.intersection(raw):
        raise RuleError("Signature files must be declarative.")
    entries = raw.get("signature", [])
    if not isinstance(entries, list) or not entries:
        raise RuleError("A signature file needs at least one [[signature]] table.")
    parsed: list[Signature] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuleError("Each signature must be a table.")
        if forbidden.intersection(entry):
            raise RuleError("Signature files must be declarative.")
        ident = entry.get("id")
        name = entry.get("name")
        if not isinstance(ident, str) or not ident or any(char in ident for char in " /\\"):
            raise RuleError("Each signature needs a single-segment id.")
        if ident in seen:
            raise RuleError(f"Duplicate signature id {ident}.")
        seen.add(ident)
        if not isinstance(name, str) or not name:
            raise RuleError(f"{ident} needs a name.")
        mime = entry.get("mime", "application/octet-stream")
        if not isinstance(mime, str):
            raise RuleError(f"{ident} mime must be a string.")
        extensions = entry.get("extensions", [])
        if not isinstance(extensions, list) or not all(isinstance(item, str) for item in extensions):
            raise RuleError(f"{ident} extensions must be a list of strings.")
        min_size = int(entry.get("min_size", 0))
        max_size = entry.get("max_size")
        alignment = int(entry.get("alignment", 1))
        priority = int(entry.get("priority", 100))
        if min_size < 0 or alignment < 1 or priority < 0:
            raise RuleError(f"{ident} has an invalid size, alignment, or priority.")
        if max_size is not None and (not isinstance(max_size, int) or max_size < min_size):
            raise RuleError(f"{ident} max_size is invalid.")
        groups = _groups(entry, ident)
        description = entry.get("description", "")
        variant = entry.get("variant", "")
        if not isinstance(description, str) or not isinstance(variant, str):
            raise RuleError(f"{ident} description and variant must be strings.")
        needle, bias = _needle(groups)
        parsed.append(
            Signature(
                id=ident,
                name=name,
                mime=mime,
                extensions=[item if item.startswith(".") else f".{item}" for item in extensions],
                groups=groups,
                min_size=min_size,
                max_size=max_size if isinstance(max_size, int) else None,
                alignment=alignment,
                priority=priority,
                description=description,
                variant=variant,
                builtin=builtin,
                strength="strong" if len(needle) >= 4 else "medium",
                scan=len(needle) >= 3,
                needle=needle,
                needle_bias=bias,
            )
        )
    return parsed


def _groups(entry: dict[str, object], ident: str) -> list[MatchGroup]:
    groups: list[MatchGroup] = []
    hex_value = entry.get("hex")
    if isinstance(hex_value, str):
        groups.append(MatchGroup(_match_list([{"offset": 0, "hex": hex_value, "required": True}], ident)))
    elif isinstance(hex_value, list):
        for item in hex_value:
            if not isinstance(item, str):
                raise RuleError(f"{ident} hex alternatives must be strings.")
            groups.append(MatchGroup(_match_list([{"offset": 0, "hex": item, "required": True}], ident)))
    matches = entry.get("match", [])
    alternatives = entry.get("alternative", [])
    if not isinstance(matches, list) or not isinstance(alternatives, list):
        raise RuleError(f"{ident} match entries must be a list.")
    if matches:
        groups.append(MatchGroup(_match_list(matches, ident)))
    for item in alternatives:
        if not isinstance(item, dict):
            raise RuleError(f"{ident} alternatives must be tables.")
        nested = item.get("match")
        if not isinstance(nested, list):
            raise RuleError(f"{ident} alternatives need match lists.")
        groups.append(MatchGroup(_match_list(nested, ident)))
    if not groups:
        raise RuleError(f"{ident} needs at least one match.")
    return groups


def _match_list(items: list[object], ident: str) -> list[Match]:
    parsed: list[Match] = []
    for item in items:
        if not isinstance(item, dict):
            raise RuleError(f"{ident} has a match that is not a table.")
        offset = item.get("offset", 0)
        hex_text = item.get("hex")
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise RuleError(f"{ident} has a non-integer offset.")
        if abs(offset) > MAX_RULE_OFFSET:
            raise RuleError(f"{ident} offset is outside the allowed range.")
        if not isinstance(hex_text, str):
            raise RuleError(f"{ident} match needs a hex string.")
        pattern, mask = _hex_bytes(hex_text, f"{ident} hex")
        if "mask" in item:
            if not isinstance(item["mask"], str):
                raise RuleError(f"{ident} mask must be a hex string.")
            mask = _apply_mask(item["mask"], pattern, mask)
        end_relative = bool(item.get("end_relative", offset < 0))
        if end_relative and offset < 0:
            offset = abs(offset)
        required = bool(item.get("required", True))
        parsed.append(Match(offset, pattern, mask, required, end_relative))
    if not any(item.required for item in parsed):
        raise RuleError(f"{ident} needs a required match.")
    return parsed


def _needle(groups: list[MatchGroup]) -> tuple[bytes, int]:
    best: Match | None = None
    for group in groups:
        for match in group.matches:
            if match.required and not match.end_relative and (best is None or len(match.pattern) > len(best.pattern)):
                best = match
    if best is None:
        return b"", 0
    visible = bytes(byte if mask else 0 for byte, mask in zip(best.pattern, best.mask, strict=True))
    if visible.strip(b"\x00") == b"":
        return best.pattern, best.offset
    return visible, best.offset


def matches(blob: Blob, signature: Signature, base: int) -> bool:
    """Return whether any alternative group matches at base."""
    if signature.alignment > 1 and base % signature.alignment != 0:
        return False
    available = blob.size - base
    if available < signature.min_size:
        return False
    if base == 0 and signature.max_size is not None and blob.size > signature.max_size:
        return False
    return any(_group_matches(blob, group, base) for group in signature.groups)


def _group_matches(blob: Blob, group: MatchGroup, base: int) -> bool:
    saw_required = False
    for match in group.matches:
        relative = blob.size - match.offset - len(match.pattern)
        start = relative if match.end_relative else base + match.offset
        window = blob.read_at(start, len(match.pattern))
        ok = len(window) == len(match.pattern) and _masked_equal(window, match)
        if not match.required:
            continue
        saw_required = True
        if not ok:
            return False
    return saw_required


def _masked_equal(window: bytes, match: Match) -> bool:
    for got, expected, mask in zip(window, match.pattern, match.mask, strict=True):
        if (got & mask) != (expected & mask):
            return False
    return True


def evidence_lines(blob: Blob, signature: Signature, base: int) -> list[str]:
    """Describe the matches that fired."""
    lines: list[str] = []
    for group in signature.groups:
        if not _group_matches(blob, group, base):
            continue
        for match in group.matches:
            start = blob.size - match.offset - len(match.pattern) if match.end_relative else base + match.offset
            where = "end" if match.end_relative else f"0x{start:08x}"
            lines.append(f"{signature.name} bytes at {where}")
        break
    return lines


def _builtin() -> list[Signature]:
    documents = [
        """
[[signature]]
id = "png"
name = "PNG"
mime = "image/png"
extensions = [".png"]
min_size = 8
priority = 80
[[signature.match]]
offset = 0
hex = "89 50 4E 47 0D 0A 1A 0A"
""",
        """
[[signature]]
id = "jpeg"
name = "JPEG"
mime = "image/jpeg"
extensions = [".jpg", ".jpeg", ".jpe", ".jfif"]
min_size = 4
priority = 70
[[signature.match]]
offset = 0
hex = "FF D8 FF"
""",
        """
[[signature]]
id = "gif"
name = "GIF"
mime = "image/gif"
extensions = [".gif"]
min_size = 14
priority = 80
hex = ["47 49 46 38 37 61", "47 49 46 38 39 61"]
""",
        """
[[signature]]
id = "bmp"
name = "BMP"
mime = "image/bmp"
extensions = [".bmp", ".dib"]
min_size = 26
priority = 40
[[signature.match]]
offset = 0
hex = "42 4D"
""",
        """
[[signature]]
id = "zip"
name = "ZIP"
mime = "application/zip"
extensions = [".zip", ".jar", ".docx", ".xlsx", ".pptx", ".odt", ".apk"]
min_size = 22
priority = 60
hex = ["50 4B 03 04", "50 4B 05 06", "50 4B 07 08"]
""",
        """
[[signature]]
id = "pdf"
name = "PDF"
mime = "application/pdf"
extensions = [".pdf"]
min_size = 8
priority = 75
[[signature.match]]
offset = 0
hex = "25 50 44 46 2D"
""",
        """
[[signature]]
id = "wav"
name = "WAV"
mime = "audio/wav"
extensions = [".wav", ".wave"]
min_size = 12
priority = 85
[[signature.match]]
offset = 0
hex = "52 49 46 46"
[[signature.match]]
offset = 8
hex = "57 41 56 45"
""",
        """
[[signature]]
id = "mp3"
name = "MP3"
mime = "audio/mpeg"
extensions = [".mp3"]
min_size = 4
priority = 30
hex = ["49 44 33", "FF FB", "FF F3", "FF F2"]
""",
        """
[[signature]]
id = "elf"
name = "ELF"
mime = "application/x-elf"
extensions = [".elf", ".so", ".o"]
min_size = 52
priority = 90
[[signature.match]]
offset = 0
hex = "7F 45 4C 46"
""",
        """
[[signature]]
id = "pe"
name = "PE"
mime = "application/vnd.microsoft.portable-executable"
extensions = [".exe", ".dll", ".sys", ".efi"]
min_size = 64
priority = 50
[[signature.match]]
offset = 0
hex = "4D 5A"
""",
        """
[[signature]]
id = "sqlite"
name = "SQLite"
mime = "application/vnd.sqlite3"
extensions = [".sqlite", ".sqlite3", ".db"]
min_size = 100
priority = 90
[[signature.match]]
offset = 0
hex = "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00"
""",
        """
[[signature]]
id = "gzip"
name = "GZIP"
mime = "application/gzip"
extensions = [".gz", ".gzip", ".tgz"]
min_size = 18
priority = 80
[[signature.match]]
offset = 0
hex = "1F 8B"
""",
        """
[[signature]]
id = "webp"
name = "WebP"
mime = "image/webp"
extensions = [".webp"]
min_size = 12
priority = 85
[[signature.match]]
offset = 0
hex = "52 49 46 46"
[[signature.match]]
offset = 8
hex = "57 45 42 50"
""",
        """
[[signature]]
id = "avi"
name = "AVI"
mime = "video/x-msvideo"
extensions = [".avi"]
min_size = 12
priority = 85
[[signature.match]]
offset = 0
hex = "52 49 46 46"
[[signature.match]]
offset = 8
hex = "41 56 49 20"
""",
        """
[[signature]]
id = "tiff"
name = "TIFF"
mime = "image/tiff"
extensions = [".tif", ".tiff"]
min_size = 8
priority = 70
hex = ["49 49 2A 00", "4D 4D 00 2A"]
""",
        """
[[signature]]
id = "flac"
name = "FLAC"
mime = "audio/flac"
extensions = [".flac"]
min_size = 4
[[signature.match]]
offset = 0
hex = "66 4C 61 43"
""",
        """
[[signature]]
id = "ogg"
name = "Ogg"
mime = "application/ogg"
extensions = [".ogg", ".oga", ".ogv"]
min_size = 4
[[signature.match]]
offset = 0
hex = "4F 67 67 53"
""",
        """
[[signature]]
id = "mp4"
name = "ISO BMFF"
mime = "video/mp4"
extensions = [".mp4", ".m4a", ".mov", ".heic"]
min_size = 12
[[signature.match]]
offset = 4
hex = "66 74 79 70"
""",
        """
[[signature]]
id = "sevenzip"
name = "7-Zip"
mime = "application/x-7z-compressed"
extensions = [".7z"]
min_size = 6
[[signature.match]]
offset = 0
hex = "37 7A BC AF 27 1C"
""",
        """
[[signature]]
id = "rar"
name = "RAR"
mime = "application/vnd.rar"
extensions = [".rar"]
min_size = 7
[[signature.match]]
offset = 0
hex = "52 61 72 21 1A 07"
""",
        """
[[signature]]
id = "bzip2"
name = "bzip2"
mime = "application/x-bzip2"
extensions = [".bz2"]
min_size = 10
[[signature.match]]
offset = 0
hex = "42 5A 68"
""",
        """
[[signature]]
id = "xz"
name = "XZ"
mime = "application/x-xz"
extensions = [".xz"]
min_size = 12
[[signature.match]]
offset = 0
hex = "FD 37 7A 58 5A 00"
""",
        """
[[signature]]
id = "zstd"
name = "Zstandard"
mime = "application/zstd"
extensions = [".zst"]
min_size = 4
[[signature.match]]
offset = 0
hex = "28 B5 2F FD"
""",
        """
[[signature]]
id = "wasm"
name = "WebAssembly"
mime = "application/wasm"
extensions = [".wasm"]
min_size = 8
[[signature.match]]
offset = 0
hex = "00 61 73 6D"
""",
        """
[[signature]]
id = "macho"
name = "Mach-O"
mime = "application/x-mach-binary"
extensions = [".o", ".dylib"]
min_size = 4
priority = 55
hex = ["FE ED FA CE", "FE ED FA CF", "CE FA ED FE", "CF FA ED FE"]
""",
        """
[[signature]]
id = "ttf"
name = "TrueType"
mime = "font/ttf"
extensions = [".ttf", ".otf"]
min_size = 12
hex = ["00 01 00 00", "4F 54 54 4F"]
""",
        """
[[signature]]
id = "woff"
name = "WOFF"
mime = "font/woff"
extensions = [".woff", ".woff2"]
min_size = 4
hex = ["77 4F 46 46", "77 4F 46 32"]
""",
        """
[[signature]]
id = "ole"
name = "OLE Compound File"
mime = "application/x-cfb"
extensions = [".doc", ".xls", ".ppt", ".msi"]
min_size = 8
[[signature.match]]
offset = 0
hex = "D0 CF 11 E0 A1 B1 1A E1"
""",
        """
[[signature]]
id = "java-class"
name = "Java Class"
mime = "application/java-vm"
extensions = [".class"]
min_size = 8
[[signature.match]]
offset = 0
hex = "CA FE BA BE"
""",
        """
[[signature]]
id = "psd"
name = "Photoshop"
mime = "image/vnd.adobe.photoshop"
extensions = [".psd"]
min_size = 4
[[signature.match]]
offset = 0
hex = "38 42 50 53"
""",
        """
[[signature]]
id = "pcap"
name = "pcap"
mime = "application/vnd.tcpdump.pcap"
extensions = [".pcap", ".cap"]
min_size = 24
hex = ["D4 C3 B2 A1", "A1 B2 C3 D4"]
""",
        """
[[signature]]
id = "cab"
name = "Cabinet"
mime = "application/vnd.ms-cab-compressed"
extensions = [".cab"]
min_size = 8
[[signature.match]]
offset = 0
hex = "4D 53 43 46"
""",
        """
[[signature]]
id = "tar"
name = "tar"
mime = "application/x-tar"
extensions = [".tar"]
min_size = 262
[[signature.match]]
offset = 257
hex = "75 73 74 61 72"
""",
        """
[[signature]]
id = "iso9660"
name = "ISO 9660"
mime = "application/x-iso9660-image"
extensions = [".iso"]
min_size = 32774
[[signature.match]]
offset = 32769
hex = "43 44 30 30 31"
""",
    ]
    found: list[Signature] = []
    for document in documents:
        found.extend(parse_rules(document, builtin=True))
    for item in found:
        item.builtin = True
        if item.id in {"bmp", "pe", "mp3"}:
            item.strength = "medium"
        if item.id in {"bmp", "pe"}:
            item.scan = False
    return found


BUILTIN: list[Signature] = _builtin()
BUILTIN_IDS = {item.id for item in BUILTIN}


def catalogue(settings: Settings) -> list[Signature]:
    """Return built-in signatures followed by valid user rules."""
    items = list(BUILTIN)
    directory = user_signature_dir(settings)
    if not directory.is_dir():
        return items
    for path in sorted(directory.glob("*.toml")):
        try:
            loaded = parse_rules(path.read_text(encoding="utf-8"))
        except (OSError, RuleError):
            continue
        for rule in loaded:
            if rule.id in BUILTIN_IDS:
                continue
            items.append(rule)
    return items


def load_rule_file(path: Path) -> list[Signature]:
    """Load and validate one custom rule file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FilesystemError(f"Cannot read {path}: {exc}") from exc
    rules = parse_rules(text)
    conflicts = [rule.id for rule in rules if rule.id in BUILTIN_IDS]
    if conflicts:
        raise RuleError("Custom rules cannot replace built-in signatures: " + ", ".join(conflicts))
    return rules


def save_rules(settings: Settings, rules: list[Signature], source: Path, *, force: bool) -> Path:
    """Copy a validated rule file into the user signature directory."""
    directory = user_signature_dir(settings)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{rules[0].id}.toml"
    if destination.exists() and not force:
        raise FilesystemError(f"Refusing to overwrite {destination}.")
    destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return destination


def remove_rule(settings: Settings, ident: str) -> None:
    """Delete a user rule. Built-in signatures stay in the catalogue."""
    if ident in BUILTIN_IDS:
        raise RuleError(f"{ident} is built in and cannot be removed.")
    path = user_signature_dir(settings) / f"{ident}.toml"
    if not path.is_file():
        raise FilesystemError(f"No user signature named {ident}.")
    path.unlink()
