<p align="center">
  <a href="https://github.com/lupaxa-security-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/security-toolbox/readme-logo.png" alt="Security Toolbox" />
  </a>
</p>

<h1 align="center">Magic Bytes</h1>

Magic Bytes identifies, checks, and extracts binary file structures. It runs offline and does not use the network.

A signature is not proof of a valid file. Validation is not proof that a file is safe to open. The tool never executes what it inspects or extracts.

## Install

Python 3.11 or newer:

```bash
pip install lupaxa-magic-bytes
```

The command is `magic-bytes`.

## Quick Start

```bash
magic-bytes identify mystery.dat
magic-bytes validate picture.png --level standard
magic-bytes carve suspicious.bin --list
```

## What it Does

- Identifies formats from bytes, including files whose extension is wrong or missing.
- Validates PNG, JPEG, GIF, BMP, ZIP, PDF, WAV, MP3, ELF, PE, SQLite, and GZIP.
- Reports other common formats from signatures when no structural validator exists.
- Finds embedded objects, trailing bytes, and overlapping interpretations.
- Carves recoverable ranges without modifying the source.
- Maps layouts, measures entropy, dumps hex, compares files, and scans directories.
- Accepts declarative TOML signatures. Rules cannot run programs.

## Confidence

Confidence is a label, not a probability. A file can be confidently identified and still be truncated.

| Confidence  | Meaning                                          |
| ----------- | ------------------------------------------------ |
| `confirmed` | Structural validation passed                     |
| `high`      | Strong signature, or validation was only partial |
| `medium`    | A recognised signature with limited support      |
| `low`       | A weak or ambiguous signature                    |
| `unknown`   | Not enough evidence                              |

## Commands

Global options come before the subcommand.

| Option                  | Effect                          |
| ----------------------- | ------------------------------- |
| `--config PATH`         | Load a TOML file                |
| `--json`                | Print one JSON document         |
| `--quiet`               | Hide the human report           |
| `--verbose`             | More diagnostic detail          |
| `--debug`               | Trace unexpected errors         |
| `--no-colour`           | Plain text                      |
| `--no-progress`         | Hide progress                   |
| `--jobs N`              | Worker count for scans          |
| `--max-file-size SIZE`  | Refuse larger inputs            |
| `--max-scan-bytes SIZE` | Bound a deep scan               |
| `--timeout SECONDS`     | Stop bounded work               |
| `--force`               | Replace an existing output file |
| `--version`             | Print the version               |
| `--help`                | Show help                       |

Sizes accept integers, `0x` hex, and `K`, `M`, or `G` suffixes.

| Command      | Purpose                         | Main options                                                                 |           |                                            |
| ------------ | ------------------------------- | ---------------------------------------------------------------------------- |           |                                            |
| `identify`   | Name the likely formats         | `--all`, `--deep`, `--offset`, `--signatures-only`                           |           |                                            |
| `inspect`    | Combine structure and findings  | `--deep`, `--embedded`, `--trailing`, `--entropy`, `--structure`, `--report` |           |                                            |
| `validate`   | Check one recognised structure  | `--format`, `--level basic\                                                  | standard\ | deep`, `--strict`, `--report`              |
| `scan`       | Walk a directory                | `--recursive`, `--mismatches`, `--invalid`, `--embedded`, `--trailing`       |           |                                            |
| `carve`      | Copy a range out of a file      | `--list`, `--id`, `--all`, `--offset`, `--length`, `--validated-only`        |           |                                            |
| `compare`    | Diff two files                  | `--structural`, `--bytewise`, `--format text\                                | json\     | html`                                      |
| `entropy`    | Shannon bits per byte           | `--block-size`, `--window-size`, `--step`, `--offset`, `--length`, `--chart` |           |                                            |
| `hexdump`    | Show or search bytes            | `--offset`, `--length`, `--width`, `--find`, `--utf8`                        |           |                                            |
| `map`        | Draw regions                    | `--format terminal\                                                          | html\     | json`, `--show-entropy`, `--show-embedded` |
| `signatures` | List and manage TOML rules      | `list`, `show`, `add`, `remove`, `validate`, `test`                          |           |                                            |

`identify` keeps competing candidates. The primary one is the strongest, not merely the first. An extension mismatch is an observation. High entropy is not evidence of encryption, and a PE overlay is not evidence of malice.

## Validation

| Level      | Behaviour                                                    |
| ---------- | ------------------------------------------------------------ |
| `basic`    | Signature and essential header checks                        |
| `standard` | Boundaries, required chunks, and declared sizes              |
| `deep`     | CRCs, deflate checks, and a read-only SQLite integrity check |

`--strict` turns warnings into failures. A failed validation exits 6. That is different from the validator failing to run.

PDF reports say when a full semantic parse was not done. ZIP64 and xref streams are called out instead of being treated as corruption. SQLite deep checks open the file read-only and immutable so they do not create a journal.

## Carving

```bash
magic-bytes carve suspicious.bin --list
magic-bytes carve suspicious.bin --id 2 --output recovered.bin
```

Boundaries are `exact`, `estimated`, or `user-selected`. Only an exact validated extraction is described as fully validated. Output is never executed. Existing files are kept unless `--force` is set. Each extraction reports the source
offset, length, and SHA-256.

## Custom Signatures

```toml
[[signature]]
id = "custom-data"
name = "Custom Data File"
mime = "application/x-custom"
extensions = [".dat"]
min_size = 16

[[signature.match]]
offset = 0
hex = "4C 55 50 41 ?? 41"
required = true
```

`hex` may also be a list of alternative patterns. `??` is a wildcard. `end_relative` measures from the end of the file. Built-in signatures cannot be replaced. A rule file that sets `command`, `exec`, `script`, `python`, or `shell` is
rejected.

```bash
magic-bytes signatures validate custom.toml
magic-bytes signatures test custom.toml sample.dat
magic-bytes signatures add custom.toml
```

## JSON

`--json` prints one object and nothing else on standard output. Offsets are integers. Reports include `catalogue_version` and `validator_version`.

```json
{
  "schema_version": 1,
  "command": "identify",
  "success": true,
  "results": []
}
```

## Exit Codes

| Code | Meaning                            |
| ---- | ---------------------------------- |
| 0    | Success                            |
| 1    | General failure                    |
| 2    | Invalid arguments or configuration |
| 3    | Unsupported format or operation    |
| 4    | Input or output error              |
| 5    | No recognised format               |
| 6    | Structural validation failed       |
| 7    | Extraction failed                  |
| 8    | Resource limit exceeded            |
| 9    | Invalid custom signature           |
| 10   | Partial batch failure              |

## Configuration

A file is optional. The user file is the platform config directory for `magic-bytes` / `Lupaxa` / `config.toml`. Environment variables use the `MAGIC_BYTES_` prefix and override the file. Explicit CLI options override both.

```toml
validation_level = "standard"
max_file_size = 536870912
max_scan_bytes = 536870912
max_depth = 4
max_candidates = 256
max_extract_size = 268435456
workers = 4
entropy_block_size = 4096
colour = true
follow_symlinks = false
timeout_seconds = 60
```

## Security

Inputs are untrusted. Declared lengths are checked before they are used. Decompression and candidate counts stop at configured limits. Archive carving copies the archive object; it does not unpack members or follow paths inside them. HTML
reports are self-contained and escape file-derived text.

## Troubleshooting

- `validate` on a signature-only format exits 3 because there is no structural validator.
- A ZIP or PDF with a prefix can still be valid. The report names the prefix.
- Deep scans can stop early when the candidate or byte limit is reached. The report then says the analysis is incomplete.
- `carve` without `--list`, `--id`, `--all`, or `--offset` only lists objects.

<a href="https://github.com/the-lupaxa-project">
  <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
