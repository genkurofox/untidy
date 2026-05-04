# untidy

Offline CLI that scans local files for sensitive data and writes a CSV report. No data leaves the machine.

## Install

```
pip install -e .
```

Or use the **single-file** version with no install:

```
python untidy_solo.py scan PATH ...
```

`untidy_solo.py` is a self-contained drop-in. CSV/SQL/JSON/text scanning works
out of the box; Excel/PDF/DOCX/YAML scanning requires the matching optional
package and degrades gracefully if missing (the file type is skipped with a
read error).

## Usage

Scan files on disk:

```
untidy scan PATH [PATH ...] [options]
```

Scan a git repo's history for sensitive data in **deleted** files (they stay in history forever after `git rm`):

```
untidy scan-git REPO_PATH [options]
```

### Options

| flag | default | description |
|------|---------|-------------|
| `--output` | `untidy-findings.csv` | Where to write the CSV report |
| `--exclude GLOB` | (none) | Skip paths matching this glob. Repeatable. |
| `--include-ext` | all supported types | Comma-separated extensions to scan |
| `--max-size-mb` | `200` | Skip files larger than this |
| `--min-confidence` | `low` | Drop findings below this confidence (`low`/`medium`/`high`) |
| `--no-mask` | off | Emit raw matches instead of masked values |
| `--strict` | off | Exit non-zero if any file failed to read (don't conflate read errors with "no findings") |
| `--verbose` | off | Per-file progress on stderr |

`scan-git` additionally supports `--max-commits N` to cap how many deletion events are scanned, and omits `--exclude` (history entries aren't paths on disk).

### Supported file types

- **CSV** — streamed row-by-row; headers used for column-level heuristics
- **Excel** (`.xlsx`) — every sheet, streamed via openpyxl read-only
- **T-SQL** (`.sql`) — string literals, `INSERT ... VALUES`, and comments
- **PDF** (`.pdf`) — page-by-page text extraction (pdfminer.six)
- **DOCX** (`.docx`) — paragraphs and table cells (python-docx)
- **JSON / NDJSON** — every primitive value; the dict key becomes the column header so `{"first_name": "Jane"}` flags NAME
- **YAML** (`.yaml`, `.yml`) — same as JSON via PyYAML
- **Plain text / logs / markdown** — line-by-line regex scan

### Detection

Value-level regex + checksums combined with column-header heuristics for tabular data. Coverage:

- **PII identifiers** — SSN (validated), Luhn-validated credit cards, email, US phone, international phone (E.164), dates, IPv4, IPv6, US routing number, IBAN (with mod-97 checksum), MRN (header- or keyword-gated), passport, US driver's license, ICD-10 diagnosis codes
- **Inline name / address / DOB** — keyword-gated free-text patterns (`name:`, `address:`, `DOB:`)
- **Secrets** — AWS access key + secret access key, GitHub PATs, Slack tokens, Stripe keys, Google API keys, JWTs, PEM private keys
- **Header heuristics** for tabular data — `ssn`, `dob`, `patient_name`, `address`, `iban`, `passport`, `drivers_license`, `password`, etc.

### Exit codes

- `0` — no findings (and no read errors when `--strict` is set)
- `1` — findings present
- `2` — error (bad path, not a git repo, or read errors with `--strict`)

## Privacy

- Zero network code paths.
- Matches are masked by default (last 4 chars visible). Use `--no-mask` to triage.
- Tests ship with synthetic sample data only.
