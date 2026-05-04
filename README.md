# untidy

Offline CLI that scans local files for sensitive data and writes a CSV report. No data leaves the machine.

## Install

```
pip install -e .
```

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
| `--include-ext` | `.csv,.xlsx,.sql,.txt,.log,.md` | Comma-separated extensions to scan |
| `--max-size-mb` | `200` | Skip files larger than this |
| `--min-confidence` | `low` | Drop findings below this confidence (`low`/`medium`/`high`) |
| `--no-mask` | off | Emit raw matches instead of masked values |
| `--verbose` | off | Per-file progress on stderr |

`scan-git` additionally supports `--max-commits N` to cap how many deletion events are scanned, and omits `--exclude` (history entries aren't paths on disk).

### Supported file types

- **CSV** — streamed row-by-row; headers used for column-level heuristics
- **Excel** (`.xlsx`) — every sheet, streamed via openpyxl read-only mode
- **T-SQL** (`.sql`) — string literals, `INSERT ... VALUES`, and comments
- Plain text / logs / markdown — line-by-line regex scan

### Detection

Value-level regex + checksums (SSN, Luhn-validated credit card, email, US phone, dates, medical-record numbers, IP, routing number) combined with column-header heuristics for tabular data (`ssn`, `dob`, `patient_name`, `address`, etc.).

### Exit codes

- `0` — no findings
- `1` — findings present
- `2` — error

## Privacy

- Zero network code paths.
- Matches are masked by default (last 4 chars visible). Use `--no-mask` to triage.
- Tests ship with synthetic sample data only.
