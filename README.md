# Sentinel SOC Lite

Sentinel SOC Lite is a lightweight, rule-based educational Security Operations Centre (SOC) log analyzer. It parses synthetic authentication events, identifies suspicious patterns, assigns severity, and writes JSON and CSV reports. It is not a production SIEM and does not determine that an IP address is malicious.

## Problem statement and objectives

Authentication logs can contain useful signals, but reviewing them manually is time-consuming. This project demonstrates how to validate log records, apply transparent time-window rules, and produce concise investigation leads with Python's standard library.

Objectives:

- Parse authentication records safely and report malformed lines without stopping analysis.
- Detect repeated failed logins, potential brute-force activity, successful logins after repeated failures, and broad username targeting.
- Produce reproducible, spreadsheet-friendly reports and an understandable CLI summary.

## Features

- Python 3.10+; no third-party runtime dependencies.
- Timestamp, status, and IP validation (including IPv4 and IPv6).
- Rolling per-source-IP detection windows and configurable thresholds in `DetectionConfig`.
- JSON and CSV reports, including malformed-line details and recommended actions.
- Synthetic authentication fixtures use documentation/private network addresses only.

## Technologies

Python, `re`, `datetime`, `collections`, `ipaddress`, `json`, `csv`, `argparse`, `logging`, `pathlib`, and `unittest`.

## Architecture and folder structure

- `src/log_parser.py`: validated event and malformed-line parsing.
- `src/detector.py`: independent detection rules and alert models.
- `src/reporter.py`: report summary and JSON/CSV serialization.
- `src/utils.py`: shared timestamp formatting.
- `src/main.py`: CLI orchestration and user-facing output.
- `data/`: synthetic valid and malformed authentication samples.
- `tests/`: standard-library unit tests.

```text
sentinel-soc-lite/
├── data/
│   ├── auth.log
│   └── sample_malformed.log
├── reports/
│   └── .gitkeep
├── src/
│   ├── __init__.py
│   ├── detector.py
│   ├── log_parser.py
│   ├── main.py
│   ├── reporter.py
│   └── utils.py
├── tests/
│   ├── __init__.py
│   ├── test_detector.py
│   ├── test_parser.py
│   └── test_reporter.py
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

## Detection rules

| Rule | Condition | Severity |
|---|---|---|
| Brute-force pattern | At least 5 failed logins from one IP within 5 minutes | HIGH |
| Successful login after failures | At least 5 recent failures from one IP, followed by a success from that IP | CRITICAL |
| Multiple usernames targeted | At least 5 distinct usernames from one IP within 10 minutes | HIGH |
| Repeated failed logins | 3 or 4 failures from one IP within 5 minutes | MEDIUM |

Overlapping lower-severity failure alerts are superseded by a critical success-after-failures alert for the same source and incident window. Alert language describes suspicious activity requiring investigation; it does not assert malicious intent.

## Installation (Windows)

Install Python 3.10 or later and ensure the Python launcher (`py`) is available. From the project directory, create and activate a virtual environment:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

There are no required third-party packages. `requirements.txt` is provided for conventional tooling; no package installation is necessary.

## Usage

Analyze the bundled sample (reports default to `reports/`):

```powershell
py -m src.main --input data/auth.log
```

Choose another output directory or include malformed-line diagnostics:

```powershell
py -m src.main --input data/auth.log --output reports
py -m src.main --input data/sample_malformed.log --verbose
py -m src.main --help
```

The CLI exits with status 2 for input/output or permission errors, status 1 for unexpected analysis failures, and status 0 on success. Malformed individual records are counted and skipped without preventing valid records from being analyzed.

Example terminal summary (counts are calculated from the selected input):

```text
[+] Analysis completed successfully

## LOG STATISTICS
Total log entries       : 30
Valid entries           : 30
Malformed entries       : 0
Successful logins       : 9
Failed logins           : 21

## THREAT DETECTION SUMMARY
Total alerts            : 5
CRITICAL                : 1
HIGH                    : 2
MEDIUM                  : 2

## REPORTS
JSON Report             : reports\report.json
CSV Report              : reports\report.csv
```

## Reports

`reports/report.json` contains generation time, input path, total/valid/malformed counts, success/failure counts, per-severity alert totals, malformed line details, alert objects, and recommended actions. Each alert contains an ID, rule type, source IP, affected usernames, attempt count, timestamp, severity, description, and recommended action.

`reports/report.csv` has the columns `timestamp,alert_id,alert_type,source_ip,username,attempts,severity,description,recommended_action`. CSV headers are still written when there are no alerts. Generated reports are ignored by Git by default.

## Tests

Run the complete test suite from the project directory:

```powershell
py -m unittest discover -s tests -v
```

## Limitations

- Rules are simple thresholds and can produce false positives; tune them for the environment.
- Input is limited to the documented single-line event format.
- No live log collection, threat-intelligence enrichment, persistent storage, dashboard, or automated response is included.
- Timestamps are interpreted as naive local log times; no timezone normalization is performed.

## Future improvements

Potential extensions include additional log formats, timezone-aware parsing, configurable rule settings, alert suppression state, and integration tests using controlled fixtures.

## Project information

Sentinel SOC Lite is an educational example for learning Python log parsing and defensive detection concepts. The sample data is synthetic. No personal author details or professional experience are implied.
