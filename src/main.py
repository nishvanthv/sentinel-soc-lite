"""Command-line entry point for Sentinel SOC Lite."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from src.detector import detect_alerts
from src.log_parser import parse_log
from src.reporter import build_report, write_reports

LOGGER = logging.getLogger("sentinel_soc_lite")


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious activity."
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to an authentication log file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports"),
        help="Directory for JSON and CSV reports (default: reports)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Log malformed lines and diagnostic details",
    )
    return parser


def run_analysis(input_path: Path, output_path: Path) -> tuple[dict[str, object], Path, Path]:
    """Analyze the given log and write both reports."""
    events, malformed = parse_log(input_path)
    alerts = detect_alerts(events)
    report = build_report(input_path, events, malformed, alerts)
    json_path, csv_path = write_reports(output_path, report, alerts)
    return report, json_path, csv_path


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = create_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    try:
        report, json_path, csv_path = run_analysis(args.input, args.output)
    except FileNotFoundError:
        LOGGER.error("Input file not found: %s", args.input)
        return 2
    except IsADirectoryError:
        LOGGER.error("Input path is a directory, not a file: %s", args.input)
        return 2
    except PermissionError as exc:
        LOGGER.error("Permission denied: %s", exc)
        return 2
    except (OSError, UnicodeError) as exc:
        LOGGER.error("Could not read input or write reports: %s", exc)
        return 2
    except Exception:
        LOGGER.exception("Unexpected analysis failure")
        return 1

    if args.verbose:
        for item in report["malformed_lines"]:
            LOGGER.warning("Line %s: %s", item["line_number"], item["error"])

    print("[+] Analysis completed successfully")
    print()
    print("## LOG STATISTICS")
    print(f"Total log entries       : {report['total_log_entries']}")
    print(f"Valid entries           : {report['valid_log_entries']}")
    print(f"Malformed entries       : {report['malformed_log_entries']}")
    print(f"Successful logins       : {report['successful_logins']}")
    print(f"Failed logins           : {report['failed_logins']}")
    print()
    print("## THREAT DETECTION SUMMARY")
    print(f"Total alerts            : {report['total_alerts']}")
    print(f"CRITICAL                : {report['critical_alerts']}")
    print(f"HIGH                    : {report['high_alerts']}")
    print(f"MEDIUM                  : {report['medium_alerts']}")
    print()
    print("## REPORTS")
    print(f"JSON Report             : {json_path}")
    print(f"CSV Report              : {csv_path}")
    print()
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
