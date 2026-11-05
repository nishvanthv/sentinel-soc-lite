"""Generate JSON and CSV reports for Sentinel SOC Lite analyses."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Iterable

from src.detector import Alert
from src.log_parser import AuthEvent, MalformedLine
from src.utils import format_timestamp

CSV_COLUMNS = (
    "timestamp",
    "alert_id",
    "alert_type",
    "source_ip",
    "username",
    "attempts",
    "severity",
    "description",
    "recommended_action",
)


def build_report(
    input_filename: str | Path,
    events: Iterable[AuthEvent],
    malformed: Iterable[MalformedLine],
    alerts: Iterable[Alert],
) -> dict[str, object]:
    """Build the report summary and alert details."""
    event_list = list(events)
    malformed_list = list(malformed)
    alert_list = list(alerts)
    severity_counts = Counter(alert.severity for alert in alert_list)
    return {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "input_file": str(input_filename),
        "total_log_entries": len(event_list) + len(malformed_list),
        "valid_log_entries": len(event_list),
        "malformed_log_entries": len(malformed_list),
        "successful_logins": sum(event.status == "SUCCESS" for event in event_list),
        "failed_logins": sum(event.status == "FAILED" for event in event_list),
        "total_alerts": len(alert_list),
        "critical_alerts": severity_counts["CRITICAL"],
        "high_alerts": severity_counts["HIGH"],
        "medium_alerts": severity_counts["MEDIUM"],
        "malformed_lines": [
            {
                "line_number": line.line_number,
                "content": line.content,
                "error": line.error,
            }
            for line in malformed_list
        ],
        "alerts": [alert.to_dict() for alert in alert_list],
        "recommended_actions": [
            {"alert_id": alert.alert_id, "action": alert.recommended_action}
            for alert in alert_list
        ],
    }


def write_reports(
    output_directory: str | Path,
    report: dict[str, object],
    alerts: Iterable[Alert],
) -> tuple[Path, Path]:
    """Write readable JSON and spreadsheet-friendly CSV reports."""
    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)
    json_path = output_path / "report.json"
    csv_path = output_path / "report.csv"

    with json_path.open("w", encoding="utf-8", newline="\n") as json_file:
        json.dump(report, json_file, indent=2, ensure_ascii=False)
        json_file.write("\n")

    with csv_path.open("w", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(
                {
                    "timestamp": format_timestamp(alert.timestamp),
                    "alert_id": alert.alert_id,
                    "alert_type": alert.alert_type,
                    "source_ip": alert.source_ip,
                    "username": ", ".join(alert.affected_usernames),
                    "attempts": alert.attempts,
                    "severity": alert.severity,
                    "description": alert.description,
                    "recommended_action": alert.recommended_action,
                }
            )
    return json_path, csv_path
