import csv
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from src.detector import Alert
from src.log_parser import AuthEvent, MalformedLine
from src.reporter import CSV_COLUMNS, build_report, write_reports


class ReporterTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            AuthEvent(datetime(2026, 11, 5, 9), "alice", "192.0.2.1", "SUCCESS"),
            AuthEvent(datetime(2026, 11, 5, 9, 1), "bob", "192.0.2.1", "FAILED"),
        ]
        self.alerts = [
            Alert(
                "ALT-1",
                "REPEATED_FAILURES",
                "192.0.2.1",
                ("bob",),
                3,
                datetime(2026, 11, 5, 9, 2),
                "MEDIUM",
                "Repeated failures require investigation.",
                "Review authentication activity.",
            )
        ]

    def test_report_contains_correct_summary_and_alert(self):
        report = build_report("data/auth.log", self.events, [], self.alerts)
        self.assertEqual(report["total_log_entries"], 2)
        self.assertEqual(report["successful_logins"], 1)
        self.assertEqual(report["failed_logins"], 1)
        self.assertEqual(report["medium_alerts"], 1)
        self.assertEqual(report["alerts"][0]["alert_id"], "ALT-1")

    def test_writes_json_and_csv_reports(self):
        report = build_report("auth.log", self.events, [], self.alerts)
        with tempfile.TemporaryDirectory() as directory:
            json_path, csv_path = write_reports(directory, report, self.alerts)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["total_alerts"], 1)
            with csv_path.open(encoding="utf-8-sig", newline="") as csv_file:
                rows = list(csv.DictReader(csv_file))
            self.assertEqual(tuple(rows[0].keys()), CSV_COLUMNS)
            self.assertEqual(rows[0]["username"], "bob")
            self.assertEqual(rows[0]["severity"], "MEDIUM")

    def test_empty_alerts_still_write_reports_with_csv_header(self):
        report = build_report("empty.log", [], [], [])
        with tempfile.TemporaryDirectory() as directory:
            json_path, csv_path = write_reports(directory, report, [])
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            with csv_path.open(encoding="utf-8-sig", newline="") as csv_file:
                rows = list(csv.reader(csv_file))
            self.assertEqual(payload["total_alerts"], 0)
            self.assertEqual(rows, [list(CSV_COLUMNS)])

    def test_report_includes_malformed_line_details_and_creates_directory(self):
        malformed = [MalformedLine(2, "bad", "Invalid format")]
        report = build_report("auth.log", self.events, malformed, self.alerts)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "reports"
            json_path, _ = write_reports(output, report, self.alerts)
            self.assertTrue(json_path.exists())
            self.assertEqual(report["malformed_lines"][0]["line_number"], 2)
            self.assertEqual(report["total_log_entries"], 3)


if __name__ == "__main__":
    unittest.main()
