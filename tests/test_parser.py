import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from src.log_parser import parse_lines, parse_log


class LogParserTests(unittest.TestCase):
    def test_parses_valid_record_and_normalizes_status(self):
        events, malformed = parse_lines(
            ["2026-11-05 09:00:00 username=admin ip=192.168.1.10 status=failed"]
        )
        self.assertEqual(malformed, [])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].timestamp, datetime(2026, 11, 5, 9, tzinfo=timezone.utc))
        self.assertEqual(events[0].ip, "192.168.1.10")
        self.assertEqual(events[0].username, "admin")
        self.assertEqual(events[0].status, "FAILED")

    def test_rejects_invalid_ip_and_reports_line_number(self):
        events, malformed = parse_lines(
            ["2026-11-05 09:00:00 username=admin ip=999.1.1.1 status=FAILED"]
        )
        self.assertEqual(events, [])
        self.assertEqual(malformed[0].line_number, 1)
        self.assertIn("Invalid IP address", malformed[0].error)

    def test_rejects_invalid_timestamp_and_status(self):
        _, malformed = parse_lines(
            [
                "2026-02-30 09:00:00 username=admin ip=192.0.2.1 status=FAILED",
                "2026-11-05 09:00:00 username=admin ip=192.0.2.1 status=UNKNOWN",
            ]
        )
        self.assertIn("Invalid timestamp", malformed[0].error)
        self.assertIn("Unsupported login status", malformed[1].error)

    def test_malformed_line_does_not_discard_valid_lines(self):
        events, malformed = parse_lines(
            [
                "2026-11-05 09:00:00 username=admin ip=192.0.2.1 status=SUCCESS",
                "bad line",
                "2026-11-05 09:01:00 username=user ip=198.51.100.2 status=FAILED",
            ]
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(len(malformed), 1)
        self.assertEqual(malformed[0].line_number, 2)

    def test_empty_lines_input(self):
        self.assertEqual(parse_lines([]), ([], []))
        self.assertEqual(parse_lines(["", "  "]), ([], []))

    def test_reads_empty_log_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.log"
            path.write_text("", encoding="utf-8")
            self.assertEqual(parse_log(path), ([], []))


if __name__ == "__main__":
    unittest.main()
