import unittest
from datetime import datetime, timedelta

from src.detector import (
    detect_alerts,
    detect_brute_force,
    detect_multiple_usernames,
    detect_repeated_failures,
    detect_success_after_failures,
)
from src.log_parser import AuthEvent


BASE = datetime(2026, 11, 5, 9, 0)


def event(minutes, seconds, username="user", ip="192.0.2.1", status="FAILED"):
    return AuthEvent(BASE + timedelta(minutes=minutes, seconds=seconds), username, ip, status)


class DetectorTests(unittest.TestCase):
    def test_five_failures_trigger_high_brute_force(self):
        alerts = detect_brute_force([event(0, i * 30) for i in range(5)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")
        self.assertEqual(alerts[0].attempts, 5)

    def test_four_failures_do_not_trigger_brute_force(self):
        self.assertEqual(len(detect_brute_force([event(0, i * 30) for i in range(4)])), 0)

    def test_three_failures_trigger_medium_alert(self):
        alerts = detect_repeated_failures([event(0, i * 30) for i in range(3)])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "MEDIUM")

    def test_events_outside_five_minute_window_are_not_combined(self):
        events = [event(0, 0), event(6, 0), event(12, 0), event(18, 0), event(24, 0)]
        self.assertEqual(detect_brute_force(events), [])

    def test_success_after_five_recent_failures_is_critical(self):
        events = [event(0, i * 30) for i in range(5)]
        events.append(event(2, 45, status="SUCCESS"))
        alerts = detect_success_after_failures(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "CRITICAL")
        self.assertEqual(alerts[0].alert_type, "SUCCESS_AFTER_FAILURES")

    def test_success_before_qualifying_failures_does_not_trigger_critical(self):
        events = [event(0, 0, status="SUCCESS")] + [event(1, i * 30) for i in range(5)]
        self.assertEqual(detect_success_after_failures(events), [])

    def test_multiple_usernames_from_one_ip_trigger_high_alert(self):
        events = [
            event(0, index * 30, username=name)
            for index, name in enumerate(("a", "b", "c", "d", "e"))
        ]
        alerts = detect_multiple_usernames(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")
        self.assertEqual(len(alerts[0].affected_usernames), 5)

    def test_different_ips_are_analyzed_independently(self):
        events = [event(0, index * 30, ip="192.0.2.1") for index in range(3)]
        events.extend(event(0, index * 30, ip="198.51.100.2") for index in range(2))
        self.assertEqual(detect_repeated_failures(events)[0].source_ip, "192.0.2.1")

    def test_normal_successes_do_not_create_alerts(self):
        self.assertEqual(
            detect_alerts([event(0, 0, status="SUCCESS"), event(1, 0, status="SUCCESS")]),
            [],
        )

    def test_duplicate_alerts_are_suppressed_for_same_incident(self):
        events = [event(0, index * 30) for index in range(7)]
        alerts = detect_alerts(events)
        brute = [alert for alert in alerts if alert.alert_type == "BRUTE_FORCE"]
        self.assertEqual(len(brute), 1)

    def test_critical_alert_supersedes_lower_severity_same_incident(self):
        events = [event(0, index * 30) for index in range(5)]
        events.append(event(2, 45, status="SUCCESS"))
        alerts = detect_alerts(events)
        self.assertEqual([alert.severity for alert in alerts], ["CRITICAL"])

    def test_brute_force_alert_supersedes_medium_same_incident(self):
        events = [event(0, index * 30) for index in range(5)]
        alerts = detect_alerts(events)
        self.assertEqual([alert.alert_type for alert in alerts], ["BRUTE_FORCE"])

    def test_repeated_attempts_after_separate_window_can_alert_again(self):
        events = [event(0, index * 20) for index in range(5)]
        events.extend(event(10, index * 20) for index in range(5))
        self.assertEqual(len(detect_brute_force(events)), 2)


if __name__ == "__main__":
    unittest.main()
