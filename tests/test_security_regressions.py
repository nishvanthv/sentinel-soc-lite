import unittest
from datetime import datetime,timezone,timedelta
from src.log_parser import parse_lines,MAX_LINE_LENGTH,AuthEvent
from src.reporter import _safe_csv
from src.engine import detect_password_spraying
class SecurityRegressionTests(unittest.TestCase):
 def test_legacy_timestamps_are_utc(self):
  events,bad=parse_lines(["2026-11-05 09:00:00 username=a ip=192.0.2.1 status=SUCCESS"])
  self.assertFalse(bad); self.assertEqual(events[0].timestamp.utcoffset(),timedelta(0))
 def test_oversized_line_rejected(self):
  events,bad=parse_lines(["x"*(MAX_LINE_LENGTH+1)])
  self.assertFalse(events); self.assertIn("maximum",bad[0].error)
 def test_csv_formula_prefix_neutralized(self):
  self.assertEqual(_safe_csv("=1+1"),"'=1+1"); self.assertEqual(_safe_csv("ordinary"),"ordinary")
 def test_spray_uses_failed_events_only(self):
  base=datetime(2026,11,5,tzinfo=timezone.utc)
  events=[AuthEvent(base+timedelta(seconds=i),f"u{i}","192.0.2.9","FAILED") for i in range(5)]
  events.append(AuthEvent(base,"legitimate","192.0.2.9","SUCCESS"))
  self.assertEqual(len(detect_password_spraying(events)),1)
if __name__=="__main__": unittest.main()
