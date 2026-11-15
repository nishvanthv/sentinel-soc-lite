"""JSON and spreadsheet-safe CSV reporting."""
from __future__ import annotations
import csv,json
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
from typing import Iterable
from src.detector import Alert
from src.log_parser import AuthEvent,MalformedLine
CSV_COLUMNS=("timestamp","alert_id","alert_type","source_ip","username","attempts","severity","description","recommended_action")
def _safe_csv(value):
    if not isinstance(value,str): return value
    if value.lstrip(" \t\r\n").startswith(("=","+","-","@")): return "'"+value
    return value
def build_report(input_filename: str|Path,events: Iterable[AuthEvent],malformed: Iterable[MalformedLine],alerts: Iterable[Alert]):
    es,ms,als=list(events),list(malformed),list(alerts); counts=Counter(a.severity for a in als)
    return {"generated_at":datetime.now(timezone.utc).isoformat(timespec="seconds"),"timestamp_policy":"Legacy timestamps without offsets are interpreted as UTC",
    "input_file":str(input_filename),"total_log_entries":len(es)+len(ms),"valid_log_entries":len(es),"malformed_log_entries":len(ms),
    "successful_logins":sum(e.status=="SUCCESS" for e in es),"failed_logins":sum(e.status=="FAILED" for e in es),
    "total_alerts":len(als),"critical_alerts":counts["CRITICAL"],"high_alerts":counts["HIGH"],"medium_alerts":counts["MEDIUM"],
    "malformed_lines":[{"line_number":m.line_number,"content":m.content,"error":m.error} for m in ms],
    "alerts":[a.to_dict() for a in als],"recommended_actions":[{"alert_id":a.alert_id,"action":a.recommended_action} for a in als]}
def write_reports(output_directory: str|Path,report: dict[str,object],alerts: Iterable[Alert]):
    out=Path(output_directory); out.mkdir(parents=True,exist_ok=True); jp=out/"report.json"; cp=out/"report.csv"
    jp.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    with cp.open("w",encoding="utf-8-sig",newline="") as stream:
        writer=csv.DictWriter(stream,fieldnames=CSV_COLUMNS); writer.writeheader()
        for a in alerts:
            row={"timestamp":a.timestamp.isoformat(),"alert_id":a.alert_id,"alert_type":a.alert_type,"source_ip":a.source_ip,
            "username":", ".join(a.affected_usernames),"attempts":a.attempts,"severity":a.severity,"description":a.description,"recommended_action":a.recommended_action}
            writer.writerow({k:_safe_csv(v) for k,v in row.items()})
    return jp,cp
