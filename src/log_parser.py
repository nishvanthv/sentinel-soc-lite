"""Bounded parser for the legacy authentication log format."""
from __future__ import annotations
import ipaddress, re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
MAX_LINE_LENGTH=8192
MAX_USERNAME_LENGTH=128
PATTERN=re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) username=(?P<username>\S+) ip=(?P<ip>\S+) status=(?P<status>\S+)$")
@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    username: str
    ip: str
    status: str
@dataclass(frozen=True)
class MalformedLine:
    line_number: int
    content: str
    error: str
def parse_lines(lines: Iterable[str]):
    events=[]; malformed=[]
    for number,raw in enumerate(lines,1):
        if len(raw)>MAX_LINE_LENGTH:
            malformed.append(MalformedLine(number,raw[:256],"Line exceeds maximum length")); continue
        line=raw.strip()
        if not line: continue
        match=PATTERN.fullmatch(line)
        if not match:
            malformed.append(MalformedLine(number,line[:256],"Line does not match expected format")); continue
        values=match.groupdict()
        if len(values["username"])>MAX_USERNAME_LENGTH:
            malformed.append(MalformedLine(number,line[:256],"Username exceeds maximum length")); continue
        try:
            stamp=datetime.strptime(values["timestamp"],"%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            ip=str(ipaddress.ip_address(values["ip"]))
        except ValueError as exc:
            malformed.append(MalformedLine(number,line[:256],str(exc))); continue
        status=values["status"].upper()
        if status not in {"SUCCESS","FAILED"}:
            malformed.append(MalformedLine(number,line[:256],f"Unsupported status: {values['status']}")); continue
        events.append(AuthEvent(stamp,values["username"],ip,status))
    return events,malformed
def parse_log(path: str | Path):
    with Path(path).open("r",encoding="utf-8",errors="replace") as stream:
        return parse_lines(stream)
