"""Parse and validate Sentinel SOC Lite authentication log entries."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"username=(?P<username>\S+) ip=(?P<ip>\S+) status=(?P<status>\S+)$"
)
_VALID_STATUSES = {"SUCCESS", "FAILED"}


@dataclass(frozen=True)
class AuthEvent:
    """A validated authentication event."""

    timestamp: datetime
    username: str
    ip: str
    status: str


@dataclass(frozen=True)
class MalformedLine:
    """A log line that could not be parsed, with its source location."""

    line_number: int
    content: str
    error: str


def parse_lines(lines: Iterable[str]) -> tuple[list[AuthEvent], list[MalformedLine]]:
    """Parse log lines, preserving valid entries when other lines are invalid."""
    events: list[AuthEvent] = []
    malformed: list[MalformedLine] = []

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        match = _LOG_PATTERN.fullmatch(line)
        if match is None:
            malformed.append(
                MalformedLine(line_number, line, "Line does not match the expected format")
            )
            continue

        values = match.groupdict()
        try:
            timestamp = datetime.strptime(values["timestamp"], "%Y-%m-%d %H:%M:%S")
        except ValueError as exc:
            malformed.append(MalformedLine(line_number, line, f"Invalid timestamp: {exc}"))
            continue

        try:
            ip = str(ipaddress.ip_address(values["ip"]))
        except ValueError as exc:
            malformed.append(MalformedLine(line_number, line, f"Invalid IP address: {exc}"))
            continue

        status = values["status"].upper()
        if status not in _VALID_STATUSES:
            malformed.append(
                MalformedLine(line_number, line, f"Unsupported login status: {values['status']}")
            )
            continue

        events.append(
            AuthEvent(
                timestamp=timestamp,
                username=values["username"],
                ip=ip,
                status=status,
            )
        )

    return events, malformed


def parse_log(path: str | Path) -> tuple[list[AuthEvent], list[MalformedLine]]:
    """Read and parse a UTF-8 authentication log file."""
    with Path(path).open("r", encoding="utf-8") as log_file:
        return parse_lines(log_file)
