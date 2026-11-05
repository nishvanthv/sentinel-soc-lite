"""Rule-based detection for suspicious authentication patterns."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from typing import Iterable

from src.log_parser import AuthEvent
from src.utils import format_timestamp


@dataclass(frozen=True)
class DetectionConfig:
    """Thresholds and rolling windows used by the detection rules."""

    brute_force_threshold: int = 5
    repeated_failure_threshold: int = 3
    targeted_username_threshold: int = 5
    failure_window: timedelta = timedelta(minutes=5)
    username_window: timedelta = timedelta(minutes=10)


@dataclass(frozen=True)
class Alert:
    """A suspicious-activity alert produced by a detection rule."""

    alert_id: str
    alert_type: str
    source_ip: str
    affected_usernames: tuple[str, ...]
    attempts: int
    timestamp: datetime
    severity: str
    description: str
    recommended_action: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "source_ip": self.source_ip,
            "affected_usernames": list(self.affected_usernames),
            "attempts": self.attempts,
            "timestamp": format_timestamp(self.timestamp),
            "severity": self.severity,
            "description": self.description,
            "recommended_action": self.recommended_action,
        }


def _new_alert(
    *,
    alert_type: str,
    source_ip: str,
    usernames: Iterable[str],
    attempts: int,
    timestamp: datetime,
    severity: str,
    description: str,
    recommended_action: str,
) -> Alert:
    ordered_usernames = tuple(sorted(set(usernames)))
    identity = (
        f"{alert_type}|{source_ip}|{timestamp.isoformat()}|"
        f"{','.join(ordered_usernames)}"
    )
    alert_id = f"ALT-{sha256(identity.encode('utf-8')).hexdigest()[:16].upper()}"
    return Alert(
        alert_id=alert_id,
        alert_type=alert_type,
        source_ip=source_ip,
        affected_usernames=ordered_usernames,
        attempts=attempts,
        timestamp=timestamp,
        severity=severity,
        description=description,
        recommended_action=recommended_action,
    )


def detect_brute_force(
    events: Iterable[AuthEvent], config: DetectionConfig | None = None
) -> list[Alert]:
    """Detect high-volume failed logins using a rolling per-IP window."""
    settings = config or DetectionConfig()
    failed_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.status == "FAILED":
            failed_by_ip[event.ip].append(event)

    alerts: list[Alert] = []
    for ip, failures in failed_by_ip.items():
        failures.sort(key=lambda event: event.timestamp)
        left = 0
        last_emitted: datetime | None = None
        for right, event in enumerate(failures):
            while event.timestamp - failures[left].timestamp > settings.failure_window:
                left += 1
            count = right - left + 1
            if count < settings.brute_force_threshold:
                continue
            if last_emitted is not None and event.timestamp - last_emitted <= settings.failure_window:
                continue
            window_events = failures[left : right + 1]
            alerts.append(
                _new_alert(
                    alert_type="BRUTE_FORCE",
                    source_ip=ip,
                    usernames=(item.username for item in window_events),
                    attempts=count,
                    timestamp=event.timestamp,
                    severity="HIGH",
                    description=(
                        f"{count} failed login attempts from {ip} occurred within "
                        f"{settings.failure_window} and require investigation."
                    ),
                    recommended_action=(
                        "Review authentication records and account activity; apply "
                        "appropriate rate limits or access controls if warranted."
                    ),
                )
            )
            last_emitted = event.timestamp
    return alerts


def detect_success_after_failures(
    events: Iterable[AuthEvent], config: DetectionConfig | None = None
) -> list[Alert]:
    """Detect a successful login after enough recent failures from the same IP."""
    settings = config or DetectionConfig()
    ordered = sorted(events, key=lambda event: event.timestamp)
    failed_by_ip: dict[str, deque[AuthEvent]] = defaultdict(deque)
    alerts: list[Alert] = []
    last_emitted: dict[str, datetime] = {}

    for event in ordered:
        recent_failures = failed_by_ip[event.ip]
        while (
            recent_failures
            and event.timestamp - recent_failures[0].timestamp > settings.failure_window
        ):
            recent_failures.popleft()

        if event.status == "SUCCESS":
            if len(recent_failures) >= settings.brute_force_threshold:
                previous = last_emitted.get(event.ip)
                if previous is None or event.timestamp - previous > settings.failure_window:
                    failures = list(recent_failures)
                    alerts.append(
                        _new_alert(
                            alert_type="SUCCESS_AFTER_FAILURES",
                            source_ip=event.ip,
                            usernames=[item.username for item in failures] + [event.username],
                            attempts=len(failures) + 1,
                            timestamp=event.timestamp,
                            severity="CRITICAL",
                            description=(
                                f"A successful login from {event.ip} followed "
                                f"{len(failures)} failed attempts within "
                                f"{settings.failure_window}; investigate the activity."
                            ),
                            recommended_action=(
                                "Promptly verify the successful login with the account "
                                "owner and review the source IP and affected accounts."
                            ),
                        )
                    )
                    last_emitted[event.ip] = event.timestamp
        elif event.status == "FAILED":
            recent_failures.append(event)

    return alerts


def detect_multiple_usernames(
    events: Iterable[AuthEvent], config: DetectionConfig | None = None
) -> list[Alert]:
    """Detect a single IP attempting authentication for many usernames."""
    settings = config or DetectionConfig()
    events_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        events_by_ip[event.ip].append(event)

    alerts: list[Alert] = []
    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda event: event.timestamp)
        left = 0
        last_emitted: datetime | None = None
        for right, event in enumerate(ip_events):
            while event.timestamp - ip_events[left].timestamp > settings.username_window:
                left += 1
            window_events = ip_events[left : right + 1]
            usernames = {item.username for item in window_events}
            if len(usernames) < settings.targeted_username_threshold:
                continue
            if last_emitted is not None and event.timestamp - last_emitted <= settings.username_window:
                continue
            alerts.append(
                _new_alert(
                    alert_type="MULTIPLE_USERNAMES",
                    source_ip=ip,
                    usernames=usernames,
                    attempts=len(window_events),
                    timestamp=event.timestamp,
                    severity="HIGH",
                    description=(
                        f"{len(usernames)} distinct usernames were targeted from {ip} "
                        f"within {settings.username_window}; investigate the activity."
                    ),
                    recommended_action=(
                        "Review the targeted accounts and authentication patterns; "
                        "consider rate limits and additional monitoring."
                    ),
                )
            )
            last_emitted = event.timestamp
    return alerts


def detect_repeated_failures(
    events: Iterable[AuthEvent], config: DetectionConfig | None = None
) -> list[Alert]:
    """Detect three or more but fewer than the brute-force threshold failures."""
    settings = config or DetectionConfig()
    failed_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.status == "FAILED":
            failed_by_ip[event.ip].append(event)

    alerts: list[Alert] = []
    for ip, failures in failed_by_ip.items():
        failures.sort(key=lambda event: event.timestamp)
        left = 0
        last_emitted: datetime | None = None
        for right, event in enumerate(failures):
            while event.timestamp - failures[left].timestamp > settings.failure_window:
                left += 1
            count = right - left + 1
            if not settings.repeated_failure_threshold <= count < settings.brute_force_threshold:
                continue
            if last_emitted is not None and event.timestamp - last_emitted <= settings.failure_window:
                continue
            window_events = failures[left : right + 1]
            alerts.append(
                _new_alert(
                    alert_type="REPEATED_FAILURES",
                    source_ip=ip,
                    usernames=(item.username for item in window_events),
                    attempts=count,
                    timestamp=event.timestamp,
                    severity="MEDIUM",
                    description=(
                        f"{count} failed login attempts from {ip} occurred within "
                        f"{settings.failure_window}; investigate the activity."
                    ),
                    recommended_action=(
                        "Review the account and source activity; monitor for additional "
                        "failures or escalation."
                    ),
                )
            )
            last_emitted = event.timestamp
    return alerts


def detect_alerts(
    events: Iterable[AuthEvent], config: DetectionConfig | None = None
) -> list[Alert]:
    """Run all detection rules and suppress lower-severity duplicates."""
    settings = config or DetectionConfig()
    event_list = list(events)
    critical = detect_success_after_failures(event_list, settings)
    brute_force = detect_brute_force(event_list, settings)
    repeated = detect_repeated_failures(event_list, settings)
    targeted = detect_multiple_usernames(event_list, settings)

    # A critical follow-on success supersedes the brute-force/repeated alert for
    # the same source in the same failure window.
    alerts = []
    for alert in brute_force + repeated:
        if any(
            critical_alert.source_ip == alert.source_ip
            and timedelta(0) <= critical_alert.timestamp - alert.timestamp
            <= settings.failure_window
            for critical_alert in critical
        ):
            continue
        if alert.alert_type == "REPEATED_FAILURES" and any(
            brute_alert.source_ip == alert.source_ip
            and timedelta(0) <= brute_alert.timestamp - alert.timestamp
            <= settings.failure_window
            for brute_alert in brute_force
        ):
            continue
        alerts.append(alert)
    alerts.extend(critical)
    alerts.extend(targeted)
    alerts.sort(key=lambda alert: (alert.timestamp, alert.source_ip, alert.alert_type))

    unique: dict[tuple[str, str, datetime], Alert] = {}
    for alert in alerts:
        unique.setdefault((alert.alert_type, alert.source_ip, alert.timestamp), alert)
    return list(unique.values())
