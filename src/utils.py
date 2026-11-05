"""Shared formatting helpers for Sentinel SOC Lite."""

from datetime import datetime


def format_timestamp(value: datetime) -> str:
    """Format timestamps consistently in reports."""
    return value.isoformat(sep=" ")
