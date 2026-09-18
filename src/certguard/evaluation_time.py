"""Pinned evaluation instants for reproducible verdicts."""

from __future__ import annotations

from datetime import UTC, date, datetime


def resolve_evaluated_at(value: datetime | date | str | None) -> datetime:
    """Return an aware UTC instant.

    ``YYYY-MM-DD`` is midnight UTC on that date. A full ISO-8601 value is
    honoured as written. ``None`` means "now", which is *not* reproducible.
    """
    if value is None:
        return datetime.now(UTC)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    text = str(value).strip()
    if len(text) == 10:
        parsed_date = date.fromisoformat(text)
        return datetime(
            parsed_date.year, parsed_date.month, parsed_date.day, tzinfo=UTC
        )
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
