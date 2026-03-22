"""Time utilities for EchoLake."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple, Union
import re
from dateutil import parser as date_parser


def parse_timestamp(
    value: Union[str, int, float, datetime],
    format: str = "iso8601"
) -> datetime:
    """
    Parse timestamp from various formats.

    Args:
        value: Timestamp value to parse
        format: Expected format (iso8601, auto, unix_seconds, unix_millis, rfc3339, or strftime pattern)

    Returns:
        Parsed datetime object (timezone-aware)

    Raises:
        ValueError: If timestamp cannot be parsed
    """
    if isinstance(value, datetime):
        # Already a datetime, ensure it's timezone-aware
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    if format == "auto":
        # Use dateutil.parser.parse for flexible parsing
        if isinstance(value, str):
            dt = date_parser.parse(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        raise ValueError(f"Expected string for auto format, got {type(value)}")

    elif format == "iso8601" or format == "rfc3339":
        if isinstance(value, str):
            dt = date_parser.isoparse(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        raise ValueError(f"Expected string for {format}, got {type(value)}")

    elif format == "unix_seconds":
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        elif isinstance(value, str):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        raise ValueError(f"Expected number for unix_seconds, got {type(value)}")

    elif format == "unix_millis":
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value / 1000.0, tz=timezone.utc)
        elif isinstance(value, str):
            return datetime.fromtimestamp(float(value) / 1000.0, tz=timezone.utc)
        raise ValueError(f"Expected number for unix_millis, got {type(value)}")

    else:
        # Assume it's a strftime pattern
        if isinstance(value, str):
            dt = datetime.strptime(value, format)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        raise ValueError(f"Expected string for custom format, got {type(value)}")


def format_timestamp(dt: datetime, format: str = "iso8601") -> str:
    """
    Format datetime to string.

    Args:
        dt: Datetime to format
        format: Target format (iso8601, unix_seconds, unix_millis, or strftime pattern)

    Returns:
        Formatted timestamp string
    """
    if format == "iso8601":
        return dt.isoformat()

    elif format == "unix_seconds":
        return str(int(dt.timestamp()))

    elif format == "unix_millis":
        return str(int(dt.timestamp() * 1000))

    else:
        # Assume it's a strftime pattern
        return dt.strftime(format)


def now_utc() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


def parse_time_reference(value: str) -> datetime:
    """
    Parse time reference like 'now', 'earliest', or ISO8601 timestamp.

    Args:
        value: Time reference string

    Returns:
        Parsed datetime

    Raises:
        ValueError: If value cannot be parsed
    """
    if value.lower() == "now":
        return now_utc()

    # Try to parse as ISO8601
    try:
        return parse_timestamp(value, "iso8601")
    except Exception as e:
        raise ValueError(f"Invalid time reference: {value}. Expected 'now' or ISO8601 timestamp") from e


@dataclass
class TimeExpression:
    """Represents a time expression that may need event data to resolve."""
    base: str  # "now", "earliest", "latest", or ISO8601 timestamp
    offsets: List[Tuple[str, int]]  # [("+", 3600), ("-", 86400)] for +1h-1d

    def resolve(
        self,
        earliest: Optional[datetime] = None,
        latest: Optional[datetime] = None
    ) -> datetime:
        """
        Resolve expression to actual datetime.

        Args:
            earliest: Earliest timestamp from events (required for 'earliest' base)
            latest: Latest timestamp from events (required for 'latest' base)

        Returns:
            Resolved datetime

        Raises:
            ValueError: If base requires event data that wasn't provided
        """
        if self.base == "now":
            result = datetime.now(timezone.utc)
        elif self.base == "earliest":
            if earliest is None:
                raise ValueError("Cannot resolve 'earliest' without event data")
            result = earliest
        elif self.base == "latest":
            if latest is None:
                raise ValueError("Cannot resolve 'latest' without event data")
            result = latest
        else:
            # ISO8601 timestamp
            result = parse_timestamp(self.base)

        # Apply offsets
        for sign, seconds in self.offsets:
            if sign == "+":
                result += timedelta(seconds=seconds)
            else:
                result -= timedelta(seconds=seconds)

        return result


def _unit_to_seconds(value: int, unit: str) -> int:
    """
    Convert time unit to seconds.

    Args:
        value: Numeric value
        unit: Time unit (s, m, h, d, w, mon, y)

    Returns:
        Total seconds

    Raises:
        ValueError: If unit is unknown
    """
    units = {
        's': 1,
        'm': 60,
        'h': 3600,
        'd': 86400,
        'w': 604800,
        'mon': 2592000,  # 30 days
        'y': 31536000,   # 365 days
    }

    if unit not in units:
        raise ValueError(f"Unknown time unit: {unit}")

    return value * units[unit]


def parse_time_expression(expr: str) -> TimeExpression:
    """
    Parse relative time expression.

    Supports:
    - Simple keywords: "now", "earliest", "latest"
    - ISO8601 timestamps: "2024-01-15T10:00:00Z"
    - Relative expressions: "now-2h", "earliest+1d", "latest-30m"
    - Complex expressions: "now-1d-12h-30m"

    Time units:
    - s: seconds
    - m: minutes
    - h: hours
    - d: days
    - w: weeks
    - mon: months (30 days)
    - y: years (365 days)

    Examples:
        "now" -> TimeExpression(base="now", offsets=[])
        "now-2h" -> TimeExpression(base="now", offsets=[("-", 7200)])
        "earliest+1d-30m" -> TimeExpression(base="earliest", offsets=[("+", 86400), ("-", 1800)])
        "2024-01-15T10:00:00Z" -> TimeExpression(base="2024-01-15T10:00:00Z", offsets=[])

    Args:
        expr: Time expression string

    Returns:
        TimeExpression object

    Raises:
        ValueError: If expression is invalid
    """
    # Check if it's a simple keyword (case-insensitive)
    if expr.lower() in ("now", "earliest", "latest"):
        return TimeExpression(base=expr.lower(), offsets=[])

    # Check if it's an ISO8601 timestamp (contains 'T' or ':')
    if 'T' in expr or (':' in expr and '-' not in expr[:10]):
        # Validate it's a valid timestamp
        try:
            parse_timestamp(expr)
            return TimeExpression(base=expr, offsets=[])
        except ValueError:
            raise ValueError(f"Invalid ISO8601 timestamp: {expr}")

    # Parse relative expression
    # Pattern: (now|earliest|latest)([-+]\d+[smhdwmony]+)+
    pattern = r'^(now|earliest|latest)((?:[-+]\d+[smhdwmony]+)+)$'
    match = re.match(pattern, expr, re.IGNORECASE)

    if not match:
        raise ValueError(
            f"Invalid time expression: {expr}. "
            f"Expected format: now|earliest|latest[+/-<number><unit>...] or ISO8601 timestamp"
        )

    base = match.group(1).lower()
    offset_str = match.group(2)

    # Parse offsets
    offset_pattern = r'([-+])(\d+)([smhdwmony]+)'
    offsets = []

    for offset_match in re.finditer(offset_pattern, offset_str):
        sign = offset_match.group(1)
        value = int(offset_match.group(2))
        unit = offset_match.group(3).lower()

        # Convert to seconds
        seconds = _unit_to_seconds(value, unit)
        offsets.append((sign, seconds))

    return TimeExpression(base=base, offsets=offsets)
