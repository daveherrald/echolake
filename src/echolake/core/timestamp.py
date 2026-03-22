"""Timestamp extraction and manipulation logic."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import re
from ..utils.time import parse_timestamp, parse_time_expression, TimeExpression


class TimestampExtractor:
    """Extract timestamps from events based on field patterns."""

    def __init__(self, patterns: Optional[List[Dict[str, Any]]] = None):
        """
        Initialize timestamp extractor.

        Args:
            patterns: List of timestamp patterns with 'field', 'format', 'is_base'
        """
        self.patterns = patterns or []

    def extract_from_dict(self, data: Dict[str, Any]) -> Dict[str, datetime]:
        """
        Extract timestamps from dictionary data.

        Args:
            data: Event data as dictionary

        Returns:
            Dictionary mapping field names to datetime objects
        """
        timestamps = {}
        # Track original matched strings for regex extractions so that
        # _update_raw_data can do targeted string replacement instead of
        # overwriting the entire field value.
        self._regex_originals = {}
        self._regex_formats = {}

        for pattern in self.patterns:
            # Handle both dict and Pydantic model patterns
            if isinstance(pattern, dict):
                field = pattern.get("field")
                format_type = pattern.get("format", "iso8601")
            else:
                # Assume it's a Pydantic model (has attributes)
                field = getattr(pattern, "field", None)
                format_type = getattr(pattern, "format", "iso8601")

            if field is None:
                continue

            value = self._get_nested_field(data, field)
            if value is not None:
                # Handle regex extraction (e.g., pulling timestamp from raw text)
                regex_pattern = pattern.get("regex") if isinstance(pattern, dict) else getattr(pattern, "regex", None)
                if regex_pattern and isinstance(value, str):
                    match = re.search(regex_pattern, value)
                    if match:
                        self._regex_originals[field] = match.group(1)
                        self._regex_formats[field] = format_type
                        value = match.group(1)
                    else:
                        continue

                try:
                    dt = parse_timestamp(value, format_type)
                    if dt:
                        timestamps[field] = dt
                except (ValueError, TypeError):
                    # Skip unparseable timestamps
                    pass

        return timestamps

    def extract_from_text(self, text: str, patterns: Optional[List[str]] = None) -> List[datetime]:
        """
        Extract timestamps from text using regex patterns.

        Args:
            text: Text to extract from
            patterns: Optional regex patterns for timestamps

        Returns:
            List of extracted datetime objects
        """
        timestamps = []
        default_patterns = [
            # ISO8601
            r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?',
            # Unix timestamp (10 digits)
            r'\b\d{10}\b',
            # RFC3339
            r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})',
        ]

        use_patterns = patterns or default_patterns

        for pattern in use_patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                try:
                    dt = parse_timestamp(match.group(0))
                    if dt:
                        timestamps.append(dt)
                except (ValueError, TypeError):
                    continue

        return timestamps

    def get_base_timestamp(
        self, timestamps: Dict[str, datetime], prefer_field: Optional[str] = None
    ) -> Optional[datetime]:
        """
        Get the base timestamp for delta calculation.

        Args:
            timestamps: Dictionary of extracted timestamps
            prefer_field: Preferred field to use as base (if is_base=True in patterns)

        Returns:
            Base timestamp or None
        """
        # First try to find field marked as is_base
        for pattern in self.patterns:
            # Handle both dict and Pydantic model patterns
            if isinstance(pattern, dict):
                is_base = pattern.get("is_base", False)
                field = pattern.get("field")
            else:
                # Assume it's a Pydantic model (has attributes)
                is_base = getattr(pattern, "is_base", False)
                field = getattr(pattern, "field", None)

            if is_base and field and field in timestamps:
                return timestamps[field]

        # Fall back to prefer_field
        if prefer_field and prefer_field in timestamps:
            return timestamps[prefer_field]

        # Fall back to earliest timestamp
        if timestamps:
            return min(timestamps.values())

        return None

    @staticmethod
    def _get_nested_field(data: Dict[str, Any], field: str) -> Any:
        """
        Get nested field from dictionary using dot notation.

        Args:
            data: Dictionary to search
            field: Field name (supports dot notation like 'metadata.timestamp')

        Returns:
            Field value or None
        """
        parts = field.split('.')
        current = data

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None

        return current


class TimestampManipulator:
    """Manipulate timestamps while preserving deltas."""

    def __init__(
        self,
        delta_factor: float = 1.0,
        base_time: str = "auto",
        target_time: str = "now",
        prevent_future: bool = True,
        ceiling_time: Optional[str] = "now",
    ):
        """
        Initialize timestamp manipulator.

        Args:
            delta_factor: Multiply time deltas by this factor
            base_time: Base time reference ('auto', 'earliest', 'latest', or time expression)
            target_time: Target time for echo ('now' or time expression)
            prevent_future: Prevent timestamps beyond ceiling
            ceiling_time: Maximum allowed timestamp ('now' or time expression)
        """
        self.delta_factor = delta_factor
        self.base_time_expr = base_time  # Store expression string
        self.target_time_expr = target_time
        self.prevent_future = prevent_future
        self.ceiling_time_expr = ceiling_time

        # Parse expressions (validates syntax)
        # For base_time, handle legacy "auto" keyword
        if base_time == "auto":
            self._base_expr = None  # Will use earliest
        else:
            self._base_expr = parse_time_expression(base_time)

        self._target_expr = parse_time_expression(target_time) if target_time else None
        self._ceiling_expr = parse_time_expression(ceiling_time) if ceiling_time else None

        # Cached computed values (will be resolved later)
        self._target_dt: Optional[datetime] = None
        self._ceiling_dt: Optional[datetime] = None

    def calculate_shifts(
        self, events_timestamps: List[Dict[str, datetime]]
    ) -> Tuple[datetime, datetime, Dict[str, timedelta]]:
        """
        Calculate timestamp shifts for all events.

        Args:
            events_timestamps: List of timestamp dicts from events

        Returns:
            Tuple of (original_base_time, new_base_time, shift_map)
            shift_map is dict mapping original timestamp to timedelta shift
        """
        # Find original base time
        original_base = self._find_base_time(events_timestamps)
        if original_base is None:
            raise ValueError("No timestamps found in events")

        # Collect all timestamps to find max delta
        all_timestamps: List[datetime] = []
        for ts_dict in events_timestamps:
            all_timestamps.extend(ts_dict.values())

        # Find maximum delta from base
        max_delta = timedelta(0)
        for ts in all_timestamps:
            delta = ts - original_base
            if delta > max_delta:
                max_delta = delta

        # Calculate new base time
        # If prevent_future is enabled, adjust new_base so the latest event doesn't exceed ceiling
        initial_target = self._calculate_target_time()
        ceiling = self._calculate_ceiling_time()

        if self.prevent_future and ceiling:
            # Calculate what the latest event time would be
            max_new_delta = max_delta * self.delta_factor
            projected_max = initial_target + max_new_delta

            # If it would exceed ceiling, shift the base time back
            if projected_max > ceiling:
                new_base = ceiling - max_new_delta
            else:
                new_base = initial_target
        else:
            new_base = initial_target

        # Build shift map
        shift_map: Dict[str, timedelta] = {}

        for ts_dict in events_timestamps:
            for field, original_dt in ts_dict.items():
                # Calculate original delta from base
                original_delta = original_dt - original_base

                # Apply delta factor
                new_delta = original_delta * self.delta_factor

                # Calculate new timestamp
                new_dt = new_base + new_delta

                # Store shift as timedelta
                shift = new_dt - original_dt
                shift_map[original_dt.isoformat()] = shift

        return original_base, new_base, shift_map

    def apply_shift(
        self, original_dt: datetime, shift_map: Dict[str, timedelta]
    ) -> datetime:
        """
        Apply shift to a timestamp.

        Args:
            original_dt: Original datetime
            shift_map: Map from ISO timestamp to timedelta shift

        Returns:
            Shifted datetime
        """
        key = original_dt.isoformat()
        if key in shift_map:
            return original_dt + shift_map[key]
        return original_dt

    def _find_base_time(self, events_timestamps: List[Dict[str, datetime]]) -> Optional[datetime]:
        """Find the base timestamp from events."""
        all_timestamps: List[datetime] = []

        for ts_dict in events_timestamps:
            all_timestamps.extend(ts_dict.values())

        if not all_timestamps:
            return None

        earliest = min(all_timestamps)
        latest = max(all_timestamps)

        # Handle legacy "auto" and "earliest" keywords
        if self.base_time_expr in ("auto", "earliest"):
            return earliest

        # Resolve time expression
        if self._base_expr:
            return self._base_expr.resolve(earliest=earliest, latest=latest)

        return earliest  # Default to earliest

    def _calculate_target_time(self) -> datetime:
        """Calculate the target time for echo."""
        if self._target_dt is None:
            if self.target_time_expr == "now":
                self._target_dt = datetime.now(timezone.utc)
            elif self._target_expr:
                # Resolve time expression
                # For target time, earliest/latest don't make sense in most cases,
                # but we support them anyway by passing None (will raise error if used)
                self._target_dt = self._target_expr.resolve()
            else:
                raise ValueError(f"Invalid target_time: {self.target_time_expr}")

        return self._target_dt

    def _calculate_ceiling_time(self) -> Optional[datetime]:
        """Calculate the ceiling time."""
        if not self.prevent_future:
            return None

        if self._ceiling_dt is None:
            if self.ceiling_time_expr == "now":
                self._ceiling_dt = datetime.now(timezone.utc)
            elif self._ceiling_expr:
                # Resolve time expression
                self._ceiling_dt = self._ceiling_expr.resolve()

        return self._ceiling_dt
