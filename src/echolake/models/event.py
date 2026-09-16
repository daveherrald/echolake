"""Event data model for EchoLake."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union
import json
from ..utils.time import format_timestamp


@dataclass
class Event:
    """
    Unified event representation for EchoLake.

    Attributes:
        raw_data: Original data (string, dict, or other format)
        timestamps: Extracted timestamps by field name
        metadata: Schema-specific metadata
        format: Input format (json, jsonl, text, xml)
        schema: Optional schema name (lakehouse_bronze, ocsf, etc.)
        regex_originals: Original matched strings for regex-extracted timestamps
        regex_formats: Format types for regex-extracted timestamps (unix_seconds, iso8601, etc.)
        field_formats: Format that actually parsed each timestamp field
        field_originals: Original pre-shift value of each timestamp field
        field_preserve: Fields whose native on-the-wire format must be preserved on writeback
    """
    raw_data: Union[str, dict, Any]
    timestamps: Dict[str, datetime] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    format: str = "jsonl"
    schema: Optional[str] = None
    regex_originals: Dict[str, str] = field(default_factory=dict)
    regex_formats: Dict[str, str] = field(default_factory=dict)
    field_formats: Dict[str, str] = field(default_factory=dict)
    field_originals: Dict[str, Any] = field(default_factory=dict)
    field_preserve: Dict[str, bool] = field(default_factory=dict)

    def apply_timestamp_shift(
        self,
        delta_map: Dict[str, timedelta],
        field_mapping: Optional[Dict[str, str]] = None
    ) -> 'Event':
        """
        Apply timestamp transformations and return new Event.

        Args:
            delta_map: Mapping of field names to time deltas to apply
            field_mapping: Optional mapping of timestamp fields to JSON paths

        Returns:
            New Event instance with shifted timestamps
        """
        new_timestamps = {}
        for field_name, original_ts in self.timestamps.items():
            if field_name in delta_map:
                new_timestamps[field_name] = original_ts + delta_map[field_name]
            else:
                new_timestamps[field_name] = original_ts

        # Create new event with updated timestamps
        new_event = Event(
            raw_data=self._update_raw_data(new_timestamps, field_mapping),
            timestamps=new_timestamps,
            metadata=self.metadata.copy(),
            format=self.format,
            schema=self.schema
        )
        return new_event



    @staticmethod
    def _fractional_digits(value: str) -> int:
        """Count digits after the decimal point in a numeric string."""
        return len(value.split('.')[1]) if '.' in value else 0

    def _preserve_shape(self, field_name: str, new_ts: datetime) -> Any:
        """Render a shifted timestamp in the same format and type as the original.

        Falls back to ISO8601 only when the original shape is unknown.
        """
        fmt = self.field_formats.get(field_name, "iso8601")
        original = self.field_originals.get(field_name)

        if fmt == "unix_seconds":
            ts = new_ts.timestamp()
            if isinstance(original, int):
                # A whole-second field cannot carry a fractional shift, so it
                # lands on the nearest second rather than truncating toward it.
                # Such a field stays exact only to its own one-second
                # resolution, which can leave it up to half a second from a
                # millisecond-precision sibling in the same event.
                return round(ts)
            if isinstance(original, float):
                # Keep the source's precision, but never render coarser than a
                # millisecond. A source that happened to write `.25` would
                # otherwise round the shifted value to centiseconds and drift
                # from the millisecond-precision siblings (TimeCreated, the
                # envelope's ISO times) that describe the same instant.
                return round(ts, max(self._fractional_digits(str(original)), 3))
            if isinstance(original, str):
                decimals = self._fractional_digits(original)
                return f"{ts:.{decimals}f}" if decimals else str(int(ts))
            return ts

        if fmt == "unix_millis":
            ms = int(new_ts.timestamp() * 1000)
            return ms if isinstance(original, (int, float)) else str(ms)

        if fmt == "dotnet_date":
            return format_timestamp(new_ts, "dotnet_date")

        if fmt in ("iso8601", "rfc3339"):
            return new_ts.isoformat()

        return format_timestamp(new_ts, fmt)

    def apply_timestamp_shifts(self, shift_map: Dict[str, timedelta]) -> 'Event':
        """
        Apply timestamp shifts using a shift map from TimestampManipulator.

        Args:
            shift_map: Map from ISO timestamp strings to timedelta shifts

        Returns:
            New Event instance with shifted timestamps
        """
        new_timestamps = {}
        for field_name, original_ts in self.timestamps.items():
            # Look up the shift using the ISO format of the original timestamp
            iso_key = original_ts.isoformat()
            if iso_key in shift_map:
                new_timestamps[field_name] = original_ts + shift_map[iso_key]
            else:
                # No shift found, keep original
                new_timestamps[field_name] = original_ts

        # Create new event with updated timestamps
        new_event = Event(
            raw_data=self._update_raw_data(new_timestamps),
            timestamps=new_timestamps,
            metadata=self.metadata.copy(),
            format=self.format,
            schema=self.schema,
            regex_originals=self.regex_originals.copy(),
            regex_formats=self.regex_formats.copy(),
            field_formats=self.field_formats.copy(),
            field_originals=self.field_originals.copy(),
            field_preserve=self.field_preserve.copy(),
        )
        return new_event

    def _update_raw_data(
        self,
        new_timestamps: Dict[str, datetime],
        field_mapping: Optional[Dict[str, str]] = None
    ) -> Union[str, dict, Any]:
        """Update raw_data with new timestamp values."""
        if isinstance(self.raw_data, dict):
            # Deep copy the dict
            updated = json.loads(json.dumps(self.raw_data))

            for field_name, new_ts in new_timestamps.items():
                # Handle nested fields (e.g., "metadata.timestamp")
                if field_mapping and field_name in field_mapping:
                    path = field_mapping[field_name].split('.')
                else:
                    path = field_name.split('.')

                # Navigate to the field and update it
                current = updated
                for key in path[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]

                # For regex-extracted timestamps, do string substitution
                # within the original field value (e.g., replace timestamp
                # inside a syslog line) instead of overwriting the whole field
                if field_name in self.regex_originals:
                    original_match = self.regex_originals[field_name]
                    fmt = self.regex_formats.get(field_name, "iso8601")
                    # Format new timestamp in same format as original
                    if fmt == "unix_seconds" and '.' in original_match:
                        # Preserve fractional precision from original
                        decimals = len(original_match.split('.')[1])
                        new_ts_str = f"{new_ts.timestamp():.{decimals}f}"
                    else:
                        new_ts_str = format_timestamp(new_ts, fmt)
                    field_value = current.get(path[-1], "")
                    if isinstance(field_value, str) and original_match in field_value:
                        current[path[-1]] = field_value.replace(
                            original_match, new_ts_str, 1
                        )
                    else:
                        current[path[-1]] = new_ts_str
                elif self.field_preserve.get(field_name):
                    # Round-trip the field in its own on-the-wire shape. Native
                    # payload fields are read by downstream parsers that expect
                    # the original type and format, so coercing them to an
                    # ISO8601 string would make the event unparseable.
                    current[path[-1]] = self._preserve_shape(field_name, new_ts)
                else:
                    # Direct field replacement
                    current[path[-1]] = new_ts.isoformat()

            return updated

        elif isinstance(self.raw_data, str):
            # For string data, we need to do string replacement
            # This is handled by the change_map approach
            return self.raw_data

        else:
            # Unknown format, return as-is
            return self.raw_data

    def serialize(self, output_format: str) -> Union[str, bytes]:
        """
        Serialize event to output format.

        Args:
            output_format: Target format (json, jsonl, text)

        Returns:
            Serialized event data
        """
        if output_format == "json":
            if isinstance(self.raw_data, dict):
                return json.dumps(self.raw_data, indent=2)
            else:
                return str(self.raw_data)

        elif output_format == "jsonl":
            if isinstance(self.raw_data, dict):
                return json.dumps(self.raw_data)
            else:
                return str(self.raw_data)

        elif output_format == "text":
            if isinstance(self.raw_data, dict):
                # If there's a 'line' field (from text input), return just that
                if 'line' in self.raw_data:
                    return self.raw_data['line']
                return json.dumps(self.raw_data)
            else:
                return str(self.raw_data)

        else:
            raise ValueError(f"Unsupported output format: {output_format}")

    def get_base_timestamp(self, base_field: Optional[str] = None) -> Optional[datetime]:
        """
        Get the base timestamp for delta calculation.

        Args:
            base_field: Specific field to use as base, or None for earliest

        Returns:
            Base timestamp or None if no timestamps found
        """
        if not self.timestamps:
            return None

        if base_field and base_field in self.timestamps:
            return self.timestamps[base_field]

        # Return earliest timestamp
        return min(self.timestamps.values())

    def __repr__(self) -> str:
        """String representation of Event."""
        ts_info = f"{len(self.timestamps)} timestamp(s)" if self.timestamps else "no timestamps"
        schema_info = f" [{self.schema}]" if self.schema else ""
        return f"<Event format={self.format}{schema_info} {ts_info}>"
