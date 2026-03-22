"""Raw schema handler (no specific schema)."""

import logging
from typing import Any, Dict, List, Optional
from ..base import InputSchema
from ...models.event import Event
from ...core.timestamp import TimestampExtractor

logger = logging.getLogger(__name__)


class RawSchema(InputSchema):
    """
    Raw schema handler - no schema-specific extraction.

    Uses generic timestamp detection patterns.
    Supports sourcetype-based registry lookup for custom timestamp fields.
    """

    def __init__(self, timestamp_patterns: Optional[List[Dict[str, Any]]] = None):
        """
        Initialize raw schema.

        Args:
            timestamp_patterns: Optional custom timestamp patterns (highest priority)
        """
        self.custom_patterns = timestamp_patterns
        self.timestamp_extractor = TimestampExtractor(
            timestamp_patterns or self.get_timestamp_patterns()
        )
        # Cache sourcetype-specific extractors to avoid re-creating per event
        self._sourcetype_extractors: Dict[str, TimestampExtractor] = {}

    def _get_extractor_for_sourcetype(self, sourcetype: str) -> Optional[TimestampExtractor]:
        """Get or create a TimestampExtractor with registry patterns prepended."""
        if sourcetype in self._sourcetype_extractors:
            return self._sourcetype_extractors[sourcetype]

        from ..timestamp_registry import TimestampRegistry
        registry = TimestampRegistry.get()
        registry_patterns = registry.lookup(sourcetype)

        if registry_patterns is None:
            self._sourcetype_extractors[sourcetype] = None
            return None

        # Prepend registry patterns before schema defaults
        merged = registry_patterns + self.get_timestamp_patterns()
        extractor = TimestampExtractor(merged)
        self._sourcetype_extractors[sourcetype] = extractor
        logger.debug(f"Created timestamp extractor for sourcetype '{sourcetype}' with {len(registry_patterns)} registry patterns")
        return extractor

    def extract_event(self, raw_data: dict, format_type: str, sourcetype: str = None) -> Event:
        """
        Extract Event from raw data.

        Args:
            raw_data: Parsed data dictionary
            format_type: Format type
            sourcetype: Optional sourcetype for registry lookup

        Returns:
            Event instance
        """
        # Choose extractor: custom patterns > sourcetype registry > defaults
        extractor = self.timestamp_extractor
        if not self.custom_patterns and sourcetype:
            st_extractor = self._get_extractor_for_sourcetype(sourcetype)
            if st_extractor:
                extractor = st_extractor

        timestamps = extractor.extract_from_dict(raw_data)
        regex_originals = getattr(extractor, '_regex_originals', {})
        regex_formats = getattr(extractor, '_regex_formats', {})

        # No schema-specific metadata
        metadata = {
            'schema': None,
        }

        return Event(
            raw_data=raw_data,
            timestamps=timestamps,
            metadata=metadata,
            format=format_type,
            schema=None,
            regex_originals=regex_originals,
            regex_formats=regex_formats,
        )

    def get_timestamp_patterns(self) -> List[Dict[str, Any]]:
        """
        Get generic timestamp patterns.

        Returns:
            List of common timestamp field patterns
        """
        if self.custom_patterns:
            return self.custom_patterns

        # Common timestamp field names
        return [
            {'field': 'timestamp', 'format': 'iso8601', 'is_base': True},
            {'field': 'time', 'format': 'unix_millis', 'is_base': False},  # OCSF/common unix ms
            {'field': 'time', 'format': 'iso8601', 'is_base': False},  # Also try ISO8601 for 'time'
            {'field': 'ts', 'format': 'unix_seconds', 'is_base': False},
            {'field': 'ts', 'format': 'unix_millis', 'is_base': False},
            {'field': 'datetime', 'format': 'iso8601', 'is_base': False},
            {'field': 'event_time', 'format': 'iso8601', 'is_base': False},
            {'field': 'eventTime', 'format': 'iso8601', 'is_base': False},  # AWS CloudTrail
            {'field': 'EventTime', 'format': 'iso8601', 'is_base': False},
            {'field': '@timestamp', 'format': 'iso8601', 'is_base': False},
            {'field': 'created_at', 'format': 'iso8601', 'is_base': False},
            {'field': 'createdAt', 'format': 'iso8601', 'is_base': False},
            {'field': '_time', 'format': 'iso8601', 'is_base': False},
            {'field': '_time', 'format': 'unix_seconds', 'is_base': False},
            {'field': 'start_time', 'format': 'unix_millis', 'is_base': False},  # OCSF
            {'field': 'end_time', 'format': 'unix_millis', 'is_base': False},  # OCSF
        ]

    def validate_event(self, raw_data: dict) -> bool:
        """
        Validate raw event (always valid).

        Args:
            raw_data: Data to validate

        Returns:
            Always True
        """
        return True
