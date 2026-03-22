"""Lakehouse Bronze schema handler."""

from datetime import datetime
from typing import Any, Dict, List
from ..base import InputSchema
from ...models.event import Event
from ...core.timestamp import TimestampExtractor
from ...utils.time import parse_timestamp


class LakehouseBronzeSchema(InputSchema):
    """
    Schema handler for Lakehouse Bronze format.

    Extracts _event_time, _ingest_time, and _metadata fields.
    """

    def __init__(self):
        """Initialize Lakehouse Bronze schema."""
        self.timestamp_extractor = TimestampExtractor(self.get_timestamp_patterns())

    def extract_event(self, raw_data: dict, format_type: str, sourcetype: str = None) -> Event:
        """
        Extract Event from Lakehouse Bronze data.

        Args:
            raw_data: Parsed data dictionary
            format_type: Format type (should be json or jsonl)
            sourcetype: Ignored (Lakehouse has fixed patterns)

        Returns:
            Event instance
        """
        # Extract timestamps
        timestamps = self.timestamp_extractor.extract_from_dict(raw_data)

        # Extract metadata
        metadata = {
            'schema': 'lakehouse_bronze',
        }

        if '_metadata' in raw_data:
            metadata['_metadata'] = raw_data['_metadata']

        # Additional Lakehouse-specific fields
        if '_source' in raw_data:
            metadata['_source'] = raw_data['_source']

        if '_ingestion_job_id' in raw_data:
            metadata['_ingestion_job_id'] = raw_data['_ingestion_job_id']

        return Event(
            raw_data=raw_data,
            timestamps=timestamps,
            metadata=metadata,
            format=format_type,
            schema='lakehouse_bronze',
        )

    def get_timestamp_patterns(self) -> List[Dict[str, Any]]:
        """
        Get timestamp patterns for Lakehouse Bronze.

        Returns:
            List of timestamp pattern configurations
        """
        return [
            {
                'field': '_event_time',
                'format': 'iso8601',
                'is_base': True,  # Use _event_time as base for delta calculation
            },
            {
                'field': '_ingest_time',
                'format': 'iso8601',
                'is_base': False,
            },
        ]

    def validate_event(self, raw_data: dict) -> bool:
        """
        Validate that data conforms to Lakehouse Bronze schema.

        Args:
            raw_data: Data to validate

        Returns:
            True if valid, False otherwise
        """
        # Lakehouse Bronze should have at least _event_time
        return '_event_time' in raw_data
