"""OCSF (Open Cybersecurity Schema Framework) schema handler."""

from typing import Any, Dict, List
from ..base import InputSchema
from ...models.event import Event
from ...core.timestamp import TimestampExtractor


class OCSFSchema(InputSchema):
    """
    Schema handler for OCSF format.

    Pass-through schema that tags events with class_name and class_uid
    without strict validation.
    """

    def __init__(self, timestamp_field: str = "time"):
        """
        Initialize OCSF schema.

        Args:
            timestamp_field: Field name for primary timestamp (default: 'time')
        """
        self.timestamp_field = timestamp_field
        self.timestamp_extractor = TimestampExtractor(self.get_timestamp_patterns())

    def extract_event(self, raw_data: dict, format_type: str, sourcetype: str = None) -> Event:
        """
        Extract Event from OCSF data.

        Args:
            raw_data: Parsed data dictionary
            format_type: Format type
            sourcetype: Ignored (OCSF has fixed patterns)

        Returns:
            Event instance with OCSF metadata
        """
        # Extract timestamps
        timestamps = self.timestamp_extractor.extract_from_dict(raw_data)

        # Extract OCSF metadata
        metadata = {
            'schema': 'ocsf',
        }

        # Tag with OCSF class information if present
        if 'class_name' in raw_data:
            metadata['class_name'] = raw_data['class_name']

        if 'class_uid' in raw_data:
            metadata['class_uid'] = raw_data['class_uid']

        if 'category_name' in raw_data:
            metadata['category_name'] = raw_data['category_name']

        if 'category_uid' in raw_data:
            metadata['category_uid'] = raw_data['category_uid']

        if 'severity' in raw_data:
            metadata['severity'] = raw_data['severity']

        if 'severity_id' in raw_data:
            metadata['severity_id'] = raw_data['severity_id']

        return Event(
            raw_data=raw_data,
            timestamps=timestamps,
            metadata=metadata,
            format=format_type,
            schema='ocsf',
        )

    def get_timestamp_patterns(self) -> List[Dict[str, Any]]:
        """
        Get timestamp patterns for OCSF.

        Returns:
            List of timestamp pattern configurations
        """
        patterns = [
            {
                'field': self.timestamp_field,
                'format': 'unix_millis',  # OCSF uses Unix milliseconds
                'is_base': True,
            },
        ]

        # Also check for common timestamp fields
        additional_fields = ['start_time', 'end_time', 'create_time', 'modify_time']
        for field in additional_fields:
            patterns.append({
                'field': field,
                'format': 'unix_millis',
                'is_base': False,
            })

        return patterns

    def validate_event(self, raw_data: dict) -> bool:
        """
        Validate OCSF event (minimal validation).

        Args:
            raw_data: Data to validate

        Returns:
            True if has basic OCSF structure
        """
        # Minimal validation: should have class_uid or class_name
        return 'class_uid' in raw_data or 'class_name' in raw_data
