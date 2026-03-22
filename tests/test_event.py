"""Tests for Event data model."""

import pytest
import json
from datetime import datetime, timedelta
from echolake.models.event import Event


class TestEvent:
    """Tests for Event model."""

    def test_create_event(self):
        """Test creating an Event."""
        raw_data = {'timestamp': '2024-01-01T10:00:00Z', 'message': 'test'}
        timestamps = {'timestamp': datetime(2024, 1, 1, 10, 0, 0)}
        metadata = {'schema': 'raw'}

        event = Event(
            raw_data=raw_data,
            timestamps=timestamps,
            metadata=metadata,
            format='json',
            schema='raw'
        )

        assert event.raw_data == raw_data
        assert event.timestamps == timestamps
        assert event.format == 'json'
        assert event.schema == 'raw'

    def test_get_base_timestamp(self):
        """Test getting base timestamp from event."""
        timestamps = {
            'ts1': datetime(2024, 1, 1, 11, 0, 0),
            'ts2': datetime(2024, 1, 1, 10, 0, 0),
        }

        event = Event(
            raw_data={},
            timestamps=timestamps,
            metadata={},
            format='json'
        )

        # Should return earliest by default
        base = event.get_base_timestamp()
        assert base == timestamps['ts2']

    def test_apply_timestamp_shifts(self):
        """Test applying timestamp shifts to event."""
        original_ts = datetime(2024, 1, 1, 10, 0, 0)
        raw_data = {'timestamp': original_ts.isoformat()}
        timestamps = {'timestamp': original_ts}

        event = Event(
            raw_data=raw_data,
            timestamps=timestamps,
            metadata={},
            format='json'
        )

        # Create shift map: shift by 1 hour
        shift = timedelta(hours=1)
        shift_map = {original_ts.isoformat(): shift}

        modified_event = event.apply_timestamp_shifts(shift_map)

        # Check that timestamp was shifted
        expected_ts = original_ts + shift
        assert modified_event.timestamps['timestamp'] == expected_ts

        # Check that raw_data was updated
        assert modified_event.raw_data['timestamp'] == expected_ts.isoformat()

    def test_serialize_json(self):
        """Test serializing event to JSON."""
        raw_data = {'timestamp': '2024-01-01T10:00:00Z', 'message': 'test'}
        event = Event(
            raw_data=raw_data,
            timestamps={},
            metadata={},
            format='json'
        )

        serialized = event.serialize('json')
        deserialized = json.loads(serialized)

        assert deserialized == raw_data

    def test_serialize_jsonl(self):
        """Test serializing event to JSONL."""
        raw_data = {'timestamp': '2024-01-01T10:00:00Z', 'message': 'test'}
        event = Event(
            raw_data=raw_data,
            timestamps={},
            metadata={},
            format='jsonl'
        )

        serialized = event.serialize('jsonl')

        # JSONL should not have newline at end
        assert not serialized.endswith('\n')

        # Should be valid JSON
        deserialized = json.loads(serialized)
        assert deserialized == raw_data

    def test_serialize_text(self):
        """Test serializing event to text."""
        raw_data = {'line': 'This is a log line'}
        event = Event(
            raw_data=raw_data,
            timestamps={},
            metadata={},
            format='text'
        )

        serialized = event.serialize('text')
        assert serialized == 'This is a log line'
