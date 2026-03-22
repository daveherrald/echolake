"""Tests for timestamp manipulation."""

import pytest
from datetime import datetime, timedelta, timezone
from echolake.core.timestamp import TimestampExtractor, TimestampManipulator
from echolake.utils.time import parse_timestamp


class TestTimestampExtractor:
    """Tests for TimestampExtractor."""

    def test_extract_from_dict_simple(self):
        """Test extracting timestamps from simple dict."""
        patterns = [
            {'field': 'timestamp', 'format': 'iso8601', 'is_base': True}
        ]
        extractor = TimestampExtractor(patterns)

        data = {'timestamp': '2024-01-01T10:00:00Z', 'message': 'test'}
        timestamps = extractor.extract_from_dict(data)

        assert 'timestamp' in timestamps
        assert isinstance(timestamps['timestamp'], datetime)

    def test_extract_nested_field(self):
        """Test extracting nested timestamp field."""
        patterns = [
            {'field': 'metadata.timestamp', 'format': 'iso8601', 'is_base': True}
        ]
        extractor = TimestampExtractor(patterns)

        data = {
            'metadata': {'timestamp': '2024-01-01T10:00:00Z'},
            'message': 'test'
        }
        timestamps = extractor.extract_from_dict(data)

        assert 'metadata.timestamp' in timestamps

    def test_get_base_timestamp(self):
        """Test getting base timestamp."""
        patterns = [
            {'field': 'ts1', 'format': 'iso8601', 'is_base': False},
            {'field': 'ts2', 'format': 'iso8601', 'is_base': True},
        ]
        extractor = TimestampExtractor(patterns)

        timestamps = {
            'ts1': datetime(2024, 1, 1, 11, 0, 0, tzinfo=timezone.utc),
            'ts2': datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
        }

        base = extractor.get_base_timestamp(timestamps)
        assert base == timestamps['ts2']


class TestTimestampManipulator:
    """Tests for TimestampManipulator."""

    def test_calculate_shifts_preserve_deltas(self):
        """Test that delta_factor=1.0 preserves time deltas."""
        manipulator = TimestampManipulator(
            delta_factor=1.0,
            base_time='earliest',
            target_time='2024-01-01T12:00:00Z',
            prevent_future=False
        )

        events_timestamps = [
            {'ts': datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},
            {'ts': datetime(2024, 1, 1, 10, 5, 0, tzinfo=timezone.utc)},
            {'ts': datetime(2024, 1, 1, 10, 10, 0, tzinfo=timezone.utc)},
        ]

        original_base, new_base, shift_map = manipulator.calculate_shifts(events_timestamps)

        # Calculate new timestamps
        new_timestamps = []
        for ts_dict in events_timestamps:
            for field, dt in ts_dict.items():
                new_dt = manipulator.apply_shift(dt, shift_map)
                new_timestamps.append(new_dt)

        # Check that deltas are preserved
        original_deltas = [
            events_timestamps[1]['ts'] - events_timestamps[0]['ts'],
            events_timestamps[2]['ts'] - events_timestamps[1]['ts'],
        ]
        new_deltas = [
            new_timestamps[1] - new_timestamps[0],
            new_timestamps[2] - new_timestamps[1],
        ]

        assert original_deltas == new_deltas

    def test_calculate_shifts_expand_deltas(self):
        """Test that delta_factor=2.0 doubles time deltas."""
        manipulator = TimestampManipulator(
            delta_factor=2.0,
            base_time='earliest',
            target_time='2024-01-01T12:00:00Z',
            prevent_future=False
        )

        events_timestamps = [
            {'ts': datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},
            {'ts': datetime(2024, 1, 1, 10, 5, 0, tzinfo=timezone.utc)},
        ]

        original_delta = events_timestamps[1]['ts'] - events_timestamps[0]['ts']

        original_base, new_base, shift_map = manipulator.calculate_shifts(events_timestamps)

        new_timestamps = []
        for ts_dict in events_timestamps:
            for field, dt in ts_dict.items():
                new_dt = manipulator.apply_shift(dt, shift_map)
                new_timestamps.append(new_dt)

        new_delta = new_timestamps[1] - new_timestamps[0]

        assert new_delta == original_delta * 2

    def test_prevent_future(self):
        """Test that prevent_future caps timestamps."""
        now = datetime.now(timezone.utc)
        manipulator = TimestampManipulator(
            delta_factor=100.0,  # Large factor to push into future
            base_time='earliest',
            target_time='now',
            prevent_future=True,
            ceiling_time='now'
        )

        events_timestamps = [
            {'ts': datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},
            {'ts': datetime(2024, 1, 1, 10, 5, 0, tzinfo=timezone.utc)},
        ]

        original_base, new_base, shift_map = manipulator.calculate_shifts(events_timestamps)

        for ts_dict in events_timestamps:
            for field, dt in ts_dict.items():
                new_dt = manipulator.apply_shift(dt, shift_map)
                # Should not be more than a few seconds in the future
                assert new_dt <= now + timedelta(seconds=5)


class TestTimestampManipulatorWithExpressions:
    """Tests for TimestampManipulator with time expressions."""

    def test_calculate_shifts_with_latest_base(self):
        """Test using 'latest' as base time."""
        manipulator = TimestampManipulator(
            base_time="latest",
            target_time="2024-01-02T12:00:00Z",
            delta_factor=1.0,
            prevent_future=False,
        )

        events = [
            {"timestamp": datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},
            {"timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)},  # Latest
            {"timestamp": datetime(2024, 1, 1, 11, 0, 0, tzinfo=timezone.utc)},
        ]

        original_base, new_base, shift_map = manipulator.calculate_shifts(events)

        # Original base should be latest (12:00)
        assert original_base == datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_calculate_shifts_with_earliest_plus_offset(self):
        """Test using 'earliest+1h' as base time."""
        manipulator = TimestampManipulator(
            base_time="earliest+1h",
            target_time="2024-01-02T12:00:00Z",
            delta_factor=1.0,
            prevent_future=False,
        )

        events = [
            {"timestamp": datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},  # Earliest
            {"timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)},
        ]

        original_base, new_base, shift_map = manipulator.calculate_shifts(events)

        # Base should be earliest + 1h = 11:00
        assert original_base == datetime(2024, 1, 1, 11, 0, 0, tzinfo=timezone.utc)

    def test_calculate_shifts_with_latest_minus_offset(self):
        """Test using 'latest-30m' as base time."""
        manipulator = TimestampManipulator(
            base_time="latest-30m",
            target_time="2024-01-02T12:00:00Z",
            delta_factor=1.0,
            prevent_future=False,
        )

        events = [
            {"timestamp": datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},
            {"timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)},  # Latest
        ]

        original_base, new_base, shift_map = manipulator.calculate_shifts(events)

        # Base should be latest - 30m = 11:30
        assert original_base == datetime(2024, 1, 1, 11, 30, 0, tzinfo=timezone.utc)

    def test_target_time_with_offset(self):
        """Test target time with offset expression."""
        # Using a fixed target time for predictability
        manipulator = TimestampManipulator(
            base_time="earliest",
            target_time="2024-01-02T12:00:00Z",  # ISO8601 still works
            delta_factor=1.0,
            prevent_future=False,
        )

        events = [
            {"timestamp": datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},
            {"timestamp": datetime(2024, 1, 1, 11, 0, 0, tzinfo=timezone.utc)},
        ]

        original_base, new_base, shift_map = manipulator.calculate_shifts(events)

        # New base should be the target time
        assert new_base == datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc)

    def test_complex_base_expression(self):
        """Test complex base time expression."""
        manipulator = TimestampManipulator(
            base_time="earliest+1d+12h",
            target_time="2024-01-02T12:00:00Z",
            delta_factor=1.0,
            prevent_future=False,
        )

        events = [
            {"timestamp": datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},  # Earliest
            {"timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)},
        ]

        original_base, new_base, shift_map = manipulator.calculate_shifts(events)

        # Base should be earliest + 1d + 12h = Jan 2 22:00
        assert original_base == datetime(2024, 1, 2, 22, 0, 0, tzinfo=timezone.utc)

    def test_backward_compatibility_auto(self):
        """Test that 'auto' still works (backward compatibility)."""
        manipulator = TimestampManipulator(
            base_time="auto",  # Should behave like 'earliest'
            target_time="2024-01-02T12:00:00Z",
            delta_factor=1.0,
            prevent_future=False,
        )

        events = [
            {"timestamp": datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},  # Earliest
            {"timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)},
        ]

        original_base, new_base, shift_map = manipulator.calculate_shifts(events)

        # Should use earliest
        assert original_base == datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

    def test_backward_compatibility_now(self):
        """Test that 'now' still works without offset."""
        manipulator = TimestampManipulator(
            base_time="earliest",
            target_time="now",  # Should be current time
            delta_factor=1.0,
            prevent_future=False,
        )

        events = [
            {"timestamp": datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)},
        ]

        before = datetime.now(timezone.utc)
        original_base, new_base, shift_map = manipulator.calculate_shifts(events)
        after = datetime.now(timezone.utc)

        # New base should be approximately now
        assert before <= new_base <= after + timedelta(seconds=1)
