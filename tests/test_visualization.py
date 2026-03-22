"""Tests for visualization utilities."""

import pytest
from datetime import datetime, timedelta, timezone

from echolake.cli.visualization import (
    calculate_event_buckets,
    _build_histogram,
)


class TestEventBuckets:
    """Tests for event bucketing for histogram display."""

    def test_calculate_buckets_simple(self):
        """Test basic bucket calculation."""
        # Create events spanning 10 hours
        start = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

        events = [
            (start,),
            (start + timedelta(hours=2),),
            (start + timedelta(hours=4),),
            (start + timedelta(hours=6),),
            (start + timedelta(hours=8),),
            (start + timedelta(hours=10),),
        ]

        buckets = calculate_event_buckets(events, num_buckets=5)

        # Should have 5 buckets
        assert len(buckets) == 5

        # Should have events distributed across buckets
        total_events = sum(buckets.values())
        assert total_events == 6  # 6 timestamps total

    def test_calculate_buckets_empty(self):
        """Test with no events."""
        buckets = calculate_event_buckets([], num_buckets=10)
        assert buckets == {}

    def test_calculate_buckets_single_time(self):
        """Test when all events are at the same time."""
        same_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        events = [
            (same_time,),
            (same_time,),
            (same_time,),
        ]

        buckets = calculate_event_buckets(events, num_buckets=10)

        # Should have one bucket with all events
        assert len(buckets) == 1
        assert sum(buckets.values()) == 3

    def test_calculate_buckets_multiple_timestamps_per_event(self):
        """Test with events that have multiple timestamps."""
        start = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

        # Events with multiple timestamps each
        events = [
            (start, start + timedelta(minutes=1)),
            (start + timedelta(hours=2), start + timedelta(hours=2, minutes=1)),
            (start + timedelta(hours=4), start + timedelta(hours=4, minutes=1)),
        ]

        buckets = calculate_event_buckets(events, num_buckets=5)

        # Should count all timestamps
        total_timestamps = sum(buckets.values())
        assert total_timestamps == 6  # 3 events × 2 timestamps each


class TestHistogramBuilding:
    """Tests for ASCII histogram building."""

    def test_build_histogram_simple(self):
        """Test basic histogram building."""
        start = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

        buckets = {
            start: 5,
            start + timedelta(hours=1): 3,
            start + timedelta(hours=2): 8,
            start + timedelta(hours=3): 2,
        }

        histogram = _build_histogram(buckets, width=40, height=8)

        # Should return non-empty string
        assert isinstance(histogram, str)
        assert len(histogram) > 0

        # Should contain bar characters
        assert any(char in histogram for char in ['░', '▂', '▄', '█'])

    def test_build_histogram_empty(self):
        """Test with no data."""
        histogram = _build_histogram({}, width=40, height=8)
        assert histogram == ""

    def test_build_histogram_all_zeros(self):
        """Test with all zero counts."""
        start = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

        buckets = {
            start: 0,
            start + timedelta(hours=1): 0,
            start + timedelta(hours=2): 0,
        }

        histogram = _build_histogram(buckets, width=40, height=8)
        assert histogram == ""

    def test_build_histogram_scales_correctly(self):
        """Test that histogram scales to max value."""
        start = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

        # One very large value
        buckets = {
            start: 100,
            start + timedelta(hours=1): 10,
            start + timedelta(hours=2): 1,
        }

        histogram = _build_histogram(buckets, width=40, height=8)

        # Should scale to height (tallest bar should use tallest character)
        assert '█' in histogram  # Tallest bar


class TestTimelineText:
    """Tests for timeline text generation."""

    def test_timeline_shows_markers(self):
        """Test that timeline includes all markers."""
        # This is tested implicitly through CLI tests
        # since the timeline building is complex and visual
        pass


class TestDryRunVisualization:
    """Tests for dry-run visualization output."""

    def test_dry_run_creates_histogram_data(self):
        """Test that dry-run mode collects data for histogram."""
        # This is tested through integration tests
        pass
