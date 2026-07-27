"""Tests for the Lakehouse Bronze schema handler.

Regression coverage for the bug where bronze JSONL exports carrying the real
`_time` field extracted zero timestamps (because the schema only knew about the
manifest field name `_event_time`), which caused a timestamp-shifting run to
silently write 0 events and still report success.
"""

from echolake.inputs.schemas.lakehouse import LakehouseBronzeSchema


def test_bronze_extracts_time_field_iso():
    """A bronze event with an ISO8601 `_time` yields a base timestamp."""
    schema = LakehouseBronzeSchema()
    event = schema.extract_event(
        {"_time": "2025-03-03T22:59:54+00:00", "sourcetype": "WinEventLog:Security", "_raw": "x"},
        "jsonl",
    )
    assert event.timestamps, "expected a timestamp extracted from `_time`"
    assert "_time" in event.timestamps


def test_bronze_extracts_time_field_epoch():
    """A bronze event with an epoch-seconds `_time` yields a base timestamp."""
    schema = LakehouseBronzeSchema()
    event = schema.extract_event(
        {"_time": 1740956394, "sourcetype": "suricata", "_raw": "y"},
        "jsonl",
    )
    assert event.timestamps, "expected a timestamp extracted from epoch `_time`"


def test_bronze_still_supports_legacy_event_time():
    """The legacy `_event_time` field remains a valid base timestamp."""
    schema = LakehouseBronzeSchema()
    event = schema.extract_event(
        {"_event_time": "2025-03-03T22:59:54+00:00", "_raw": "z"},
        "jsonl",
    )
    assert event.timestamps


def test_bronze_validate_accepts_time_or_event_time():
    schema = LakehouseBronzeSchema()
    assert schema.validate_event({"_time": "2025-03-03T22:59:54+00:00"})
    assert schema.validate_event({"_event_time": "2025-03-03T22:59:54+00:00"})
    assert not schema.validate_event({"foo": "bar"})
