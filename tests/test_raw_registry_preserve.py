"""Raw-schema events keep each registry field's native type and format when shifted."""

from datetime import timedelta

import pytest

from echolake.inputs.schemas.raw import RawSchema

DELTA = timedelta(days=30, hours=1, minutes=2, seconds=3, milliseconds=456)
DELTA_MS = int(DELTA.total_seconds() * 1000)


def _shift(payload, sourcetype):
    event = RawSchema().extract_event(payload, "jsonl", sourcetype=sourcetype)
    assert event.timestamps, f"no timestamp extracted for {sourcetype}"
    shift_map = {ts.isoformat(): DELTA for ts in event.timestamps.values()}
    return event.apply_timestamp_shifts(shift_map).raw_data


def test_vpcflow_json_keeps_integer_epoch_seconds():
    out = _shift({"start": 1790000000, "end": 1790000025, "bytes": 10}, "aws:vpcflow:json")
    assert out["start"] == 1790000000 + round(DELTA.total_seconds())
    assert out["end"] == 1790000025 + round(DELTA.total_seconds())
    assert out["bytes"] == 10


def test_github_audit_keeps_integer_epoch_millis():
    out = _shift(
        {"timestamp": 1790000000123, "created_at": 1790000000123, "expires_at": 1790600000123},
        "github:audit",
    )
    for field, original in (("timestamp", 1790000000123), ("created_at", 1790000000123),
                            ("expires_at", 1790600000123)):
        assert isinstance(out[field], int)
        assert out[field] == original + DELTA_MS


def test_crowdstrike_fdr_sensor_keeps_string_epochs():
    out = _shift(
        {"timestamp": "1790000000123", "ProcessStartTime": "1789999999.500",
         "ProcessEndTime": "", "LinuxBootTime": "1789000000"},
        "crowdstrike:fdr",
    )
    assert out["timestamp"] == str(1790000000123 + DELTA_MS)
    assert out["ProcessStartTime"] == f"{1789999999.5 + DELTA.total_seconds():.3f}"
    assert out["ProcessEndTime"] == ""
    assert out["LinuxBootTime"] == str(round(1789000000 + DELTA.total_seconds()))


def test_crowdstrike_fdr_audit_iso_timestamp_and_millis():
    out = _shift(
        {"timestamp": "2026-09-21T12:00:00Z", "UTCTimestamp": "1790000000000",
         "ActionTimestamp": "1790000000000"},
        "crowdstrike:fdr",
    )
    assert out["timestamp"].startswith("2026-10-21T13:02:03.456")
    assert out["UTCTimestamp"] == str(1790000000000 + DELTA_MS)
    assert out["ActionTimestamp"] == str(1790000000000 + DELTA_MS)


@pytest.mark.parametrize("vector_ts", [1790000000, "2026-09-21T12:00:00.123456789Z"])
def test_linux_secure_vector_shifts_line_in_place(vector_ts):
    line = "2026-09-21T12:00:00.123456+00:00 host-a sshd-session[1]: Connection closed"
    out = _shift({"message": line, "timestamp": vector_ts, "host": "host-a"}, "linux_secure:vector")
    assert out["message"] == (
        "2026-10-21T13:02:03.579456+00:00 host-a sshd-session[1]: Connection closed"
    )
    assert type(out["timestamp"]) is type(vector_ts)
    assert out["host"] == "host-a"
