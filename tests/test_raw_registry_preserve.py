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
        {"@timestamp": 1790000000123, "created_at": 1790000000123, "expires_at": 1790600000123},
        "github:audit",
    )
    for field, original in (("@timestamp", 1790000000123), ("created_at", 1790000000123),
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
    assert out["timestamp"] == "2026-10-21T13:02:03Z"  # whole-second Z input
    assert out["UTCTimestamp"] == str(1790000000000 + DELTA_MS)
    assert out["ActionTimestamp"] == str(1790000000000 + DELTA_MS)


def test_crowdstrike_fdr_sensor_export_shifts_device_snapshot():
    # The falcon:edr shape (sensor events with the device record merged in)
    # resolves under the canonical crowdstrike:fdr sourcetype.
    out = _shift(
        {"timestamp": "1786624827440", "ProcessStartTime": "1786624826.892",
         "OciContainerStartTime": "1786614514.447",
         "device_first_seen": "2026-08-11T14:21:40Z",
         "ChangeTimeNs": "1786624739297074819", "device_hostname": "node-a"},
        "crowdstrike:fdr",
    )
    assert out["timestamp"] == str(1786624827440 + DELTA_MS)
    assert out["ProcessStartTime"] == f"{1786624826.892 + DELTA.total_seconds():.3f}"
    assert out["OciContainerStartTime"] == f"{1786614514.447 + DELTA.total_seconds():.3f}"
    assert out["device_first_seen"] == "2026-09-10T15:23:43Z"
    # No registry format for epoch nanoseconds; left to the optional payload scan.
    assert out["ChangeTimeNs"] == "1786624739297074819"
    assert out["device_hostname"] == "node-a"


def test_kubernetes_audit_shifts_received_and_stage_timestamps():
    out = _shift(
        {"requestReceivedTimestamp": "2026-08-11T23:51:50.213823Z",
         "stageTimestamp": "2026-08-11T23:51:50.218925Z", "verb": "get"},
        "kubernetes:audit",
    )
    assert out["requestReceivedTimestamp"] == "2026-09-11T00:53:53.669823Z"
    assert out["stageTimestamp"] == "2026-09-11T00:53:53.674925Z"
    assert out["verb"] == "get"


def test_github_audit_shifts_iso_run_times():
    # Workflow-run records carry ISO started_at alongside the epoch-ms fields.
    out = _shift(
        {"@timestamp": 1786614495688, "created_at": 1786614495688,
         "started_at": "2026-08-13T09:47:50.000Z"},
        "github:audit",
    )
    for field in ("@timestamp", "created_at"):
        assert isinstance(out[field], int)
        assert out[field] == 1786614495688 + DELTA_MS
    assert out["started_at"] == "2026-09-12T10:49:53.456Z"


def test_iso_preservation_keeps_suffix_style_and_precision():
    # Z stays Z, whole seconds stay whole (rounded to the nearest second),
    # and fractional precision matches the original.
    out = _shift(
        {"eventTime": "2026-08-13T12:29:39Z",  # whole seconds, Z
         "time_dt": "2026-08-13T12:29:39.500Z"},  # 3 digits, Z
        "aws:cloudtrail",
    )
    assert out["eventTime"] == "2026-09-12T13:31:42Z"  # .456 rounds down
    assert out["time_dt"] == "2026-09-12T13:31:42.956Z"  # .500 + .456 = .956


def test_linux_secure_shifts_raw_line_in_place():
    line = "2026-09-21T12:00:00.123456+00:00 host-a sshd-session[1]: Connection closed"
    out = _shift({"line": line}, "linux_secure")
    assert out["line"] == (
        "2026-10-21T13:02:03.579456+00:00 host-a sshd-session[1]: Connection closed"
    )
