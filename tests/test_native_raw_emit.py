"""Tests for --emit raw|bronze (native raw log emission)."""

import glob
import json
import os
import re

import pytest

from echolake.core.config import Config, EchoConfig
from echolake.core.echo import EchoEngine, EnvelopeShapeError
from echolake.inputs.schemas.lakehouse import LakehouseBronzeSchema
from echolake.utils.time import format_timestamp, parse_timestamp


# A Lakewatch bronze row: envelope fields plus the native Windows event in `data`.
# The payload carries its own timestamps, which is the whole point of these tests.
def _bronze_event(epoch_seconds=1782746483.162, millis=1782746483162):
    return {
        "_event_time": "2026-06-29T15:21:23.162Z",
        "_ingest_time": "2026-06-29T15:21:23.162Z",
        "lw_id": "6556602da7b9099062631357",
        "_meta": {"file_name": "cPpjOi.0.json.gz"},
        "data": {
            "Id": 4728,
            "MachineName": "EMU-WS01",
            "LogName": "Security",
            "_time": epoch_seconds,
            "TimeCreated": f"/Date({millis})/",
        },
    }


def _run(tmp_path, emit=None, events=None):
    indir = tmp_path / "in"
    indir.mkdir()
    outdir = tmp_path / "out"
    outdir.mkdir()
    for ev in events or [_bronze_event()]:
        with open(indir / "a.jsonl", "a") as fh:
            fh.write(json.dumps(ev) + "\n")

    emit_line = f"  emit: {emit}\n" if emit else ""
    cfg_yaml = tmp_path / "c.yaml"
    cfg_yaml.write_text(
        f"""
input:
  source:
    type: local
    path: {indir}
  format: jsonl
  schema: lakehouse_bronze
output:
  destination:
    type: local
    path: {outdir}
  format: jsonl
echo:
  target_time: now
{emit_line}"""
    )
    cfg = Config.from_file(str(cfg_yaml))
    stats = EchoEngine(cfg).run()
    out_files = glob.glob(os.path.join(str(outdir), "**", "*.jsonl"), recursive=True)
    lines = [l for f in out_files for l in open(f).read().splitlines() if l.strip()]
    return stats, [json.loads(l) for l in lines]


ENVELOPE_KEYS = ("_event_time", "_ingest_time", "lw_id", "_meta", "data")


# --- emission shape ---------------------------------------------------------

def test_raw_is_the_default(tmp_path):
    _, events = _run(tmp_path)
    assert len(events) == 1
    for key in ENVELOPE_KEYS:
        assert key not in events[0], f"envelope key {key} leaked into raw output"
    assert events[0]["Id"] == 4728
    assert events[0]["MachineName"] == "EMU-WS01"


def test_bronze_keeps_the_envelope(tmp_path):
    _, events = _run(tmp_path, emit="bronze")
    assert len(events) == 1
    for key in ENVELOPE_KEYS:
        assert key in events[0]
    assert events[0]["data"]["Id"] == 4728


def test_raw_preserves_every_non_timestamp_field(tmp_path):
    source = _bronze_event()
    _, events = _run(tmp_path, events=[source])
    emitted = {k: v for k, v in events[0].items() if k not in ("_time", "TimeCreated")}
    original = {k: v for k, v in source["data"].items() if k not in ("_time", "TimeCreated")}
    assert emitted == original


# --- payload timestamps -----------------------------------------------------

def test_payload_timestamps_are_shifted(tmp_path):
    _, events = _run(tmp_path)
    # The source payload is stamped 2026-06-29; a shifted run must not emit it.
    assert events[0]["_time"] != 1782746483.162
    assert events[0]["TimeCreated"] != "/Date(1782746483162)/"


def test_integer_epoch_lands_on_the_nearest_second(tmp_path):
    """A whole-second field rounds rather than truncating toward the second."""
    ev = _bronze_event(epoch_seconds=1782746483.162, millis=1782746483162)
    ev["data"]["_time"] = 1782746483  # int, as some sources write it
    _, events = _run(tmp_path, events=[ev])
    emitted = events[0]["_time"]
    assert isinstance(emitted, int), "integer-seconds fields keep their type"
    millis = int(re.match(r"^/Date\((-?\d+)\)/$", events[0]["TimeCreated"]).group(1))
    # Exact only to its own one-second resolution.
    assert abs(millis / 1000.0 - emitted) <= 0.5


def test_payload_timestamps_agree_after_shift(tmp_path):
    """_time and TimeCreated describe one instant and must not drift apart."""
    _, events = _run(tmp_path)
    millis = int(re.match(r"^/Date\((-?\d+)\)/$", events[0]["TimeCreated"]).group(1))
    assert abs(millis / 1000.0 - events[0]["_time"]) < 0.0005


def test_payload_timestamps_keep_their_native_shape(tmp_path):
    _, events = _run(tmp_path)
    assert isinstance(events[0]["_time"], float), "epoch seconds must stay numeric"
    assert re.match(r"^/Date\(-?\d+\)/$", events[0]["TimeCreated"])


def test_coarse_source_precision_does_not_cause_drift(tmp_path):
    """A source writing `.25` must not round the shift to centiseconds."""
    ev = _bronze_event(epoch_seconds=1782746483.25, millis=1782746483250)
    _, events = _run(tmp_path, events=[ev])
    millis = int(re.match(r"^/Date\((-?\d+)\)/$", events[0]["TimeCreated"]).group(1))
    assert abs(millis / 1000.0 - events[0]["_time"]) < 0.0005


def test_all_events_share_one_shift(tmp_path):
    sources = [
        _bronze_event(1782746483.162, 1782746483162),
        _bronze_event(1782746484.500, 1782746484500),
        _bronze_event(1782746485.25, 1782746485250),
    ]
    _, events = _run(tmp_path, events=sources)
    assert len(events) == 3
    deltas = {round(e["_time"] - s["data"]["_time"], 3) for e, s in zip(events, sources)}
    assert len(deltas) == 1, f"shift was not uniform: {deltas}"


def test_bronze_envelope_timestamps_stay_iso(tmp_path):
    """The envelope keeps its existing ISO8601 writeback, unchanged by this work."""
    _, events = _run(tmp_path, emit="bronze")
    assert isinstance(events[0]["_event_time"], str)
    assert "T" in events[0]["_event_time"]


# --- fail loud --------------------------------------------------------------

def test_missing_data_key_aborts_the_run(tmp_path):
    bad = {
        "_event_time": "2026-06-29T15:21:23.162Z",
        "_ingest_time": "2026-06-29T15:21:23.162Z",
        "lw_id": "x",
        "payload": {"Id": 4728},
    }
    with pytest.raises(EnvelopeShapeError) as exc:
        _run(tmp_path, events=[bad])
    assert "data" in str(exc.value)


def test_mixed_envelope_writes_nothing(tmp_path):
    """A partial write would look like a clean run over an incomplete dataset."""
    bad = {
        "_event_time": "2026-06-29T15:21:23.162Z",
        "_ingest_time": "2026-06-29T15:21:23.162Z",
        "lw_id": "x",
        "payload": {"Id": 1},
    }
    outdir = tmp_path / "out"
    with pytest.raises(EnvelopeShapeError):
        _run(tmp_path, events=[_bronze_event(), bad, _bronze_event()])
    written = glob.glob(os.path.join(str(outdir), "**", "*.jsonl"), recursive=True)
    assert not [l for f in written for l in open(f).read().splitlines() if l.strip()]


def test_bronze_mode_tolerates_a_missing_data_key(tmp_path):
    """Nothing is unwrapped in bronze mode, so the shape is not its business."""
    bad = {
        "_event_time": "2026-06-29T15:21:23.162Z",
        "_ingest_time": "2026-06-29T15:21:23.162Z",
        "lw_id": "x",
        "payload": {"Id": 4728},
    }
    _, events = _run(tmp_path, emit="bronze", events=[bad])
    assert events[0]["payload"] == {"Id": 4728}


# --- config -----------------------------------------------------------------

def test_emit_defaults_to_raw():
    assert EchoConfig().emit == "raw"


def test_emit_rejects_unknown_values():
    with pytest.raises(ValueError):
        EchoConfig(emit="parquet")


@pytest.mark.parametrize("value", ["raw", "bronze"])
def test_emit_accepts_known_values(value):
    assert EchoConfig(emit=value).emit == value


# --- dotnet_date format -----------------------------------------------------

def test_dotnet_date_roundtrip():
    wire = "/Date(1782746483162)/"
    assert format_timestamp(parse_timestamp(wire, "dotnet_date"), "dotnet_date") == wire


def test_dotnet_date_parses_trailing_offset():
    with_offset = parse_timestamp("/Date(1782746483162-0700)/", "dotnet_date")
    plain = parse_timestamp("/Date(1782746483162)/", "dotnet_date")
    assert with_offset == plain


def test_dotnet_date_rejects_other_strings():
    with pytest.raises(ValueError):
        parse_timestamp("2026-06-29T15:21:23Z", "dotnet_date")


def test_dotnet_date_rounds_rather_than_truncates():
    """Truncating here would drift a millisecond from the epoch-seconds path."""
    dt = parse_timestamp(1782746483.1699, "unix_seconds")
    assert format_timestamp(dt, "dotnet_date") == "/Date(1782746483170)/"


# --- schema patterns --------------------------------------------------------

def test_schema_extracts_payload_timestamps():
    ev = LakehouseBronzeSchema().extract_event(_bronze_event(), "jsonl")
    assert "data._time" in ev.timestamps
    assert "data.TimeCreated" in ev.timestamps
    assert ev.field_preserve["data._time"] is True
    assert ev.field_formats["data.TimeCreated"] == "dotnet_date"


def test_payload_timestamps_are_never_the_base():
    """The envelope owns the base timestamp; payload fields only follow it."""
    patterns = LakehouseBronzeSchema().get_timestamp_patterns()
    for p in patterns:
        if p["field"].startswith("data."):
            assert p["is_base"] is False


# --- raw text inside the payload -------------------------------------------

def test_payload_raw_text_is_shifted(tmp_path):
    """A squid line's leading epoch is the timestamp its parser reads."""
    ev = _bronze_event()
    ev["data"]["_raw"] = "1782746483.162     31 192.168.4.26 TCP_MISS/200 7265 GET http://x/"
    _, events = _run(tmp_path, events=[ev])
    assert not events[0]["_raw"].startswith("1782746483.162"), "_raw kept its original time"


def test_payload_raw_epoch_tracks_the_time_field(tmp_path):
    ev = _bronze_event()
    ev["data"]["_raw"] = "1782746483.162     31 192.168.4.26 TCP_MISS/200 7265 GET http://x/"
    _, events = _run(tmp_path, events=[ev])
    assert abs(float(events[0]["_raw"].split()[0]) - events[0]["_time"]) < 0.002


def test_payload_without_any_timestamp_aborts(tmp_path):
    """Unwrapping would strip the only shifted time, leaving a stale event."""
    ev = _bronze_event()
    del ev["data"]["_time"]
    del ev["data"]["TimeCreated"]
    with pytest.raises(EnvelopeShapeError) as exc:
        _run(tmp_path, events=[ev])
    assert "original capture time" in str(exc.value)


def test_zeek_ts_is_recognised(tmp_path):
    ev = _bronze_event()
    ev["data"] = {"uid": "C1", "proto": "tcp", "ts": 1782746483.42791}
    _, events = _run(tmp_path, events=[ev])
    assert events[0]["ts"] != 1782746483.42791
    assert isinstance(events[0]["ts"], float)
