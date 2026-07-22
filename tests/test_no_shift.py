"""Tests for --no-shift passthrough mode (skip Phase 1 scan, no timestamp changes)."""

import json
import glob
import os

from echolake.core.config import Config
from echolake.core.echo import EchoEngine


def _run(tmp_path, no_shift: bool):
    indir = tmp_path / "in"
    indir.mkdir()
    outdir = tmp_path / "out"
    outdir.mkdir()
    event = {
        "_time": "2020-01-01T00:00:00+00:00",
        "_raw": "01/01/2020 00:00:00 AM LogName=Test hello",
        "sourcetype": "WinEventLog:Application",
        "host": "h1",
    }
    (indir / "a.jsonl").write_text(json.dumps(event) + "\n")

    cfg_yaml = tmp_path / "c.yaml"
    cfg_yaml.write_text(
        f"""
input:
  source:
    type: local
    path: {indir}
  format: jsonl
  schema: raw
output:
  destination:
    type: local
    path: {outdir}
  format: jsonl
echo:
  target_time: now
  no_shift: {"true" if no_shift else "false"}
"""
    )
    cfg = Config.from_file(str(cfg_yaml))
    stats = EchoEngine(cfg).run()
    out_files = glob.glob(os.path.join(str(outdir), "**", "*.jsonl"), recursive=True)
    assert out_files, "no output written"
    lines = [l for f in out_files for l in open(f).read().splitlines() if l.strip()]
    return stats, [json.loads(l) for l in lines]


def test_no_shift_leaves_timestamps_untouched(tmp_path):
    stats, events = _run(tmp_path, no_shift=True)
    assert len(events) == 1
    # _time and embedded _raw timestamp are both unchanged
    assert events[0]["_time"] == "2020-01-01T00:00:00+00:00"
    assert "01/01/2020 00:00:00 AM" in events[0]["_raw"]
    # Phase 1 scan was skipped: no timestamp range was computed
    assert stats.original_earliest_time is None


def test_default_shift_changes_timestamps(tmp_path):
    # Control: without no_shift, the 2020 event is shifted forward (scan runs).
    stats, events = _run(tmp_path, no_shift=False)
    assert len(events) == 1
    assert events[0]["_time"] != "2020-01-01T00:00:00+00:00"
    assert stats.original_earliest_time is not None
