"""Event accounting for in-place Windows Event XML replay."""

import gzip

import pytest

from echolake.core.config import (
    Config,
    DatasetConfig,
    EchoConfig,
    OutputConfig,
    OutputDestinationConfig,
)
from echolake.core.echo import EchoEngine


EVENT = """<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-03-13T17:40:06.006000Z" />
      <Channel>Security</Channel>
    </System>
  </Event>
</Events>
"""
EMPTY = """<?xml version="1.0" encoding="utf-8"?>
<Events>
</Events>
"""
TRICKY = """<?xml version="1.0" encoding="utf-8"?>
<Events xmlns:provider="urn:provider">
  <!-- <Event /> -->
  <Metadata><![CDATA[<Event />]]><provider:Event /></Metadata>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><TimeCreated SystemTime="2026-03-13T17:40:06.006000Z" /><Channel>Security</Channel></System></Event><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>2</EventID><TimeCreated SystemTime="2026-03-13T17:40:07.006000Z" /><Channel>Security</Channel></System></Event>
</Events>
"""
SELF_CLOSING = """<?xml version="1.0" encoding="utf-8"?>
<Events><Event /></Events>
"""
UTF16_EVENT = EVENT.replace('encoding="utf-8"', 'encoding="utf-16"')
INVALID_TIMESTAMP = EVENT.replace(
    "2026-03-13T17:40:06.006000Z",
    "not-a-time",
)
MISLEADING_COMMENT = EVENT.replace(
    "<Events>",
    '<Events>\n  <!-- <TimeCreated SystemTime="2026-03-13T17:40:05.006000Z" /> -->',
)
DISTRIBUTED_TIMESTAMPS = """<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <TimeCreated SystemTime="2026-03-13T17:40:06.006000Z" />
      <TimeCreated SystemTime="2026-03-13T17:40:07.006000Z" />
    </System>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>2</EventID></System>
  </Event>
</Events>
"""


def write_gzip(path, text, encoding="utf-8"):
    with gzip.open(path, "wb") as stream:
        stream.write(text.encode(encoding))


def build_dataset(
    tmp_path,
    *,
    populated,
    event_xml=EVENT,
    event_count=1,
    sourcetype="XmlWinEventLog",
    event_encoding="utf-8",
):
    dataset_dir = tmp_path / "dataset"
    data_dir = dataset_dir / "data"
    data_dir.mkdir(parents=True)
    entries = []
    if populated:
        write_gzip(data_dir / "security.xml.gz", event_xml, encoding=event_encoding)
        entries.append(
            "  - path: data/security.xml.gz\n"
            "    format: xml\n"
            "    schema: raw\n"
            f"    sourcetype: {sourcetype}\n"
            f"    event_count: {event_count}\n"
        )
    write_gzip(data_dir / "application.xml.gz", EMPTY)
    entries.append(
        "  - path: data/application.xml.gz\n"
        "    format: xml\n"
        "    schema: raw\n"
        "    sourcetype: XmlWinEventLog\n"
        "    event_count: 0\n"
    )
    (dataset_dir / "dataset.yaml").write_text(
        "metadata:\n"
        "  name: xml-accounting-fixture\n"
        "  version: 1.0.0\n"
        "  description: Windows Event XML accounting fixture\n"
        "  timestamp_range:\n"
        "    earliest: '2026-03-13T17:40:06.006000Z'\n"
        "    latest: '2026-03-13T17:40:06.006000Z'\n"
        "    field: System/TimeCreated/@SystemTime\n"
        "files:\n"
        "  bundled:\n"
        + "".join(entries)
        + "defaults:\n"
        "  schema: raw\n",
        encoding="utf-8",
    )
    return dataset_dir


def run_dataset(tmp_path, *, populated, no_shift, shift_payload=False, **dataset_options):
    dataset_dir = build_dataset(tmp_path, populated=populated, **dataset_options)
    output_dir = tmp_path / "output"
    config = Config(
        dataset=DatasetConfig(ref=f"local:{dataset_dir}"),
        echo=EchoConfig(
            target_time="2026-11-01T00:00:00Z",
            prevent_future=False,
            no_shift=no_shift,
            shift_payload=shift_payload,
        ),
        output=OutputConfig(
            destination=OutputDestinationConfig(
                type="local",
                path=str(output_dir),
                path_template="{filename}",
            ),
            format="text",
            compression="gzip",
        ),
    )
    return EchoEngine(config).run()


@pytest.mark.parametrize(
    ("no_shift", "expected_modified"),
    [(False, 1), (True, 0)],
)
def test_xml_event_count_ignores_empty_wrappers(tmp_path, no_shift, expected_modified):
    stats = run_dataset(tmp_path, populated=True, no_shift=no_shift)

    assert stats.event_count == 1
    assert stats.events_modified == expected_modified
    assert stats.errors == 0


def test_empty_xml_dataset_reports_zero_events(tmp_path):
    stats = run_dataset(tmp_path, populated=False, no_shift=False)

    assert stats.event_count == 0
    assert stats.events_modified == 0
    assert stats.errors == 0


def test_compact_xml_counts_and_shifts_each_direct_event(tmp_path):
    stats = run_dataset(
        tmp_path,
        populated=True,
        no_shift=False,
        event_xml=TRICKY,
        event_count=2,
    )

    assert stats.event_count == 2
    assert stats.events_modified == 2
    assert stats.errors == 0


def test_xml_sourcetype_lookup_is_case_insensitive(tmp_path):
    stats = run_dataset(
        tmp_path,
        populated=True,
        no_shift=True,
        sourcetype="xmlwineventlog",
    )

    assert stats.event_count == 1
    assert stats.events_modified == 0
    assert stats.errors == 0


def test_xml_sourcetype_channel_suffix_uses_xml_accounting(tmp_path):
    stats = run_dataset(
        tmp_path,
        populated=True,
        no_shift=True,
        sourcetype="XmlWinEventLog:Security",
    )

    assert stats.event_count == 1
    assert stats.events_modified == 0
    assert stats.errors == 0


def test_xml_payload_shift_reports_modified_events(tmp_path):
    stats = run_dataset(
        tmp_path,
        populated=True,
        no_shift=False,
        shift_payload=True,
    )

    assert stats.event_count == 1
    assert stats.events_modified == 1
    assert stats.errors == 0


def test_self_closing_xml_event_is_counted_in_passthrough(tmp_path):
    stats = run_dataset(
        tmp_path,
        populated=True,
        no_shift=True,
        event_xml=SELF_CLOSING,
    )

    assert stats.event_count == 1
    assert stats.events_modified == 0
    assert stats.errors == 0


def test_utf16_xml_fails_instead_of_corrupting_output(tmp_path):
    with pytest.raises(ValueError, match="requires UTF-8 input"):
        run_dataset(
            tmp_path,
            populated=True,
            no_shift=True,
            event_xml=UTF16_EVENT,
            event_encoding="utf-16",
        )


def test_default_xml_shift_rejects_timestamp_match_outside_events(tmp_path):
    with pytest.raises(
        ValueError,
        match="found 2 event timestamp matches for 1 event timestamps",
    ):
        run_dataset(
            tmp_path,
            populated=True,
            no_shift=False,
            event_xml=MISLEADING_COMMENT,
        )


def test_payload_shift_requires_timestamp_for_each_xml_event(tmp_path):
    with pytest.raises(ValueError, match="requires exactly one System/TimeCreated"):
        run_dataset(
            tmp_path,
            populated=True,
            no_shift=False,
            shift_payload=True,
            event_xml=SELF_CLOSING,
        )


@pytest.mark.parametrize("shift_payload", [False, True])
def test_xml_shift_rejects_invalid_system_time(tmp_path, shift_payload):
    with pytest.raises(ValueError, match="Invalid Windows Event XML SystemTime"):
        run_dataset(
            tmp_path,
            populated=True,
            no_shift=False,
            shift_payload=shift_payload,
            event_xml=INVALID_TIMESTAMP,
        )


def test_xml_passthrough_preserves_invalid_system_time_bytes(tmp_path):
    stats = run_dataset(
        tmp_path,
        populated=True,
        no_shift=True,
        event_xml=INVALID_TIMESTAMP,
    )

    outputs = list((tmp_path / "output").rglob("security.xml.gz"))
    assert len(outputs) == 1
    with gzip.open(outputs[0], "rb") as stream:
        assert stream.read() == INVALID_TIMESTAMP.encode("utf-8")
    assert stats.event_count == 1
    assert stats.events_modified == 0
    assert stats.errors == 0


@pytest.mark.parametrize("shift_payload", [False, True])
def test_xml_shift_requires_one_timestamp_in_each_event(tmp_path, shift_payload):
    with pytest.raises(ValueError, match="exactly one System/TimeCreated"):
        run_dataset(
            tmp_path,
            populated=True,
            no_shift=False,
            shift_payload=shift_payload,
            event_xml=DISTRIBUTED_TIMESTAMPS,
            event_count=2,
        )
