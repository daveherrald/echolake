"""Tests for the hardened XML format handler.

Regression coverage for the bug where the handler matched the event element by
exact tag, so namespaced and capitalized documents (Windows Event XML, whose
elements are `{...}Event`) silently parsed zero events.
"""

import pytest

from echolake.inputs.formats.xml import XMLFormat

WINEVT = b"""<?xml version="1.0" encoding="utf-8"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>1</EventID><Computer>HOST1</Computer></System>
    <EventData><Data Name="Image">process.exe</Data></EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>3</EventID></System>
  </Event>
</Events>"""


def test_parses_namespaced_capitalized_events():
    events = list(XMLFormat().parse([WINEVT]))
    assert len(events) == 2  # was 0 before the fix


def test_namespace_stripped_from_keys():
    events = list(XMLFormat().parse([WINEVT]))
    assert "System" in events[0]
    # no namespace braces survive in any key
    assert all("{" not in k for k in events[0])


def test_custom_event_tag_matches_case_insensitively():
    doc = b"<root><RECORD><a>1</a></RECORD><RECORD><a>2</a></RECORD></root>"
    events = list(XMLFormat(event_tag="record").parse([doc]))
    assert len(events) == 2


def test_fail_loud_when_no_event_matches():
    # Default event tag 'event' matches none of these <record> elements.
    doc = b"<logs><record><t>x</t></record></logs>"
    with pytest.raises(ValueError):
        list(XMLFormat().parse([doc]))


def test_fail_loud_on_malformed_xml():
    with pytest.raises(ValueError):
        list(XMLFormat().parse([b"<Events><Event></Events>"]))  # unclosed <Event>


def test_empty_input_yields_nothing_without_error():
    assert list(XMLFormat().parse([b"   "])) == []
    assert list(XMLFormat().parse([b""])) == []
