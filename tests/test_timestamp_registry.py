"""Tests for the public timestamp registry support check."""

from echolake.inputs.timestamp_registry import TimestampRegistry


def test_supports_uses_all_lookup_forms(tmp_path):
    registry_path = tmp_path / "timestamps.yaml"
    registry_path.write_text(
        """
WinEventLog:Security:
  - field: TimeCreated
    format: iso8601
XmlWinEventLog:
  - field: Event.System.TimeCreated.SystemTime
    format: iso8601
registered-but-empty: []
""".lstrip()
    )
    registry = TimestampRegistry(registry_path)

    assert registry.supports("WinEventLog:Security")
    assert registry.supports("wineventlog:security")
    assert registry.supports("XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
    assert registry.supports("registered-but-empty")
    assert not registry.supports("unknown")
    assert not registry.supports(None)
