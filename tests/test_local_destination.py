"""Tests for local destination with sourcetype routing."""

import pytest
from pathlib import Path

from echolake.outputs.destinations.local import LocalDestination


class TestLocalDestinationSourcetype:
    """Test sourcetype-based output routing in LocalDestination."""

    def test_sourcetype_in_path_template(self, tmp_path):
        """Test that {sourcetype} is replaced in path template."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{sourcetype}/{filename}"
        )
        events = ['{"msg": "test"}']
        dest.write("test.jsonl", events, metadata={"sourcetype": "WinEventLog-Security"})

        output_file = tmp_path / "WinEventLog-Security" / "test.jsonl"
        assert output_file.exists()
        assert output_file.read_text().strip() == '{"msg": "test"}'

    def test_sourcetype_colon_normalized(self, tmp_path):
        """Test that colons in sourcetype are normalized to hyphens."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{sourcetype}/{filename}"
        )
        events = ['{"msg": "test"}']
        dest.write("test.jsonl", events, metadata={"sourcetype": "WinEventLog:Security"})

        output_file = tmp_path / "WinEventLog-Security" / "test.jsonl"
        assert output_file.exists()

    def test_sourcetype_slash_normalized(self, tmp_path):
        """Test that slashes in sourcetype are normalized to hyphens."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{sourcetype}/{filename}"
        )
        events = ['{"msg": "test"}']
        dest.write("test.jsonl", events, metadata={"sourcetype": "stream/dns"})

        output_file = tmp_path / "stream-dns" / "test.jsonl"
        assert output_file.exists()

    def test_sourcetype_defaults_to_unknown(self, tmp_path):
        """Test that missing sourcetype defaults to 'unknown'."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{sourcetype}/{filename}"
        )
        events = ['{"msg": "test"}']
        dest.write("test.jsonl", events)  # No metadata

        output_file = tmp_path / "unknown" / "test.jsonl"
        assert output_file.exists()

    def test_sourcetype_defaults_when_metadata_empty(self, tmp_path):
        """Test that sourcetype defaults to 'unknown' when metadata has no sourcetype."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{sourcetype}/{filename}"
        )
        events = ['{"msg": "test"}']
        dest.write("test.jsonl", events, metadata={})

        output_file = tmp_path / "unknown" / "test.jsonl"
        assert output_file.exists()

    def test_template_without_sourcetype(self, tmp_path):
        """Test that templates without {sourcetype} still work."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{filename}"
        )
        events = ['{"msg": "test"}']
        dest.write("test.jsonl", events, metadata={"sourcetype": "syslog"})

        output_file = tmp_path / "test.jsonl"
        assert output_file.exists()

    def test_multiple_sourcetypes(self, tmp_path):
        """Test writing to different sourcetype directories."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{sourcetype}/{filename}"
        )

        dest.write("events.jsonl", ['{"src": "win"}'], metadata={"sourcetype": "WinEventLog-Security"})
        dest.write("events.jsonl", ['{"src": "dns"}'], metadata={"sourcetype": "stream-dns"})
        dest.write("events.jsonl", ['{"src": "iis"}'], metadata={"sourcetype": "iis"})

        assert (tmp_path / "WinEventLog-Security" / "events.jsonl").exists()
        assert (tmp_path / "stream-dns" / "events.jsonl").exists()
        assert (tmp_path / "iis" / "events.jsonl").exists()
