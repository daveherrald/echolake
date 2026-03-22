"""Tests for stdout destination."""

import pytest
import sys
from io import StringIO

from echolake.outputs.destinations.stdout import StdoutDestination


class TestStdoutDestination:
    """Test StdoutDestination class."""

    def test_init(self):
        """Test initialization."""
        dest = StdoutDestination()
        assert dest is not None

    def test_write_single_event(self, capsys):
        """Test writing a single event."""
        dest = StdoutDestination()

        events = ['{"timestamp": "2024-01-01T10:00:00Z", "message": "test"}']
        dest.write("test-file", events)

        captured = capsys.readouterr()
        assert '{"timestamp": "2024-01-01T10:00:00Z", "message": "test"}' in captured.out

    def test_write_multiple_events(self, capsys):
        """Test writing multiple events."""
        dest = StdoutDestination()

        events = [
            '{"id": 1, "message": "first"}',
            '{"id": 2, "message": "second"}',
            '{"id": 3, "message": "third"}',
        ]
        dest.write("test-file", events)

        captured = capsys.readouterr()
        output_lines = captured.out.strip().split('\n')

        assert len(output_lines) == 3
        assert '{"id": 1, "message": "first"}' in output_lines[0]
        assert '{"id": 2, "message": "second"}' in output_lines[1]
        assert '{"id": 3, "message": "third"}' in output_lines[2]

    def test_write_empty_events(self, capsys):
        """Test writing empty event list."""
        dest = StdoutDestination()

        events = []
        dest.write("test-file", events)

        captured = capsys.readouterr()
        assert captured.out == ""

    def test_write_preserves_order(self, capsys):
        """Test that event order is preserved."""
        dest = StdoutDestination()

        events = [f'{{"event": {i}}}' for i in range(10)]
        dest.write("test-file", events)

        captured = capsys.readouterr()
        output_lines = captured.out.strip().split('\n')

        for i, line in enumerate(output_lines):
            assert f'"event": {i}' in line

    def test_write_with_newlines_in_events(self, capsys):
        """Test writing events that might contain newlines."""
        dest = StdoutDestination()

        # Events should not contain newlines themselves
        # (they're serialized JSON on one line)
        events = [
            '{"message": "line 1"}',
            '{"message": "line 2"}',
        ]
        dest.write("test-file", events)

        captured = capsys.readouterr()
        output_lines = captured.out.strip().split('\n')

        assert len(output_lines) == 2

    def test_close(self):
        """Test close method (should not raise)."""
        dest = StdoutDestination()
        dest.close()  # Should not raise

    def test_multiple_write_calls(self, capsys):
        """Test multiple calls to write."""
        dest = StdoutDestination()

        # First write
        dest.write("file1", ['{"batch": 1}'])
        captured1 = capsys.readouterr()
        assert '{"batch": 1}' in captured1.out

        # Second write
        dest.write("file2", ['{"batch": 2}'])
        captured2 = capsys.readouterr()
        assert '{"batch": 2}' in captured2.out

    def test_write_ignores_source_file_id(self, capsys):
        """Test that source_file_id is ignored (stdout doesn't care)."""
        dest = StdoutDestination()

        # Write with different source file IDs
        dest.write("file1.log", ['{"data": "a"}'])
        dest.write("file2.log", ['{"data": "b"}'])
        dest.write("/path/to/file3.log", ['{"data": "c"}'])

        captured = capsys.readouterr()
        output_lines = captured.out.strip().split('\n')

        # All events should be written regardless of source file ID
        assert len(output_lines) == 3
        assert '{"data": "a"}' in output_lines[0]
        assert '{"data": "b"}' in output_lines[1]
        assert '{"data": "c"}' in output_lines[2]

    def test_write_ignores_batch_size(self, capsys):
        """Test that batch_size parameter is ignored."""
        dest = StdoutDestination()

        events = [f'{{"event": {i}}}' for i in range(10)]

        # batch_size is ignored, all events written at once
        dest.write("test-file", events, batch_size=2)

        captured = capsys.readouterr()
        output_lines = captured.out.strip().split('\n')

        # All events should be written
        assert len(output_lines) == 10


class TestStdoutIntegration:
    """Integration tests for stdout destination."""

    def test_can_be_imported_from_destinations(self):
        """Test that StdoutDestination can be imported."""
        from echolake.outputs.destinations import StdoutDestination
        assert StdoutDestination is not None

    def test_get_destination_factory(self):
        """Test that stdout can be created via factory."""
        from echolake.outputs.destinations import get_destination

        dest = get_destination("stdout")
        assert isinstance(dest, StdoutDestination)

    def test_get_destination_factory_case_insensitive(self):
        """Test that factory is case-insensitive."""
        from echolake.outputs.destinations import get_destination

        dest1 = get_destination("stdout")
        dest2 = get_destination("STDOUT")
        dest3 = get_destination("StdOut")

        assert isinstance(dest1, StdoutDestination)
        assert isinstance(dest2, StdoutDestination)
        assert isinstance(dest3, StdoutDestination)

    def test_realistic_json_events(self, capsys):
        """Test with realistic JSON log events."""
        dest = StdoutDestination()

        events = [
            '{"timestamp": "2024-01-01T10:00:00Z", "level": "INFO", "message": "User login", "user_id": "user123"}',
            '{"timestamp": "2024-01-01T10:00:01Z", "level": "WARN", "message": "Failed attempt", "user_id": "user456"}',
            '{"timestamp": "2024-01-01T10:00:02Z", "level": "ERROR", "message": "Access denied", "user_id": "user789"}',
        ]

        dest.write("auth.log", events)

        captured = capsys.readouterr()
        output = captured.out

        # Verify all events are in output
        assert "User login" in output
        assert "Failed attempt" in output
        assert "Access denied" in output
        assert "user123" in output
        assert "user456" in output
        assert "user789" in output
