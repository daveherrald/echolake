"""JSON output format handlers."""

import json
from typing import List
from ..base import OutputFormat
from ...models.event import Event


class JSONOutputFormat(OutputFormat):
    """Output format for JSON (array of objects)."""

    def format_event(self, event: Event) -> str:
        """
        Format single event as JSON.

        Args:
            event: Event to format

        Returns:
            JSON string
        """
        return json.dumps(event.raw_data, separators=(',', ':'))

    def format_batch(self, events: List[Event]) -> str:
        """
        Format batch as JSON array.

        Args:
            events: List of events

        Returns:
            JSON array string
        """
        data = [event.raw_data for event in events]
        return json.dumps(data, separators=(',', ':'))


class JSONLOutputFormat(OutputFormat):
    """Output format for JSONL (newline-delimited JSON)."""

    def format_event(self, event: Event) -> str:
        """
        Format single event as JSON line.

        Args:
            event: Event to format

        Returns:
            JSON line (no newline at end)
        """
        return json.dumps(event.raw_data, separators=(',', ':'))

    def format_batch(self, events: List[Event]) -> str:
        """
        Format batch as JSONL.

        Args:
            events: List of events

        Returns:
            JSONL string (newline-separated)
        """
        lines = [self.format_event(event) for event in events]
        return '\n'.join(lines)
