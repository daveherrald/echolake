"""Text output format handler."""

from typing import List
from ..base import OutputFormat
from ...models.event import Event


class TextOutputFormat(OutputFormat):
    """Output format for plain text."""

    def format_event(self, event: Event) -> str:
        """
        Format single event as text.

        Args:
            event: Event to format

        Returns:
            Text string
        """
        if isinstance(event.raw_data, dict) and 'line' in event.raw_data:
            return event.raw_data['line']
        elif isinstance(event.raw_data, str):
            return event.raw_data
        else:
            return str(event.raw_data)

    def format_batch(self, events: List[Event]) -> str:
        """
        Format batch as text lines.

        Args:
            events: List of events

        Returns:
            Newline-separated text
        """
        lines = [self.format_event(event) for event in events]
        return '\n'.join(lines)
