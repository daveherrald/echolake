"""Auto-detect format handler."""

import json
from typing import Iterator, Optional
from ..base import InputFormat
from .text import TextFormat


class AutoFormat(InputFormat):
    """Handler that auto-detects format per line (JSON, XML, or plain text)."""

    def parse(self, content_stream: Iterator[bytes]) -> Iterator[dict]:
        """
        Parse content stream with per-line format detection.

        Tries JSON first for lines starting with '{', XML for lines starting
        with '<', and falls back to plain text otherwise.

        Args:
            content_stream: Iterator yielding chunks of bytes

        Yields:
            Parsed dictionaries
        """
        line_num = 0

        for line in TextFormat._decode_stream(content_stream, encoding='utf-8'):
            line_num += 1
            stripped = line.strip()
            if not stripped:
                continue

            # Try JSON for lines starting with '{'
            if stripped[0] == '{':
                parsed = self._try_json(stripped)
                if parsed is not None:
                    yield parsed
                    continue

            # Try XML for lines starting with '<'
            if stripped[0] == '<':
                parsed = TextFormat._try_parse_xml_line(stripped)
                if parsed is not None:
                    parsed['line_number'] = line_num
                    yield parsed
                    continue

            # Plain text fallback
            yield {'line': line, 'line_number': line_num}

    @staticmethod
    def _try_json(line: str) -> Optional[dict]:
        """
        Try to parse a line as JSON.

        Args:
            line: Text line that might be JSON

        Returns:
            Parsed dict, or None if parsing fails
        """
        try:
            result = json.loads(line)
            if isinstance(result, dict):
                return result
            return None
        except (json.JSONDecodeError, ValueError):
            return None
