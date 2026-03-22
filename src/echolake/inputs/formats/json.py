"""JSON and JSONL format handlers."""

import json
from typing import Iterator
from ..base import InputFormat


class JSONFormat(InputFormat):
    """Handler for JSON format (single object or array)."""

    def parse(self, content_stream: Iterator[bytes]) -> Iterator[dict]:
        """
        Parse JSON content stream.

        Note: JSON requires full document, so chunks are accumulated.
        However, individual records are still yielded one at a time.

        Args:
            content_stream: Iterator yielding chunks of bytes

        Yields:
            Parsed dictionaries
        """
        try:
            # Accumulate all chunks (JSON needs complete document)
            chunks = []
            for chunk in content_stream:
                chunks.append(chunk)

            # Decode and parse
            text = b''.join(chunks).decode('utf-8')
            data = json.loads(text)

            # Stream individual records
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        yield item
            elif isinstance(data, dict):
                yield data

        except (json.JSONDecodeError, UnicodeDecodeError):
            # Skip malformed JSON
            pass


class JSONLFormat(InputFormat):
    """Handler for JSONL format (newline-delimited JSON)."""

    def parse(self, content_stream: Iterator[bytes]) -> Iterator[dict]:
        """
        Parse JSONL content stream line by line (streaming, line-buffered).

        Args:
            content_stream: Iterator yielding chunks of bytes

        Yields:
            Parsed dictionaries (one per line)
        """
        try:
            # Stream lines with buffering
            for line_text in self._decode_stream(content_stream):
                line_text = line_text.strip()
                if not line_text:
                    continue

                try:
                    data = json.loads(line_text)
                    if isinstance(data, dict):
                        yield data
                except json.JSONDecodeError:
                    # Skip malformed lines
                    continue

        except UnicodeDecodeError:
            # Skip files with encoding issues
            pass

    @staticmethod
    def _decode_stream(byte_stream: Iterator[bytes]) -> Iterator[str]:
        """
        Decode byte stream to text lines (handles partial line boundaries).

        Args:
            byte_stream: Iterator yielding byte chunks

        Yields:
            Complete text lines
        """
        buffer = b''

        for chunk in byte_stream:
            buffer += chunk

            # Split on newlines, keep incomplete last line in buffer
            lines = buffer.split(b'\n')
            buffer = lines[-1]  # Keep incomplete line

            # Yield complete lines
            for line in lines[:-1]:
                try:
                    yield line.decode('utf-8')
                except UnicodeDecodeError:
                    # Skip malformed lines
                    continue

        # Yield final line if exists
        if buffer:
            try:
                yield buffer.decode('utf-8')
            except UnicodeDecodeError:
                pass
