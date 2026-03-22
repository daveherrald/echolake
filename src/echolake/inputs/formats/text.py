"""Text format handler."""

import xml.etree.ElementTree as ET
from typing import Iterator, Optional
from ..base import InputFormat


class TextFormat(InputFormat):
    """Handler for plain text format (line-by-line)."""

    def parse(self, content_stream: Iterator[bytes]) -> Iterator[dict]:
        """
        Parse text content stream line by line (streaming, line-buffered).
        Auto-detects and parses XML lines (e.g., Windows Event Log XML).

        Args:
            content_stream: Iterator yielding chunks of bytes

        Yields:
            Dictionaries with 'line' key containing each line, or parsed XML dict
        """
        line_num = 0

        try:
            # Stream lines with UTF-8 decoding
            for line in self._decode_stream(content_stream, encoding='utf-8'):
                line_num += 1
                stripped = line.strip()
                if stripped:  # Skip empty lines
                    # Auto-detect XML lines (Windows Event Log format)
                    if stripped.startswith('<Event') or stripped.startswith('<?xml'):
                        parsed = self._try_parse_xml_line(stripped)
                        if parsed:
                            parsed['line_number'] = line_num
                            yield parsed
                        else:
                            # If XML parsing fails, yield as plain text
                            yield {
                                'line': line,
                                'line_number': line_num,
                            }
                    else:
                        yield {
                            'line': line,
                            'line_number': line_num,
                        }

        except UnicodeDecodeError:
            # Try latin-1 as fallback
            try:
                line_num = 0
                for line in self._decode_stream(content_stream, encoding='latin-1'):
                    line_num += 1
                    stripped = line.strip()
                    if stripped:
                        if stripped.startswith('<Event') or stripped.startswith('<?xml'):
                            parsed = self._try_parse_xml_line(stripped)
                            if parsed:
                                parsed['line_number'] = line_num
                                yield parsed
                            else:
                                yield {
                                    'line': line,
                                    'line_number': line_num,
                                }
                        else:
                            yield {
                                'line': line,
                                'line_number': line_num,
                            }
            except Exception:
                # Skip files with encoding issues
                pass

    @staticmethod
    def _decode_stream(byte_stream: Iterator[bytes], encoding: str = 'utf-8') -> Iterator[str]:
        """
        Decode byte stream to text lines (handles partial line boundaries).

        Args:
            byte_stream: Iterator yielding byte chunks
            encoding: Text encoding to use

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
                    yield line.decode(encoding)
                except UnicodeDecodeError:
                    # Skip malformed lines
                    continue

        # Yield final line if exists
        if buffer:
            try:
                yield buffer.decode(encoding)
            except UnicodeDecodeError:
                pass

    @staticmethod
    def _try_parse_xml_line(line: str) -> Optional[dict]:
        """
        Try to parse a line as XML and convert to dict.

        Args:
            line: Text line that might be XML

        Returns:
            Parsed XML as dict, or None if parsing fails
        """
        try:
            root = ET.fromstring(line)
            return TextFormat._xml_element_to_dict(root)
        except ET.ParseError:
            return None

    @staticmethod
    def _xml_element_to_dict(element: ET.Element) -> dict:
        """
        Convert XML element to dictionary, flattening structure.
        Special handling for Windows Event Log XML format.

        Args:
            element: XML element

        Returns:
            Dictionary representation
        """
        result = {}

        # Remove namespace from tag
        tag = element.tag.split('}')[-1] if '}' in element.tag else element.tag

        # Add attributes
        if element.attrib:
            for key, value in element.attrib.items():
                result[key] = value

        # Handle Windows Event Log structure
        for child in element:
            child_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag

            # Special handling for System and EventData sections
            if child_tag in ['System', 'EventData']:
                child_dict = TextFormat._xml_element_to_dict(child)
                # Flatten nested dict into result
                for k, v in child_dict.items():
                    if k not in result:  # Don't overwrite
                        result[k] = v
            else:
                # For other elements, extract text or recurse
                # Special handling for TimeCreated to extract timestamp
                if child_tag == 'TimeCreated' and 'SystemTime' in child.attrib:
                    result['timestamp'] = child.attrib['SystemTime']
                    result[child_tag] = child.attrib
                elif list(child):  # Has children
                    child_dict = TextFormat._xml_element_to_dict(child)
                    result[child_tag] = child_dict
                elif child.text and child.text.strip():
                    result[child_tag] = child.text.strip()
                elif child.attrib:
                    # Special handling for Data elements with Name attribute
                    if child_tag == 'Data' and 'Name' in child.attrib:
                        field_name = child.attrib['Name']
                        field_value = child.text.strip() if child.text else ''
                        result[field_name] = field_value
                    else:
                        result[child_tag] = child.attrib

        return result
