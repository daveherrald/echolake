"""XML format handler."""

import xml.etree.ElementTree as ET
from typing import Iterator
from ..base import InputFormat


class XMLFormat(InputFormat):
    """Handler for XML format."""

    def __init__(self, event_tag: str = "event"):
        """
        Initialize XML format handler.

        Args:
            event_tag: XML tag name that represents an event
        """
        self.event_tag = event_tag

    def parse(self, content_stream: Iterator[bytes]) -> Iterator[dict]:
        """
        Parse XML content stream.

        Note: XML requires full document, so chunks are accumulated.
        However, individual elements are still yielded one at a time.

        Args:
            content_stream: Iterator yielding chunks of bytes

        Yields:
            Dictionaries converted from XML elements
        """
        try:
            # Accumulate all chunks (XML needs complete document)
            chunks = []
            for chunk in content_stream:
                chunks.append(chunk)

            # Parse XML
            content = b''.join(chunks)
            root = ET.fromstring(content)

            # Stream individual elements
            for elem in root.iter(self.event_tag):
                event_dict = self._element_to_dict(elem)
                if event_dict:
                    yield event_dict

        except ET.ParseError:
            # Skip malformed XML
            pass

    def _element_to_dict(self, element: ET.Element) -> dict:
        """
        Convert XML element to dictionary.

        Args:
            element: XML element

        Returns:
            Dictionary representation
        """
        result = {}

        # Add attributes
        if element.attrib:
            result.update(element.attrib)

        # Add text content
        if element.text and element.text.strip():
            result['_text'] = element.text.strip()

        # Add child elements
        for child in element:
            child_dict = self._element_to_dict(child)
            tag = child.tag

            # Handle multiple children with same tag
            if tag in result:
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(child_dict)
            else:
                result[tag] = child_dict

        return result
