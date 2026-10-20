"""XML format handler."""

import xml.etree.ElementTree as ET
from typing import Iterator
from ..base import InputFormat


def _local_name(tag: str) -> str:
    """Return an element or attribute tag without its XML namespace prefix."""
    return tag.split('}')[-1] if '}' in tag else tag


class XMLFormat(InputFormat):
    """Handler for XML format.

    Event elements are matched by local name, case-insensitively and ignoring
    XML namespaces, so a namespaced document such as Windows Event XML (whose
    elements are ``{http://.../events/event}Event``) is handled the same as a
    bare ``<event>``.
    """

    def __init__(self, event_tag: str = "event"):
        """
        Initialize XML format handler.

        Args:
            event_tag: Local name of the element that represents an event
                (matched case-insensitively, namespace ignored).
        """
        self.event_tag = event_tag

    def parse(self, content_stream: Iterator[bytes]) -> Iterator[dict]:
        """
        Parse an XML document, yielding one dict per event element.

        Fails loud instead of silently yielding nothing: malformed XML raises,
        and a non-empty document that matches no event element raises an error
        naming the element tags it did find.

        Args:
            content_stream: Iterator yielding chunks of bytes

        Yields:
            Dictionaries converted from matching XML elements
        """
        # XML needs the complete document, so accumulate the stream first.
        content = b''.join(content_stream)
        if not content.strip():
            return  # genuinely empty input: no events, and not an error

        try:
            root = ET.fromstring(content)
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse XML input: {e}") from e

        want = self.event_tag.lower()
        matched = 0
        seen_tags = set()
        for elem in root.iter():
            local = _local_name(elem.tag)
            if elem is not root:
                seen_tags.add(local)
            if local.lower() == want:
                event_dict = self._element_to_dict(elem)
                if event_dict:
                    matched += 1
                    yield event_dict

        if matched == 0 and seen_tags:
            raise ValueError(
                f"XML parsed but no event element matched tag {self.event_tag!r} "
                f"(matching ignores case and namespace). Element names found: "
                f"{sorted(seen_tags)[:10]}. Set the correct event tag or input format."
            )

    def _element_to_dict(self, element: ET.Element) -> dict:
        """
        Convert an XML element to a dictionary, stripping namespaces from keys.

        Args:
            element: XML element

        Returns:
            Dictionary representation
        """
        result = {}

        # Add attributes (namespace-stripped keys)
        for key, value in element.attrib.items():
            result[_local_name(key)] = value

        # Add text content
        if element.text and element.text.strip():
            result['_text'] = element.text.strip()

        # Add child elements
        for child in element:
            child_dict = self._element_to_dict(child)
            tag = _local_name(child.tag)

            # Handle multiple children with the same tag
            if tag in result:
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(child_dict)
            else:
                result[tag] = child_dict

        return result
