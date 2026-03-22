"""Input format handlers."""

from .auto import AutoFormat
from .csv import CSVFormat
from .json import JSONFormat, JSONLFormat
from .text import TextFormat
from .xml import XMLFormat

__all__ = ['AutoFormat', 'CSVFormat', 'JSONFormat', 'JSONLFormat', 'TextFormat', 'XMLFormat', 'get_format']


def get_format(format_type: str, **kwargs):
    """
    Factory function to get format handler.

    Args:
        format_type: Format type (auto, csv, json, jsonl, text, xml)
        **kwargs: Additional arguments for format handler

    Returns:
        Format handler instance
    """
    formats = {
        'auto': AutoFormat,
        'csv': CSVFormat,
        'json': JSONFormat,
        'jsonl': JSONLFormat,
        'text': TextFormat,
        'xml': XMLFormat,
    }

    format_class = formats.get(format_type.lower())
    if not format_class:
        raise ValueError(f"Unsupported format: {format_type}")

    return format_class(**kwargs)
