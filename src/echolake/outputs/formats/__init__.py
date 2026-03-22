"""Output format handlers."""

from .json import JSONOutputFormat, JSONLOutputFormat
from .text import TextOutputFormat

__all__ = ['JSONOutputFormat', 'JSONLOutputFormat', 'TextOutputFormat', 'get_output_format']


def get_output_format(format_type: str, **kwargs):
    """
    Factory function to get output format handler.

    Args:
        format_type: Format type (json, jsonl, text)
        **kwargs: Additional arguments for format handler

    Returns:
        Output format handler instance
    """
    formats = {
        'json': JSONOutputFormat,
        'jsonl': JSONLOutputFormat,
        'text': TextOutputFormat,
    }

    format_class = formats.get(format_type.lower())
    if not format_class:
        raise ValueError(f"Unsupported output format: {format_type}")

    return format_class(**kwargs)
