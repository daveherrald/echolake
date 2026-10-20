"""Input schema handlers."""

from typing import Optional
from .raw import RawSchema

__all__ = [
    'RawSchema',
    'get_schema',
]


def get_schema(schema_type: Optional[str], **kwargs):
    """
    Factory function to get schema handler.

    Args:
        schema_type: Schema type ('raw' or None; both yield the raw schema)
        **kwargs: Arguments for schema initialization

    Returns:
        Schema handler instance
    """
    if schema_type is None or schema_type.lower() == 'raw':
        return RawSchema(**kwargs)

    raise ValueError(f"Unsupported schema type: {schema_type}")
