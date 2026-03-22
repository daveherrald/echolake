"""Input schema handlers."""

from typing import Optional
from .lakehouse import LakehouseBronzeSchema
from .ocsf import OCSFSchema
from .raw import RawSchema

__all__ = [
    'LakehouseBronzeSchema',
    'OCSFSchema',
    'RawSchema',
    'get_schema',
]


def get_schema(schema_type: Optional[str], **kwargs):
    """
    Factory function to get schema handler.

    Args:
        schema_type: Schema type (lakehouse_bronze, ocsf, None for raw)
        **kwargs: Arguments for schema initialization

    Returns:
        Schema handler instance
    """
    if schema_type is None or schema_type.lower() == 'raw':
        return RawSchema(**kwargs)

    schemas = {
        'lakehouse_bronze': LakehouseBronzeSchema,
        'lakehouse': LakehouseBronzeSchema,  # Alias
'ocsf': OCSFSchema,
    }

    schema_class = schemas.get(schema_type.lower())
    if not schema_class:
        raise ValueError(f"Unsupported schema type: {schema_type}")

    return schema_class(**kwargs)
