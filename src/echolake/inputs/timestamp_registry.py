"""Sourcetype-based timestamp registry."""

import logging
from pathlib import Path
from typing import Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

_REGISTRY_FILE = Path(__file__).parent / "timestamp_registry.yaml"


class TimestampRegistry:
    """Loads and caches sourcetype->timestamp patterns from YAML."""

    _instance: Optional["TimestampRegistry"] = None

    def __init__(self, registry_path: Path = _REGISTRY_FILE):
        self._registry: Dict[str, List[Dict]] = {}
        self._lower_map: Dict[str, str] = {}  # lowercase key -> original key
        self._load(registry_path)

    def _load(self, path: Path):
        """Load registry from YAML file."""
        if not path.exists():
            logger.warning(f"Timestamp registry not found: {path}")
            return

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        for sourcetype, patterns in data.items():
            key = str(sourcetype)
            self._registry[key] = patterns
            self._lower_map[key.lower()] = key

        logger.debug(f"Loaded timestamp registry with {len(self._registry)} sourcetypes")

    @classmethod
    def get(cls) -> "TimestampRegistry":
        """Get or create the singleton registry."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def lookup(self, sourcetype: str) -> Optional[List[Dict]]:
        """Return patterns for a sourcetype, or None if not registered.

        Tries exact match first, then case-insensitive.
        """
        # Exact match
        if sourcetype in self._registry:
            return self._registry[sourcetype]

        # Case-insensitive match
        original_key = self._lower_map.get(sourcetype.lower())
        if original_key:
            return self._registry[original_key]

        return None
