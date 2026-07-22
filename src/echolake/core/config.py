"""Configuration management for EchoLake."""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import os
import yaml
from pydantic import BaseModel, Field, field_validator


class TimestampPattern(BaseModel):
    """Configuration for timestamp extraction pattern."""
    field: str = Field(..., description="Field name containing timestamp")
    format: str = Field(default="iso8601", description="Timestamp format")
    is_base: bool = Field(default=False, description="Use as base timestamp for delta calculation")


class InputSourceConfig(BaseModel):
    """Configuration for input source."""
    type: str = Field(..., description="Source type: local, s3, gcs, azure")
    path: Optional[str] = Field(default=None, description="Local path")
    bucket: Optional[str] = Field(default=None, description="Cloud bucket name")
    prefix: Optional[str] = Field(default="", description="Bucket prefix/path")
    pattern: Optional[str] = Field(default="*", description="File pattern for matching")
    include_files: Optional[List[str]] = Field(default=None, description="Specific files to include (filters list_files())")

    @field_validator('type')
    @classmethod
    def validate_source_type(cls, v: str) -> str:
        """Validate source type."""
        valid_types = ["local", "s3", "gcs", "azure", "github"]
        if v not in valid_types:
            raise ValueError(f"Invalid source type: {v}. Must be one of {valid_types}")
        return v


class InputConfig(BaseModel):
    """Configuration for input processing."""
    model_config = {"populate_by_name": True}

    source: InputSourceConfig
    format: str = Field(default="auto", description="Input format: auto, text, json, jsonl, xml")
    schema_type: Optional[str] = Field(default=None, description="Schema: lakehouse_bronze, ocsf, or None", alias="schema")
    timestamp_patterns: List[TimestampPattern] = Field(default_factory=list)

    @field_validator('format')
    @classmethod
    def validate_format(cls, v: str) -> str:
        """Validate input format."""
        valid_formats = ["auto", "csv", "text", "json", "jsonl", "xml"]
        if v not in valid_formats:
            raise ValueError(f"Invalid format: {v}. Must be one of {valid_formats}")
        return v


class OutputDestinationConfig(BaseModel):
    """Configuration for output destination."""
    type: str = Field(..., description="Destination type: local, s3, gcs, azure, stdout, splunk_hec")
    path: Optional[str] = Field(default=None, description="Local path")
    bucket: Optional[str] = Field(default=None, description="Cloud bucket name")
    path_template: Optional[str] = Field(
        default="output/{filename}",
        description="Path template with variables: {filename}, {sourcetype}, {year}, {month}, {day}, {hour}, {minute}"
    )

    # --- Splunk HTTP Event Collector (HEC) settings ---
    # Used only when type == "splunk_hec". The token is never stored here; it is
    # read at runtime from the environment variable named by hec_token_env.
    hec_url: Optional[str] = Field(
        default=None,
        description="Full HEC collector URL, e.g. https://http-inputs-<stack>.splunkcloud.com/services/collector"
    )
    hec_token_env: str = Field(
        default="ECHOLAKE_SPLUNK_HEC_TOKEN",
        description="Name of the environment variable holding the HEC token (token is not stored in config)"
    )
    index: Optional[str] = Field(default=None, description="Splunk index to route all events to (overrides per-event index)")
    verify_ssl: bool = Field(default=True, description="Verify the HEC server's TLS certificate")
    use_raw_endpoint: bool = Field(default=False, description="POST to /services/collector/raw instead of /event")
    default_host: Optional[str] = Field(default=None, description="Fallback host when an event has no host field")
    source_override: Optional[str] = Field(default=None, description="Force this source on every event")
    sourcetype_override: Optional[str] = Field(default=None, description="Force this sourcetype on every event")
    time_field: str = Field(default="_time", description="Event field carrying the event timestamp")
    raw_field: str = Field(default="_raw", description="Event field carrying the raw log line to send as the HEC event")
    host_field: str = Field(default="host", description="Event field carrying the host")
    source_field: str = Field(default="source", description="Event field carrying the source")
    sourcetype_field: str = Field(default="sourcetype", description="Event field carrying the sourcetype")
    hec_dry_run: bool = Field(default=False, description="Build and print HEC payloads without sending them")
    hec_max_workers: int = Field(default=1, description="Concurrent HEC POST workers (>1 enables parallel sending)")

    @field_validator('type')
    @classmethod
    def validate_destination_type(cls, v: str) -> str:
        """Validate destination type."""
        valid_types = ["local", "s3", "gcs", "azure", "stdout", "splunk_hec", "hec"]
        if v not in valid_types:
            raise ValueError(f"Invalid destination type: {v}. Must be one of {valid_types}")
        return v


class OutputConfig(BaseModel):
    """Configuration for output processing."""
    destination: OutputDestinationConfig
    format: str = Field(default="jsonl", description="Output format: json, jsonl, text")
    compression: Optional[str] = Field(default=None, description="Compression: gzip, bzip2, or None")
    batch_size: int = Field(default=1000, description="Batch size for writing")

    @field_validator('format')
    @classmethod
    def validate_format(cls, v: str) -> str:
        """Validate output format."""
        valid_formats = ["text", "json", "jsonl"]
        if v not in valid_formats:
            raise ValueError(f"Invalid format: {v}. Must be one of {valid_formats}")
        return v

    @field_validator('compression')
    @classmethod
    def validate_compression(cls, v: Optional[str]) -> Optional[str]:
        """Validate compression type."""
        if v is None:
            return v
        valid_compressions = ["gzip", "bzip2"]
        if v not in valid_compressions:
            raise ValueError(f"Invalid compression: {v}. Must be one of {valid_compressions}")
        return v


class EchoConfig(BaseModel):
    """Configuration for echo behavior."""
    delta_factor: float = Field(default=1.0, description="Time delta multiplication factor")
    base_time: str = Field(
        default="auto",
        description="Base time: auto, earliest, latest, earliest+1d, latest-2h, or ISO8601 timestamp"
    )
    target_time: str = Field(
        default="now",
        description="Target time: now, now-2h, now+1d, or ISO8601 timestamp"
    )
    prevent_future: bool = Field(default=True, description="Prevent timestamps in the future")
    ceiling_time: Optional[str] = Field(
        default="now",
        description="Ceiling time: now, now-1h, or ISO8601 timestamp"
    )
    no_shift: bool = Field(
        default=False,
        description="Passthrough: emit events with original timestamps and skip the Phase 1 scan (no _time or _raw changes)"
    )

    @field_validator('delta_factor')
    @classmethod
    def validate_delta_factor(cls, v: float) -> float:
        """Validate delta factor is positive."""
        if v <= 0:
            raise ValueError("delta_factor must be positive")
        return v

    @field_validator('base_time', 'target_time', 'ceiling_time')
    @classmethod
    def validate_time_expression(cls, v: Optional[str]) -> Optional[str]:
        """Validate time expression syntax."""
        if v in (None, "auto"):
            return v

        # Import here to avoid circular dependency
        from ..utils.time import parse_time_expression

        try:
            # Just validate syntax, don't resolve yet
            parse_time_expression(v)
            return v
        except ValueError as e:
            raise ValueError(f"Invalid time expression: {e}")


class DatasetConfig(BaseModel):
    """Dataset configuration."""
    ref: str = Field(..., description="Dataset reference")
    version: Optional[str] = Field(default=None, description="Version constraint")
    overrides: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Override dataset defaults"
    )


class Config(BaseModel):
    """Main configuration for EchoLake."""
    dataset: Optional[DatasetConfig] = None
    echo: EchoConfig = Field(default_factory=EchoConfig)
    input: Optional[InputConfig] = None
    output: Optional[OutputConfig] = None

    @classmethod
    def from_file(cls, config_path: Union[str, Path]) -> 'Config':
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to YAML config file

        Returns:
            Config instance
        """
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(path, 'r') as f:
            data = yaml.safe_load(f)

        return cls(**data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Config':
        """
        Create configuration from dictionary.

        Args:
            data: Configuration dictionary

        Returns:
            Config instance
        """
        return cls(**data)

    @classmethod
    def from_env(cls, prefix: str = "ECHOLAKE") -> Dict[str, Any]:
        """
        Extract configuration from environment variables.

        Args:
            prefix: Environment variable prefix

        Returns:
            Dictionary of config values from environment
        """
        config_dict: Dict[str, Any] = {}

        # Echo config
        if os.getenv(f"{prefix}_DELTA_FACTOR"):
            config_dict.setdefault("echo", {})["delta_factor"] = float(
                os.getenv(f"{prefix}_DELTA_FACTOR", "1.0")
            )

        if os.getenv(f"{prefix}_BASE_TIME"):
            config_dict.setdefault("echo", {})["base_time"] = os.getenv(f"{prefix}_BASE_TIME")

        if os.getenv(f"{prefix}_TARGET_TIME"):
            config_dict.setdefault("echo", {})["target_time"] = os.getenv(f"{prefix}_TARGET_TIME")

        if os.getenv(f"{prefix}_PREVENT_FUTURE"):
            config_dict.setdefault("echo", {})["prevent_future"] = (
                os.getenv(f"{prefix}_PREVENT_FUTURE", "true").lower() == "true"
            )

        # Input config
        if os.getenv(f"{prefix}_INPUT_SOURCE_TYPE"):
            config_dict.setdefault("input", {}).setdefault("source", {})["type"] = os.getenv(
                f"{prefix}_INPUT_SOURCE_TYPE"
            )

        if os.getenv(f"{prefix}_INPUT_FORMAT"):
            config_dict.setdefault("input", {})["format"] = os.getenv(f"{prefix}_INPUT_FORMAT")

        if os.getenv(f"{prefix}_INPUT_SCHEMA"):
            config_dict.setdefault("input", {})["schema"] = os.getenv(f"{prefix}_INPUT_SCHEMA")

        # Output config
        if os.getenv(f"{prefix}_OUTPUT_DEST_TYPE"):
            config_dict.setdefault("output", {}).setdefault("destination", {})["type"] = os.getenv(
                f"{prefix}_OUTPUT_DEST_TYPE"
            )

        if os.getenv(f"{prefix}_OUTPUT_FORMAT"):
            config_dict.setdefault("output", {})["format"] = os.getenv(f"{prefix}_OUTPUT_FORMAT")

        if os.getenv(f"{prefix}_OUTPUT_COMPRESSION"):
            config_dict.setdefault("output", {})["compression"] = os.getenv(
                f"{prefix}_OUTPUT_COMPRESSION"
            )

        return config_dict

    def merge(self, other: 'Config') -> 'Config':
        """
        Merge with another config, with other taking precedence.

        Only fields explicitly set on the override config will take precedence.
        Fields that are just Pydantic defaults on the override are not merged,
        preserving the base config's explicitly set values.

        Args:
            other: Config to merge with (higher priority)

        Returns:
            New merged Config instance
        """
        # Base: include all non-None values (including defaults)
        self_dict = self.model_dump(exclude_none=True)
        # Override: only include explicitly set fields (skip defaults)
        other_dict = other.model_dump(exclude_unset=True)

        # Deep merge
        merged = self._deep_merge(self_dict, other_dict)

        return Config(**merged)

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = value
        return result


@dataclass
class EchoStats:
    """Statistics from an echo operation."""
    event_count: int = 0
    events_modified: int = 0
    errors: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    input_source: Optional[str] = None
    output_destination: Optional[str] = None

    # Original timestamp range
    original_earliest_time: Optional[datetime] = None
    original_earliest_file: Optional[str] = None
    original_latest_time: Optional[datetime] = None
    original_latest_file: Optional[str] = None

    # New timestamp range
    new_earliest_time: Optional[datetime] = None
    new_latest_time: Optional[datetime] = None

    # Base time info (for backwards compatibility)
    original_base_time: Optional[datetime] = None
    original_base_file: Optional[str] = None
    new_base_time: Optional[datetime] = None
    delta_factor: Optional[float] = None

    # Future events tracking
    events_in_future: int = 0
    events_at_ceiling: int = 0
    run_time: Optional[datetime] = None

    def summary(self) -> Dict[str, Any]:
        """Return summary dictionary."""
        duration = None
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()

        return {
            "event_count": self.event_count,
            "events_modified": self.events_modified,
            "errors": self.errors,
            "duration_seconds": duration,
            "input_source": self.input_source,
            "output_destination": self.output_destination,

            # Original timestamp range
            "original_earliest_time": self.original_earliest_time.isoformat() if self.original_earliest_time else None,
            "original_earliest_file": self.original_earliest_file,
            "original_latest_time": self.original_latest_time.isoformat() if self.original_latest_time else None,
            "original_latest_file": self.original_latest_file,

            # New timestamp range
            "new_earliest_time": self.new_earliest_time.isoformat() if self.new_earliest_time else None,
            "new_latest_time": self.new_latest_time.isoformat() if self.new_latest_time else None,

            # Base time (backwards compat)
            "original_base_time": self.original_base_time.isoformat() if self.original_base_time else None,
            "original_base_file": self.original_base_file,
            "new_base_time": self.new_base_time.isoformat() if self.new_base_time else None,
            "delta_factor": self.delta_factor,

            # Future events
            "events_in_future": self.events_in_future,
            "run_time": self.run_time.isoformat() if self.run_time else None,
        }
