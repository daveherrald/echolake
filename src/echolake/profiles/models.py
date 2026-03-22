"""Pydantic models for echo profiles and destinations."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class EchoConfig(BaseModel):
    """Echo timing configuration."""

    delta_factor: float = Field(
        default=1.0,
        description="Time compression/expansion factor"
    )
    base_time: str = Field(
        default="earliest",
        description="Base time reference (earliest, latest, or ISO8601)"
    )
    target_time: str = Field(
        default="now-1h",
        description="Target time for echo (now, now-Xh/d/w, or ISO8601)"
    )
    prevent_future: bool = Field(
        default=True,
        description="Prevent timestamps in the future"
    )


class DatasetReference(BaseModel):
    """Reference to a dataset to include in the profile."""
    model_config = {"populate_by_name": True}

    ref: str = Field(
        ...,
        description="Dataset reference (local:, github:, etc.)"
    )
    version: str = Field(
        default="*",
        description="Version constraint (semver)"
    )
    description: Optional[str] = Field(
        default=None,
        description="Why this dataset is included"
    )

    # Optional overrides per dataset
    schema_type: Optional[str] = Field(
        default=None,
        description="Override schema for this dataset",
        alias="schema"
    )
    echo: Optional[EchoConfig] = Field(
        default=None,
        description="Override echo config for this dataset"
    )

    # Backward compatibility alias
    replay: Optional[EchoConfig] = Field(
        default=None,
        description="Deprecated: use 'echo' instead",
        exclude=True,
    )

    @model_validator(mode='after')
    def migrate_replay_to_echo(self) -> 'DatasetReference':
        """Copy 'replay' to 'echo' for backward compatibility."""
        if self.replay is not None and self.echo is None:
            self.echo = self.replay
        return self


class EchoProfileMetadata(BaseModel):
    """Metadata for an echo profile."""

    name: str = Field(
        ...,
        description="Profile name (identifier)"
    )
    version: str = Field(
        default="1.0.0",
        description="Profile version (semver)"
    )
    description: Optional[str] = Field(
        default=None,
        description="Human-readable description"
    )
    author: Optional[str] = Field(
        default=None,
        description="Profile author"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization"
    )


class EchoProfile(BaseModel):
    """Complete echo profile specification."""
    model_config = {"populate_by_name": True}

    profile: EchoProfileMetadata

    # Support multiple datasets
    datasets: List[DatasetReference] = Field(
        default_factory=list,
        description="List of datasets to echo"
    )

    # Global echo configuration (can be overridden per dataset)
    echo: Optional[EchoConfig] = Field(
        default=None,
        description="Default echo configuration for all datasets"
    )

    # Backward compatibility alias
    replay: Optional[EchoConfig] = Field(
        default=None,
        description="Deprecated: use 'echo' instead",
        exclude=True,
    )

    @model_validator(mode='after')
    def migrate_replay_to_echo(self) -> 'EchoProfile':
        """Copy 'replay' to 'echo' for backward compatibility."""
        if self.replay is not None and self.echo is None:
            self.echo = self.replay
        return self

    # Global schema (can be overridden per dataset)
    schema_type: Optional[str] = Field(
        default="raw",
        description="Default schema for all datasets",
        alias="schema"
    )

    # Optional runtime defaults
    defaults: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional defaults"
    )

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "EchoProfile":
        """Load profile from YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Profile not found: {path}")

        with open(path, "r") as f:
            data = yaml.safe_load(f)

        return cls(**data)

    def to_file(self, path: Union[str, Path]) -> None:
        """Save profile to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dict and write
        data = self.model_dump(exclude_none=True)
        with open(path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


class DestinationConnection(BaseModel):
    """Connection parameters for a destination (no credentials)."""

    # Generic connection fields
    host: Optional[str] = Field(default=None, description="Host URL")
    port: Optional[int] = Field(default=None, description="Port")
    path: Optional[str] = Field(default=None, description="Path or endpoint")

    # Cloud-specific
    bucket: Optional[str] = Field(default=None, description="S3/GCS bucket name")
    prefix: Optional[str] = Field(default=None, description="Object prefix/path")
    region: Optional[str] = Field(default=None, description="Cloud region")
    project_id: Optional[str] = Field(default=None, description="GCP project ID")

    # SIEM-specific
    index: Optional[str] = Field(default=None, description="Index")
    source: Optional[str] = Field(default=None, description="Source field")
    sourcetype: Optional[str] = Field(default=None, description="Sourcetype")
    log_type: Optional[str] = Field(default=None, description="Chronicle log type")

    # Generic extensibility
    extra: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional connection parameters"
    )


class DestinationMetadata(BaseModel):
    """Metadata for a destination."""

    name: str = Field(
        ...,
        description="Destination name (identifier)"
    )
    description: Optional[str] = Field(
        default=None,
        description="Human-readable description"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization"
    )


class Destination(BaseModel):
    """Destination configuration (no credentials)."""
    model_config = {"populate_by_name": True}

    destination: DestinationMetadata

    type: str = Field(
        ...,
        description="Destination type (chronicle, s3, local, stdout, http)"
    )

    connection: DestinationConnection = Field(
        default_factory=DestinationConnection,
        description="Connection parameters (no credentials)"
    )

    # Output format
    format: str = Field(
        default="jsonl",
        description="Output format (jsonl, json, text)"
    )

    # Compression
    compression: Optional[str] = Field(
        default=None,
        description="Output compression (gzip, bzip2)"
    )

    # Optional transformations
    schema_type: Optional[str] = Field(
        default=None,
        description="Schema transformation to apply",
        alias="schema"
    )

    @field_validator('type')
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate destination type."""
        valid_types = [
            "chronicle",
            "s3",
            "gcs",
            "azure_blob",
            "local",
            "stdout",
            "http",
            "https",
            "multi"
        ]
        if v not in valid_types:
            # Don't error - allow custom types for extensibility
            pass
        return v

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "Destination":
        """Load destination from YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Destination not found: {path}")

        with open(path, "r") as f:
            data = yaml.safe_load(f)

        return cls(**data)

    def to_file(self, path: Union[str, Path]) -> None:
        """Save destination to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = self.model_dump(exclude_none=True)
        with open(path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)


class CredentialsConfig(BaseModel):
    """Credentials configuration (never in git)."""

    # Support different credential types
    token: Optional[str] = Field(default=None, description="API token or key")
    username: Optional[str] = Field(default=None, description="Username")
    password: Optional[str] = Field(default=None, description="Password")
    api_key: Optional[str] = Field(default=None, description="API key")
    credentials_file: Optional[str] = Field(
        default=None,
        description="Path to credentials file (service account JSON, etc.)"
    )

    # AWS-specific
    aws_access_key_id: Optional[str] = Field(default=None)
    aws_secret_access_key: Optional[str] = Field(default=None)
    aws_session_token: Optional[str] = Field(default=None)

    # Environment variable references
    env: Optional[Dict[str, str]] = Field(
        default=None,
        description="Environment variable mappings"
    )

    # Generic extensibility
    extra: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional credential fields"
    )

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> Dict[str, "CredentialsConfig"]:
        """
        Load credentials from YAML file.

        Returns dict mapping destination names to credentials.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Credentials file not found: {path}")

        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if "credentials" not in data:
            raise ValueError("Credentials file must have 'credentials' key")

        # Parse each destination's credentials
        result = {}
        for dest_name, creds in data["credentials"].items():
            result[dest_name] = cls(**creds)

        return result

    @classmethod
    def from_env(cls, prefix: str = "") -> "CredentialsConfig":
        """Load credentials from environment variables."""
        import os

        return cls(
            token=os.getenv(f"{prefix}TOKEN"),
            username=os.getenv(f"{prefix}USERNAME"),
            password=os.getenv(f"{prefix}PASSWORD"),
            api_key=os.getenv(f"{prefix}API_KEY"),
            credentials_file=os.getenv(f"{prefix}CREDENTIALS_FILE"),
            aws_access_key_id=os.getenv(f"{prefix}AWS_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv(f"{prefix}AWS_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=os.getenv(f"{prefix}AWS_SESSION_TOKEN") or os.getenv("AWS_SESSION_TOKEN"),
        )
