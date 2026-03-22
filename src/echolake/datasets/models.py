"""Pydantic models for dataset manifests."""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class MitreAttackTechnique(BaseModel):
    """MITRE ATT&CK technique metadata."""

    id: str = Field(..., description="Technique ID (e.g., T1078)")
    name: str = Field(..., description="Technique name")
    tactics: List[str] = Field(default_factory=list, description="Associated tactics")

    @field_validator('id')
    @classmethod
    def validate_technique_id(cls, v: str) -> str:
        """Validate MITRE ATT&CK technique ID format."""
        if not v.startswith('T'):
            raise ValueError(f"Technique ID must start with 'T': {v}")
        return v


class MitreAttackInfo(BaseModel):
    """MITRE ATT&CK metadata for dataset."""

    techniques: List[MitreAttackTechnique] = Field(
        default_factory=list,
        description="MITRE ATT&CK techniques"
    )
    tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK tactics")


class TimestampRange(BaseModel):
    """Pre-computed timestamp range for a dataset."""
    earliest: str = Field(..., description="Earliest timestamp in ISO8601 format")
    latest: str = Field(..., description="Latest timestamp in ISO8601 format")
    field: str = Field(default="_time", description="Timestamp field name")


class DatasetMetadata(BaseModel):
    """Metadata for a dataset."""

    name: str = Field(..., description="Dataset name")
    version: str = Field(..., description="Semantic version")
    description: str = Field(..., description="Human-readable description")
    author: Optional[str] = Field(default=None, description="Author email or identifier")
    created: Optional[str] = Field(default=None, description="Creation date (ISO8601 or YYYY-MM-DD)")
    updated: Optional[str] = Field(default=None, description="Last update date (ISO8601 or YYYY-MM-DD)")
    license: Optional[str] = Field(default=None, description="License (e.g., MIT, Apache-2.0)")
    tags: List[str] = Field(default_factory=list, description="Searchable tags")
    timestamp_range: Optional[TimestampRange] = Field(
        default=None,
        description="Pre-computed timestamp range from dataset metadata"
    )
    mitre_attack: Optional[MitreAttackInfo] = Field(
        default=None,
        description="MITRE ATT&CK metadata"
    )

    @field_validator('version')
    @classmethod
    def validate_version(cls, v: str) -> str:
        """Validate semantic version format."""
        from .utils import parse_semver
        try:
            parse_semver(v)
        except ValueError as e:
            raise ValueError(f"Invalid semantic version: {e}")
        return v


class LogSource(BaseModel):
    """Vendor-neutral log source classification."""

    vendor: Optional[str] = Field(
        default=None,
        description="Vendor name (e.g., Microsoft, AWS, Cisco)"
    )
    product: Optional[str] = Field(
        default=None,
        description="Product name (e.g., Windows, CloudTrail, ASA)"
    )
    category: Optional[str] = Field(
        default=None,
        description="Log category (e.g., Security, Sysmon, Network)"
    )
    subcategory: Optional[str] = Field(
        default=None,
        description="Optional subcategory for finer classification"
    )
    event_ids: Optional[List[Union[int, str]]] = Field(
        default=None,
        description="Optional list of event IDs covered"
    )


class BundledFile(BaseModel):
    """File bundled within the dataset directory."""
    model_config = {"populate_by_name": True}

    path: str = Field(..., description="Relative path from dataset root")
    description: Optional[str] = Field(default=None, description="File description")
    format: str = Field(default="auto", description="File format (auto, jsonl, json, text, xml)")
    schema_type: Optional[str] = Field(
        default=None,
        description="Schema type (lakehouse_bronze, ocsf, raw)",
        alias="schema"
    )
    event_count: Optional[int] = Field(default=None, description="Expected event count")
    sourcetype: Optional[str] = Field(default=None, description="Source type identifier (e.g., WinEventLog:Security)")
    log_source: Optional[LogSource] = Field(
        default=None,
        description="Vendor-neutral log source classification"
    )
    platforms: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Platform-specific metadata (fully extensible, no validation)"
    )

    @field_validator('path')
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Validate path doesn't escape dataset directory."""
        path = Path(v)
        # Prevent directory traversal
        if '..' in path.parts:
            raise ValueError(f"Path cannot contain '..': {v}")
        if path.is_absolute():
            raise ValueError(f"Path must be relative: {v}")
        return v

    @field_validator('format')
    @classmethod
    def validate_format(cls, v: str) -> str:
        """Validate file format."""
        valid_formats = ["auto", "csv", "jsonl", "json", "text", "xml"]
        if v not in valid_formats:
            raise ValueError(f"Invalid format: {v}. Must be one of {valid_formats}")
        return v


class FileReference(BaseModel):
    """Reference to an external file (S3, GCS, HTTP)."""
    model_config = {"populate_by_name": True}

    uri: str = Field(..., description="URI to external file")
    description: Optional[str] = Field(default=None, description="File description")
    format: str = Field(default="auto", description="File format (auto, jsonl, json, text, xml)")
    schema_type: Optional[str] = Field(
        default=None,
        description="Schema type (lakehouse_bronze, ocsf, raw)",
        alias="schema"
    )
    checksum: Optional[str] = Field(
        default=None,
        description="Checksum in format 'algorithm:value' (e.g., sha256:abc123...)"
    )
    sourcetype: Optional[str] = Field(default=None, description="Source type identifier (e.g., WinEventLog:Security)")
    log_source: Optional[LogSource] = Field(
        default=None,
        description="Vendor-neutral log source classification"
    )
    platforms: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Platform-specific metadata (fully extensible, no validation)"
    )

    @field_validator('uri')
    @classmethod
    def validate_uri(cls, v: str) -> str:
        """Validate URI format."""
        valid_schemes = ['s3://', 'gs://', 'http://', 'https://', 'azure://']
        if not any(v.startswith(scheme) for scheme in valid_schemes):
            raise ValueError(
                f"URI must start with one of {valid_schemes}: {v}"
            )
        return v

    @field_validator('format')
    @classmethod
    def validate_format(cls, v: str) -> str:
        """Validate file format."""
        valid_formats = ["auto", "csv", "jsonl", "json", "text", "xml"]
        if v not in valid_formats:
            raise ValueError(f"Invalid format: {v}. Must be one of {valid_formats}")
        return v

    @field_validator('checksum')
    @classmethod
    def validate_checksum(cls, v: Optional[str]) -> Optional[str]:
        """Validate checksum format."""
        if v is None:
            return v
        if ':' not in v:
            raise ValueError(f"Checksum must be in format 'algorithm:value': {v}")
        algorithm, _ = v.split(':', 1)
        valid_algorithms = ['sha256', 'sha512', 'md5']
        if algorithm not in valid_algorithms:
            raise ValueError(
                f"Checksum algorithm must be one of {valid_algorithms}: {algorithm}"
            )
        return v


class DatasetFiles(BaseModel):
    """Collection of bundled and referenced files."""

    bundled: List[BundledFile] = Field(
        default_factory=list,
        description="Files included in dataset directory"
    )
    references: List[FileReference] = Field(
        default_factory=list,
        description="External file references (S3, GCS, HTTP)"
    )


class DatasetDependency(BaseModel):
    """Dependency on another dataset."""

    dataset: str = Field(..., description="Dataset reference (org/name, github:org/repo/path)")
    version: str = Field(default="*", description="Version constraint (semver)")
    description: Optional[str] = Field(default=None, description="Dependency description")

    @field_validator('version')
    @classmethod
    def validate_version_constraint(cls, v: str) -> str:
        """Validate version constraint format."""
        if v == "*":
            return v
        # Allow semver constraints like ">=1.0.0", "1.2.x", "^1.0.0"
        # Basic validation - full validation happens in resolver
        if not any(v.startswith(op) for op in ['>=', '<=', '>', '<', '=', '^', '~']) and v != "*" and 'x' not in v.lower():
            # Assume exact version
            from .utils import parse_semver
            try:
                parse_semver(v)
            except ValueError as e:
                raise ValueError(f"Invalid version constraint: {e}")
        return v


class DatasetDefaults(BaseModel):
    """Default configuration for dataset echo."""
    model_config = {"populate_by_name": True}

    echo: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Default echo config (delta_factor, base_time, target_time)"
    )

    # Backward compatibility alias
    replay: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Deprecated: use 'echo' instead",
        exclude=True,
    )

    @model_validator(mode='after')
    def migrate_replay_to_echo(self) -> 'DatasetDefaults':
        """Copy 'replay' to 'echo' for backward compatibility."""
        if self.replay is not None and self.echo is None:
            self.echo = self.replay
        return self

    schema_type: Optional[str] = Field(
        default=None,
        description="Default schema for files",
        alias="schema"
    )
    input: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Default input config (format, timestamp_patterns)"
    )


class DatasetManifest(BaseModel):
    """Complete dataset manifest (dataset.yaml)."""

    metadata: DatasetMetadata
    files: DatasetFiles = Field(default_factory=DatasetFiles)
    dependencies: List[DatasetDependency] = Field(default_factory=list)
    defaults: Optional[DatasetDefaults] = Field(default=None)

    @classmethod
    def from_file(cls, manifest_path: Union[str, Path]) -> 'DatasetManifest':
        """
        Load manifest from YAML file.

        Args:
            manifest_path: Path to dataset.yaml file

        Returns:
            DatasetManifest instance

        Raises:
            FileNotFoundError: If manifest file doesn't exist
            ValueError: If manifest is invalid
        """
        path = Path(manifest_path)
        if not path.exists():
            raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

        # Check file size (prevent loading huge files)
        max_size = 10 * 1024 * 1024  # 10 MB
        if path.stat().st_size > max_size:
            raise ValueError(f"Manifest file too large: {path.stat().st_size} bytes (max {max_size})")

        with open(path, 'r') as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Manifest must be a YAML dictionary: {manifest_path}")

        return cls(**data)

    def to_file(self, manifest_path: Union[str, Path]) -> None:
        """
        Save manifest to YAML file.

        Args:
            manifest_path: Path to write dataset.yaml file
        """
        path = Path(manifest_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w') as f:
            yaml.safe_dump(
                self.model_dump(exclude_none=True, by_alias=True),
                f,
                default_flow_style=False,
                sort_keys=False
            )

    def validate_files_exist(self, base_path: Path) -> List[str]:
        """
        Validate that bundled files exist.

        Args:
            base_path: Base directory containing the dataset

        Returns:
            List of missing file paths
        """
        missing = []
        for bundled_file in self.files.bundled:
            file_path = base_path / bundled_file.path
            if not file_path.exists():
                missing.append(bundled_file.path)
        return missing


class ResolvedDataset(BaseModel):
    """Resolved dataset with all dependencies and file paths."""

    manifest: DatasetManifest
    base_path: Path = Field(..., description="Base directory of dataset")
    resolved_dependencies: List['ResolvedDataset'] = Field(
        default_factory=list,
        description="Resolved dependency datasets"
    )

    def get_all_bundled_files(self) -> List[Path]:
        """
        Get all bundled file paths (including from dependencies).

        Returns:
            List of absolute paths to bundled files
        """
        files = []

        # Add this dataset's bundled files
        for bundled_file in self.manifest.files.bundled:
            files.append(self.base_path / bundled_file.path)

        # Add dependency bundled files (recursive)
        for dep in self.resolved_dependencies:
            files.extend(dep.get_all_bundled_files())

        return files

    def get_all_file_references(self) -> List[FileReference]:
        """
        Get all file references (including from dependencies).

        Returns:
            List of file references
        """
        refs = []

        # Add this dataset's references
        refs.extend(self.manifest.files.references)

        # Add dependency references (recursive)
        for dep in self.resolved_dependencies:
            refs.extend(dep.get_all_file_references())

        return refs

    def get_merged_defaults(self) -> Dict[str, Any]:
        """
        Get merged defaults from this dataset and dependencies.
        Dependencies are applied first, then this dataset's defaults.

        Returns:
            Merged defaults dictionary
        """
        merged = {}

        # Apply dependency defaults first (in order)
        for dep in self.resolved_dependencies:
            dep_defaults = dep.get_merged_defaults()
            merged = self._deep_merge(merged, dep_defaults)

        # Apply this dataset's defaults last (highest priority)
        if self.manifest.defaults:
            defaults_dict = self.manifest.defaults.model_dump(exclude_none=True)
            merged = self._deep_merge(merged, defaults_dict)

        return merged

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ResolvedDataset._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
