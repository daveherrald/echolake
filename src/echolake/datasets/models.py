"""Pydantic models for dataset manifests."""

import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Literal, Optional, Union
import yaml
from dateutil.parser import isoparse
from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator


MANIFEST_VERSION = "1.0.0"
SUPPORTED_FILE_FORMATS = {"auto", "csv", "jsonl", "json", "text", "xml"}


class ManifestModel(BaseModel):
    """Strict base for the versioned dataset manifest contract."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @classmethod
    def _field_name(cls, key: str) -> str:
        if key in cls.model_fields:
            return key
        for name, field_info in cls.model_fields.items():
            if field_info.alias == key:
                return name
        raise KeyError(key)

    def __getitem__(self, key: str) -> Any:
        """Provide read compatibility for callers of the former dict model."""
        field_name = type(self)._field_name(key)
        if field_name not in self.model_fields_set:
            raise KeyError(key)
        return getattr(self, field_name)

    def get(self, key: str, default: Any = None) -> Any:
        """Return a typed field by name or alias, like ``dict.get``."""
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):
        """Return canonical keys explicitly supplied to this model."""
        return self.model_dump(
            exclude_none=False,
            exclude_unset=True,
            by_alias=True,
        ).keys()

    def items(self):
        """Return canonical key-value pairs explicitly supplied to this model."""
        return self.model_dump(
            exclude_none=False,
            exclude_unset=True,
            by_alias=True,
        ).items()

    def __iter__(self):
        """Yield explicit key-value pairs so ``dict(model)`` stays compatible."""
        return iter(self.items())

    def __len__(self) -> int:
        """Return the number of explicitly supplied fields."""
        return len(self.model_fields_set)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        try:
            field_name = type(self)._field_name(key)
        except KeyError:
            return False
        return field_name in self.model_fields_set


def _validate_relative_path(value: str) -> str:
    """Validate a portable path without consulting the filesystem."""
    if not value:
        raise ValueError("Path must name a file")
    if "\\" in value or "\x00" in value:
        raise ValueError(f"Path must use POSIX separators: {value}")
    if "://" in value or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value):
        raise ValueError(f"Path must be relative: {value}")
    path = PurePosixPath(value)
    if path == PurePosixPath(".") or value.endswith("/"):
        raise ValueError("Path must name a file")
    if path.is_absolute():
        raise ValueError(f"Path must be relative: {value}")
    if ".." in path.parts:
        raise ValueError(f"Path cannot contain '..': {value}")
    return value


def _parse_aware_timestamp(value: str, label: str) -> datetime:
    """Parse an ISO 8601 timestamp and require an explicit timezone."""
    try:
        parsed = isoparse(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an ISO 8601 timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone: {value}")
    return parsed


def _validate_sourcetype(value: Optional[str]) -> Optional[str]:
    if value is None:
        return value
    if not value or value != value.strip():
        raise ValueError("sourcetype must be a non-empty trimmed string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("sourcetype cannot contain control characters")
    return value


def _validate_schema(value: Optional[str]) -> Optional[str]:
    if value not in (None, "raw"):
        raise ValueError(f"Unsupported schema type: {value}. Only 'raw' is supported")
    return value


class MitreAttackTechnique(ManifestModel):
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


class MitreAttackInfo(ManifestModel):
    """MITRE ATT&CK metadata for dataset."""

    techniques: List[MitreAttackTechnique] = Field(
        default_factory=list,
        description="MITRE ATT&CK techniques"
    )
    tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK tactics")


class AttackFlowRef(ManifestModel):
    """Reference to a companion MITRE Attack Flow document.

    Attack Flow (Center for Threat-Informed Defense) is a STIX 2.1 extension that
    describes an attack as an ordered graph of actions, assets, conditions, and
    operators. It is stored as a companion file in the dataset directory and
    referenced here rather than inlined, because the STIX bundle form is verbose.

    This is additive to ``mitre_attack``: ``mitre_attack`` remains the lightweight
    which-techniques tag, while ``attack_flow`` is the ordered representation used
    for multi-step scenario datasets.
    """

    path: str = Field(..., description="Relative path from dataset root to the Attack Flow file")
    format: str = Field(
        default="stix-2.1",
        description="Attack Flow serialization (stix-2.1 JSON bundle, or afb builder format)"
    )
    schema_version: str = Field(
        default="2.0.0",
        description="Attack Flow schema version"
    )
    description: Optional[str] = Field(default=None, description="Human-readable description")

    @field_validator('path')
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Validate a portable path inside the dataset directory."""
        return _validate_relative_path(v)

    @field_validator('format')
    @classmethod
    def validate_format(cls, v: str) -> str:
        """Validate Attack Flow format."""
        valid_formats = ["stix-2.1", "afb"]
        if v not in valid_formats:
            raise ValueError(f"Invalid Attack Flow format: {v}. Must be one of {valid_formats}")
        return v


class TimestampRange(ManifestModel):
    """Pre-computed timestamp range for a dataset."""
    earliest: str = Field(..., description="Earliest timestamp in ISO8601 format")
    latest: str = Field(..., description="Latest timestamp in ISO8601 format")
    field: str = Field(default="_time", description="Timestamp field name")

    @model_validator(mode="after")
    def validate_order(self) -> "TimestampRange":
        earliest = _parse_aware_timestamp(self.earliest, "timestamp_range.earliest")
        latest = _parse_aware_timestamp(self.latest, "timestamp_range.latest")
        if earliest > latest:
            raise ValueError("timestamp_range.earliest must not be after latest")
        return self


class MetadataDataSource(ManifestModel):
    """Named family of sourcetypes represented by a dataset."""

    name: str
    sourcetypes: List[str] = Field(default_factory=list)

    @field_validator("sourcetypes")
    @classmethod
    def validate_sourcetypes(cls, values: List[str]) -> List[str]:
        return [_validate_sourcetype(value) for value in values]  # type: ignore[list-item]


class DatasetMetadata(ManifestModel):
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
    attack_flow: Optional[AttackFlowRef] = Field(
        default=None,
        description="Reference to a companion MITRE Attack Flow document (ordered attack graph)"
    )
    source_url: Optional[str] = Field(default=None, description="Canonical upstream dataset URL")
    data_sources: List[MetadataDataSource] = Field(
        default_factory=list,
        description="Named source families represented by the dataset",
    )
    size: Dict[str, str] = Field(
        default_factory=dict,
        description="Named package sizes as published by the source",
    )
    checksums: Dict[str, str] = Field(
        default_factory=dict,
        description="Named source checksums",
    )
    references: List[str] = Field(
        default_factory=list,
        description="External references, including URLs and explanatory text",
    )
    extensions: Dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Namespaced metadata extensions",
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

    @field_validator("created", "updated")
    @classmethod
    def validate_date(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        try:
            isoparse(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata dates must use ISO 8601") from exc
        return value

    @model_validator(mode="after")
    def validate_dates(self) -> "DatasetMetadata":
        if self.created is None or self.updated is None:
            return self
        created = isoparse(self.created)
        updated = isoparse(self.updated)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        if created > updated:
            raise ValueError("metadata.created must not be after metadata.updated")
        return self


class LogSource(ManifestModel):
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
    extensions: Dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Namespaced log-source extensions",
    )


class BundledFile(ManifestModel):
    """File bundled within the dataset directory."""

    path: str = Field(..., description="Relative path from dataset root")
    description: Optional[str] = Field(default=None, description="File description")
    format: str = Field(default="auto", description="File format (auto, jsonl, json, text, xml)")
    schema_type: Optional[str] = Field(
        default=None,
        description="Schema type (raw)",
        alias="schema"
    )
    event_count: Optional[int] = Field(
        default=None,
        ge=0,
        description="Expected runtime replay event count",
    )
    sourcetype: Optional[str] = Field(default=None, description="Source type identifier (e.g., WinEventLog:Security)")
    log_source: Optional[LogSource] = Field(
        default=None,
        description="Vendor-neutral log source classification"
    )
    platforms: Optional[Dict[str, JsonValue]] = Field(
        default=None,
        description="Platform-specific metadata (fully extensible, no validation)"
    )
    extensions: Dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Namespaced bundled-file extensions",
    )

    @field_validator('path')
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Validate a portable path inside the dataset directory."""
        return _validate_relative_path(v)

    @field_validator('format')
    @classmethod
    def validate_format(cls, v: str) -> str:
        """Validate file format."""
        if v not in SUPPORTED_FILE_FORMATS:
            raise ValueError(f"Invalid format: {v}. Must be one of {sorted(SUPPORTED_FILE_FORMATS)}")
        return v

    _validate_schema_type = field_validator("schema_type")(_validate_schema)
    _validate_sourcetype_value = field_validator("sourcetype")(_validate_sourcetype)


class FileReference(ManifestModel):
    """Reference to an external file (S3, GCS, HTTP)."""

    uri: str = Field(..., description="URI to external file")
    description: Optional[str] = Field(default=None, description="File description")
    format: str = Field(default="auto", description="File format (auto, jsonl, json, text, xml)")
    schema_type: Optional[str] = Field(
        default=None,
        description="Schema type (raw)",
        alias="schema"
    )
    checksum: Optional[str] = Field(
        default=None,
        description="Checksum in format 'algorithm:value' (e.g., sha256:abc123...)"
    )
    sourcetype: Optional[str] = Field(default=None, description="Source type identifier (e.g., WinEventLog:Security)")
    event_count: Optional[int] = Field(
        default=None,
        ge=0,
        description="Declared remote event count",
    )
    log_source: Optional[LogSource] = Field(
        default=None,
        description="Vendor-neutral log source classification"
    )
    platforms: Optional[Dict[str, JsonValue]] = Field(
        default=None,
        description="Platform-specific metadata (fully extensible, no validation)"
    )
    extensions: Dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Namespaced file-reference extensions",
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
        if v not in SUPPORTED_FILE_FORMATS:
            raise ValueError(f"Invalid format: {v}. Must be one of {sorted(SUPPORTED_FILE_FORMATS)}")
        return v

    _validate_schema_type = field_validator("schema_type")(_validate_schema)
    _validate_sourcetype_value = field_validator("sourcetype")(_validate_sourcetype)

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


class DatasetFiles(ManifestModel):
    """Collection of bundled and referenced files."""

    bundled: List[BundledFile] = Field(
        default_factory=list,
        description="Files included in dataset directory"
    )
    references: List[FileReference] = Field(
        default_factory=list,
        description="External file references (S3, GCS, HTTP)"
    )

    @model_validator(mode="after")
    def validate_unique_entries(self) -> "DatasetFiles":
        bundled_paths = [entry.path for entry in self.bundled]
        reference_uris = [entry.uri for entry in self.references]
        duplicate_paths = sorted({value for value in bundled_paths if bundled_paths.count(value) > 1})
        duplicate_uris = sorted({value for value in reference_uris if reference_uris.count(value) > 1})
        if duplicate_paths:
            raise ValueError(f"duplicate bundled file paths: {duplicate_paths}")
        if duplicate_uris:
            raise ValueError(f"duplicate file reference URIs: {duplicate_uris}")
        return self


class DatasetDependency(ManifestModel):
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


class DatasetEchoConfig(ManifestModel):
    """Runtime-supported timestamp echo defaults."""

    delta_factor: float = Field(default=1.0, gt=0)
    base_time: str = "auto"
    target_time: str = "now"
    prevent_future: bool = True
    ceiling_time: Optional[str] = "now"
    no_shift: bool = False
    shift_payload: bool = False

    @field_validator("base_time", "target_time", "ceiling_time")
    @classmethod
    def validate_time_expression(cls, value: Optional[str]) -> Optional[str]:
        if value in (None, "auto"):
            return value
        from ..utils.time import parse_time_expression

        try:
            parse_time_expression(value)
        except ValueError as exc:
            raise ValueError(f"Invalid time expression: {exc}") from exc
        return value


class DatasetTimestampPattern(ManifestModel):
    """Dataset-level default timestamp extraction rule."""

    field: str
    format: str = "iso8601"
    is_base: bool = False


class DatasetInputDefaults(ManifestModel):
    """Input defaults that can be applied to every file in a dataset."""

    format: str = "auto"
    timestamp_patterns: List[DatasetTimestampPattern] = Field(default_factory=list)
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("format")
    @classmethod
    def validate_format(cls, value: str) -> str:
        if value not in SUPPORTED_FILE_FORMATS:
            raise ValueError(
                f"Invalid format: {value}. Must be one of {sorted(SUPPORTED_FILE_FORMATS)}"
            )
        return value


class DatasetDefaults(ManifestModel):
    """Default runtime configuration, preserving authored legacy keys."""

    echo: Optional[DatasetEchoConfig] = Field(default=None, description="Default echo config")
    replay: Optional[DatasetEchoConfig] = Field(
        default=None,
        description="Deprecated source key retained for lossless compatibility",
    )
    schema_type: Optional[str] = Field(
        default=None,
        description="Default schema for files",
        alias="schema",
    )
    input: Optional[DatasetInputDefaults] = Field(default=None)
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)

    _validate_schema_type = field_validator("schema_type")(_validate_schema)

    @model_validator(mode="after")
    def validate_echo_aliases(self) -> "DatasetDefaults":
        if (
            {"echo", "replay"}.issubset(self.model_fields_set)
            and self.echo != self.replay
        ):
            raise ValueError("defaults.echo and defaults.replay cannot disagree")
        return self

    @property
    def effective_echo(self) -> Optional[DatasetEchoConfig]:
        """Return the runtime echo defaults without mutating the source model."""
        return self.echo or self.replay


class HostEnvironment(ManifestModel):
    hostname: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    domain: Optional[str] = None
    workgroup: Optional[str] = None
    platform: Optional[str] = None
    network: Optional[str] = None
    ip: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class ExecutionEnvironment(ManifestModel):
    user: Optional[str] = None
    method: Optional[str] = None
    tool: Optional[str] = None
    tool_version: Optional[str] = None
    isolation: Optional[str] = None
    binary: Optional[str] = None
    args: List[str] = Field(default_factory=list)
    launch: Optional[str] = None
    actor: Optional[str] = None
    patient_zero: Optional[str] = None
    pivot_account: Optional[str] = None
    ot_target: Optional[str] = None
    c2: Optional[str] = None
    target_endpoint: Optional[str] = None
    vulnerability: Optional[str] = None
    targets: Optional[str] = None
    rce_principal: Optional[str] = None
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class CollectionEnvironment(ManifestModel):
    method: Optional[str] = None
    collector: Optional[str] = None
    channels: List[str] = Field(default_factory=list)
    sensor: Optional[str] = None
    shipper: Optional[str] = None
    ingest: Optional[str] = None
    defender: Optional[str] = None
    sysmon: Optional[str] = None
    audit_policy: Optional[str] = None
    capture_proxy: Optional[str] = None
    delivery: Optional[str] = None
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class SysmonEnvironment(ManifestModel):
    installed: Optional[bool] = None
    version: Optional[str] = None
    config_source: Optional[str] = None
    config_hash: Optional[str] = None
    hashing_algorithms: List[str] = Field(default_factory=list)
    network_connect: Optional[bool] = None
    image_load: Optional[bool] = None
    dns_query: Optional[bool] = None
    process_create_mode: Optional[str] = None
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class WindowsAuditPolicy(ManifestModel):
    process_creation: Optional[str] = None
    process_termination: Optional[str] = None
    command_line_logging: Optional[bool] = None
    logon: Optional[str] = None
    logoff: Optional[str] = None
    special_logon: Optional[str] = None
    object_access: Optional[str] = None
    registry: Optional[str] = None
    file_system: Optional[str] = None
    account_management: Optional[str] = None
    policy_change: Optional[str] = None
    privilege_use: Optional[str] = None
    token_right_adjusted: Optional[str] = None
    kerberos: Optional[str] = None
    credential_validation: Optional[str] = None
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class PowerShellEnvironment(ManifestModel):
    script_block_logging: Optional[bool] = None
    script_block_invocation: Optional[bool] = None
    module_logging: Optional[bool] = None
    module_logging_scope: Optional[str] = None
    transcription: Optional[bool] = None
    constrained_language_mode: Optional[bool] = None
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class EndpointProtectionEnvironment(ManifestModel):
    product: Optional[str] = None
    version: Optional[str] = None
    real_time_protection: Optional[bool] = None
    behavior_monitoring: Optional[bool] = None
    amsi_enabled: Optional[bool] = None
    tamper_protection: Optional[bool] = None
    cloud_protection: Optional[bool] = None
    signature_version: Optional[str] = None
    antivirus_enabled: Optional[bool] = None
    disabled_via: Optional[str] = None
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class WindowsEnvironment(ManifestModel):
    sysmon: Optional[SysmonEnvironment] = None
    audit_policy: Optional[WindowsAuditPolicy] = None
    powershell: Optional[PowerShellEnvironment] = None
    endpoint_protection: Optional[EndpointProtectionEnvironment] = None
    etw_providers: List[str] = Field(default_factory=list)
    wef_enabled: Optional[bool] = None
    event_forwarding: Dict[str, JsonValue] = Field(default_factory=dict)
    log_sizes: Dict[str, JsonValue] = Field(default_factory=dict)
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class LinuxEnvironment(ManifestModel):
    auditd: Dict[str, JsonValue] = Field(default_factory=dict)
    security_module: Dict[str, JsonValue] = Field(default_factory=dict)
    endpoint_protection: Dict[str, JsonValue] = Field(default_factory=dict)
    syslog: Dict[str, JsonValue] = Field(default_factory=dict)
    ebpf_monitoring: Optional[str] = None
    shell_logging: Optional[bool] = None
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class MacOSEnvironment(ManifestModel):
    endpoint_security_framework: Optional[bool] = None
    endpoint_protection: Dict[str, JsonValue] = Field(default_factory=dict)
    unified_logging: Dict[str, JsonValue] = Field(default_factory=dict)
    gatekeeper: Optional[bool] = None
    sip_enabled: Optional[bool] = None
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class CloudEnvironment(ManifestModel):
    provider: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    logging: Dict[str, JsonValue] = Field(default_factory=dict)
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class ZeekEnvironment(ManifestModel):
    installed: Optional[bool] = None
    logs: List[str] = Field(default_factory=list)
    capture_point: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class ProxyEnvironment(ManifestModel):
    type: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=0, le=65535)
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class NetworkEnvironment(ManifestModel):
    capture_type: Optional[str] = None
    capture_point: Optional[str] = None
    sensor: Optional[str] = None
    bpf_filter: Optional[str] = None
    protocols_monitored: List[str] = Field(default_factory=list)
    encryption_visibility: Optional[str] = None
    zeek: Optional[ZeekEnvironment] = None
    proxy: Optional[ProxyEnvironment] = None
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class ContainerEnvironment(ManifestModel):
    runtime: Optional[str] = None
    orchestrator: Optional[str] = None
    orchestrator_version: Optional[str] = None
    cluster: Optional[str] = None
    namespace: Optional[str] = None
    monitoring: Dict[str, JsonValue] = Field(default_factory=dict)
    logging: Dict[str, JsonValue] = Field(default_factory=dict)
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class DatasetEnvironment(ManifestModel):
    host: Optional[HostEnvironment] = None
    collection: Optional[CollectionEnvironment] = None
    execution: Optional[ExecutionEnvironment] = None
    windows: Optional[WindowsEnvironment] = None
    linux: Optional[LinuxEnvironment] = None
    macos: Optional[MacOSEnvironment] = None
    cloud: Optional[CloudEnvironment] = None
    network: Optional[NetworkEnvironment] = None
    container: Optional[ContainerEnvironment] = None
    versions: Dict[str, str] = Field(default_factory=dict)
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class ProvenanceBuildHost(ManifestModel):
    hostname: Optional[str] = None
    vmid: Optional[int] = None
    ip: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class ProvenanceEpochRange(ManifestModel):
    start_epoch: int
    end_epoch: int

    @model_validator(mode="after")
    def validate_order(self) -> "ProvenanceEpochRange":
        if self.start_epoch > self.end_epoch:
            raise ValueError("start_epoch must not be after end_epoch")
        return self


class ProvenanceTimeRange(ManifestModel):
    start: str
    end: str

    @model_validator(mode="after")
    def validate_order(self) -> "ProvenanceTimeRange":
        if _parse_aware_timestamp(self.start, "start") > _parse_aware_timestamp(self.end, "end"):
            raise ValueError("start must not be after end")
        return self


class ProvenanceCampaignRange(ManifestModel):
    t0: str
    t_end: str

    @model_validator(mode="after")
    def validate_order(self) -> "ProvenanceCampaignRange":
        if _parse_aware_timestamp(self.t0, "t0") > _parse_aware_timestamp(self.t_end, "t_end"):
            raise ValueError("t0 must not be after t_end")
        return self


class ProvenanceTranslation(ManifestModel):
    from_: str = Field(alias="from")
    to: str
    reason: str


class ProvenanceBuild(ManifestModel):
    host: Optional[Union[ProvenanceBuildHost, str]] = None
    timestamps: Optional[ProvenanceEpochRange] = None
    tool: Optional[str] = None
    notes: Optional[str] = None
    surface: Optional[str] = None
    ingest_time_collapsed_to_event_time: Optional[bool] = None
    filtered_orchestration_events: Optional[int] = Field(default=None, ge=0)
    window_utc: Optional[ProvenanceTimeRange] = None
    campaign_utc: Optional[ProvenanceCampaignRange] = None
    translation: Optional[ProvenanceTranslation] = None
    seed_detection: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class ProvenanceVerification(ManifestModel):
    source_counts: Dict[str, int] = Field(default_factory=dict)
    dest_counts: Dict[str, int] = Field(default_factory=dict)
    signatures: Dict[str, int] = Field(default_factory=dict)
    window_epoch: Optional[List[int]] = None
    scaffolding_leaks: Optional[int] = Field(default=None, ge=0)
    lineage_clean: Optional[bool] = None
    technique_parent: List[str] = Field(default_factory=list)
    total_events: Optional[int] = Field(default=None, ge=0)
    note: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_counts_and_window(self) -> "ProvenanceVerification":
        for label, counts in (
            ("source_counts", self.source_counts),
            ("dest_counts", self.dest_counts),
            ("signatures", self.signatures),
        ):
            negative = sorted(key for key, value in counts.items() if value < 0)
            if negative:
                raise ValueError(f"{label} contains negative counts: {negative}")
        if self.window_epoch is not None:
            if len(self.window_epoch) != 2:
                raise ValueError("window_epoch must contain [start, end]")
            if self.window_epoch[0] > self.window_epoch[1]:
                raise ValueError("window_epoch start must not be after end")
        return self


class ProvenanceRegenerated(ManifestModel):
    from_: str = Field(alias="from")
    reason: str
    total_events: int = Field(ge=0)


class DatasetProvenance(ManifestModel):
    build: ProvenanceBuild
    verification: ProvenanceVerification
    regenerated: Optional[ProvenanceRegenerated] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)


class BadactorsQualityGates(ManifestModel):
    scaffolding_hard_leaks_zero: bool
    no_future_events: bool
    lineage_clean: bool
    required_signatures_present: bool
    ingest_integrity: bool


class BadactorsQualityComponents(ManifestModel):
    coverage: float = Field(ge=0, le=1)
    signal_completeness: float = Field(ge=0, le=1)
    attribution: float = Field(ge=0, le=1)
    purity: float = Field(ge=0, le=1)
    integrity: float = Field(ge=0, le=1)


class BadactorsQualityVisibility(ManifestModel):
    coverage: float = Field(ge=0, le=1)
    observable_primitives: int = Field(ge=0)
    observed_primitives: int = Field(ge=0)
    blind_primitives: List[str] = Field(default_factory=list)
    missed_observable: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_observed(self) -> "BadactorsQualityVisibility":
        if self.observed_primitives > self.observable_primitives:
            raise ValueError("observed_primitives cannot exceed observable_primitives")
        return self


class BadactorsQualityAttribution(ManifestModel):
    attributed: int = Field(ge=0)
    technique_events: int = Field(ge=0)
    ambient_filtered: int = Field(ge=0)
    per_step: Dict[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_attribution(self) -> "BadactorsQualityAttribution":
        if self.attributed > self.technique_events:
            raise ValueError("attributed cannot exceed technique_events")
        negative = sorted(key for key, value in self.per_step.items() if value < 0)
        if negative:
            raise ValueError(f"per_step contains negative counts: {negative}")
        return self


class BadactorsQualityBestOfN(ManifestModel):
    runs: int = Field(ge=1)
    selected: str
    all_Q: Dict[str, float]
    selection: str

    @model_validator(mode="after")
    def validate_runs(self) -> "BadactorsQualityBestOfN":
        if self.runs != len(self.all_Q):
            raise ValueError("best_of_n.runs must equal the number of all_Q entries")
        if self.selected not in self.all_Q:
            raise ValueError("best_of_n.selected must name an all_Q entry")
        invalid = sorted(key for key, value in self.all_Q.items() if not 0 <= value <= 1)
        if invalid:
            raise ValueError(f"best_of_n.all_Q values must be between 0 and 1: {invalid}")
        return self


class BadactorsQuality(ManifestModel):
    Q: float = Field(ge=0, le=1)
    disqualified: bool
    gates: BadactorsQualityGates
    components: BadactorsQualityComponents
    weights: BadactorsQualityComponents
    visibility: BadactorsQualityVisibility
    attribution: BadactorsQualityAttribution
    selection: Optional[str] = None
    spec: str
    best_of_n: BadactorsQualityBestOfN
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_score(self) -> "BadactorsQuality":
        expected_weights = {
            "coverage": 0.4,
            "signal_completeness": 0.2,
            "attribution": 0.2,
            "purity": 0.1,
            "integrity": 0.1,
        }
        actual_weights = self.weights.model_dump()
        if any(
            abs(actual_weights[name] - expected) > 1e-6
            for name, expected in expected_weights.items()
        ):
            raise ValueError(
                "badactors_quality weights must match badactors quality v1: "
                "coverage=0.4, signal_completeness=0.2, attribution=0.2, "
                "purity=0.1, integrity=0.1"
            )
        weighted_score = round(sum(
            getattr(self.components, name) * getattr(self.weights, name)
            for name in ("coverage", "signal_completeness", "attribution", "purity", "integrity")
        ), 4)
        expected_disqualified = not all(self.gates.model_dump().values())
        if self.disqualified != expected_disqualified:
            raise ValueError("badactors_quality.disqualified must equal not all(gates)")
        expected_score = 0.0 if expected_disqualified else weighted_score
        if abs(self.Q - expected_score) > 1e-4:
            raise ValueError(
                "badactors_quality.Q must be zero when disqualified, otherwise it must "
                "match the rounded weighted component score"
            )
        if abs(self.components.coverage - self.visibility.coverage) > 1e-4:
            raise ValueError(
                "badactors_quality components.coverage must match visibility.coverage"
            )
        visibility_ratio = (
            self.visibility.observed_primitives / self.visibility.observable_primitives
            if self.visibility.observable_primitives
            else 1.0
        )
        if abs(self.visibility.coverage - visibility_ratio) > 1e-4:
            raise ValueError(
                "badactors_quality visibility.coverage must equal observed_primitives / "
                "observable_primitives, or 1 when there are no observable primitives"
            )
        attribution_ratio = (
            self.attribution.attributed / self.attribution.technique_events
            if self.attribution.technique_events
            else 0.0
        )
        if abs(self.components.attribution - attribution_ratio) > 1e-4:
            raise ValueError(
                "badactors_quality components.attribution must equal attributed / "
                "technique_events, or 0 when there are no technique events"
            )
        total_events = (
            self.attribution.technique_events + self.attribution.ambient_filtered
        )
        purity_ratio = (
            self.attribution.technique_events / total_events if total_events else 0.0
        )
        if abs(self.components.purity - purity_ratio) > 1e-4:
            raise ValueError(
                "badactors_quality components.purity must equal technique_events / "
                "(technique_events + ambient_filtered), or 0 when both are zero"
            )
        expected_integrity = 1.0 if self.gates.ingest_integrity else 0.0
        if abs(self.components.integrity - expected_integrity) > 1e-4:
            raise ValueError(
                "badactors_quality components.integrity must be 1 when the "
                "ingest_integrity gate passes and 0 when it fails"
            )
        if abs(self.best_of_n.all_Q[self.best_of_n.selected] - self.Q) > 1e-4:
            raise ValueError("badactors_quality selected best_of_n score must equal Q")
        if abs(
            self.best_of_n.all_Q[self.best_of_n.selected]
            - max(self.best_of_n.all_Q.values())
        ) > 1e-4:
            raise ValueError("badactors_quality best_of_n.selected must name a highest-Q run")
        return self



# ---------------------------------------------------------------------------
# Scenario entities, observables, and kill chain (STIX 2.1 vocabulary)
# ---------------------------------------------------------------------------
# These three blocks describe WHO and WHAT is in an attack dataset in the same
# vocabulary as the companion Attack Flow file, which is a STIX 2.1 bundle:
#   entities    -> STIX Domain Objects (infrastructure, identity, threat-actor,
#                  tool, malware) or the user-account observable, each exposed in
#                  the flow as an attack-asset
#   observables -> STIX Cyber-observable Objects (ipv4-addr, domain-name, file,
#                  process, windows-registry-key, ...) plus a STIX indicator when
#                  the observable is an indicator of compromise
#   kill_chain  -> ordered stages that become attack-action objects
# Entries carry a local `id` handle so stages and entities can reference each
# other; the Attack Flow builder resolves handles to STIX identifiers.

STIX_ENTITY_TYPES = {
    "infrastructure", "identity", "threat-actor", "intrusion-set", "campaign",
    "tool", "malware", "user-account",
}
STIX_OBSERVABLE_TYPES = {
    "ipv4-addr", "ipv6-addr", "mac-addr", "domain-name", "url", "email-addr",
    "email-message", "file", "directory", "process", "user-account",
    "windows-registry-key", "network-traffic", "software", "mutex",
    "x509-certificate", "artifact", "autonomous-system", "indicator",
}
# Observable types whose single defining property is `value`.
STIX_VALUE_OBSERVABLES = {"ipv4-addr", "ipv6-addr", "mac-addr", "domain-name", "url", "email-addr"}
# STIX 2.1 indicator-type-ov
STIX_INDICATOR_TYPES = {
    "anomalous-activity", "anonymization", "benign", "compromised",
    "malicious-activity", "attribution", "unknown",
}
# MITRE ATT&CK Enterprise tactic slugs (kill_chain_name "mitre-attack") -> tactic id
ATTACK_TACTICS = {
    "reconnaissance": "TA0043", "resource-development": "TA0042",
    "initial-access": "TA0001", "execution": "TA0002", "persistence": "TA0003",
    "privilege-escalation": "TA0004", "defense-evasion": "TA0005",
    "credential-access": "TA0006", "discovery": "TA0007",
    "lateral-movement": "TA0008", "collection": "TA0009",
    "command-and-control": "TA0011", "exfiltration": "TA0010", "impact": "TA0040",
    # ATT&CK v20 renamed TA0005 (Defense Evasion) to Stealth and added TA0112
    # (Defense Impairment). The legacy slug stays valid for existing manifests.
    "stealth": "TA0005", "defense-impairment": "TA0112",
}
_HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _check_handle(v: str) -> str:
    if not _HANDLE_RE.match(v):
        raise ValueError(
            f"id must be a lowercase handle (letters, digits, '.', '_', '-'): {v!r}"
        )
    return v


def _check_techniques(ids: List[str]) -> List[str]:
    for t in ids:
        if not re.match(r"^T\d{4}(\.\d{3})?$", t):
            raise ValueError(f"technique must look like T1234 or T1234.001: {t!r}")
    duplicates = sorted({technique for technique in ids if ids.count(technique) > 1})
    if duplicates:
        raise ValueError(f"technique ids must be unique: {duplicates}")
    return ids


class ScenarioEntity(ManifestModel):
    """A host, account, organization, adversary, tool, or attacker infrastructure.

    `type` is the STIX 2.1 object type used to represent it. STIX-specific
    properties (``infrastructure_types``, ``identity_class``, ``account_login``,
    ``account_type``, ``is_service_account``, ``threat_actor_types``, ``sectors``,
    ``tool_types``, ``aliases``, ...) are passed through as given and validated
    by the STIX library when the Attack Flow is built.
    """

    id: str = Field(..., description="Local handle referenced by kill_chain stages and other entities")
    type: str = Field(..., description="STIX 2.1 type: infrastructure, identity, threat-actor, tool, malware, user-account")
    name: Optional[str] = Field(default=None, description="Display name (required for every type except user-account)")
    description: Optional[str] = Field(default=None)
    role: Optional[str] = Field(default=None, description="Role in the scenario, e.g. patient-zero, pivot, target, attacker, victim")
    observables: List[str] = Field(
        default_factory=list,
        description="Handles of observables that compose this entity (an infrastructure's IP, FQDN, accounts); emitted as consists-of",
    )
    infrastructure_types: List[str] = Field(default_factory=list)
    identity_class: Optional[str] = None
    account_login: Optional[str] = None
    user_id: Optional[str] = None
    account_type: Optional[str] = None
    is_service_account: Optional[bool] = None
    is_privileged: Optional[bool] = None
    threat_actor_types: List[str] = Field(default_factory=list)
    sectors: List[str] = Field(default_factory=list)
    tool_types: List[str] = Field(default_factory=list)
    aliases: List[str] = Field(default_factory=list)
    properties: Dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Additional STIX properties passed to the Attack Flow builder",
    )

    @field_validator("id")
    @classmethod
    def _v_id(cls, v: str) -> str:
        return _check_handle(v)

    @field_validator("type")
    @classmethod
    def _v_type(cls, v: str) -> str:
        if v not in STIX_ENTITY_TYPES:
            raise ValueError(f"entity type must be one of {sorted(STIX_ENTITY_TYPES)}: {v!r}")
        return v

    @model_validator(mode="after")
    def _v_required_by_type(self) -> "ScenarioEntity":
        if self.type == "user-account":
            if not self.account_login and not self.user_id:
                raise ValueError(f"entity {self.id!r}: user-account needs account_login or user_id")
        elif not self.name:
            raise ValueError(f"entity {self.id!r}: {self.type} needs a name")
        if self.type == "identity" and not self.identity_class:
            raise ValueError(f"entity {self.id!r}: identity needs identity_class (individual, organization, system, group, class, unknown)")
        return self


class ScenarioObservable(ManifestModel):
    """A STIX cyber-observable present in the data, optionally marked as an indicator.

    `type` is a STIX 2.1 observable type (or ``indicator`` for a pattern-only
    artifact such as a named pipe, carrying ``pattern`` and ``pattern_type``).
    When ``indicator_types`` is set the builder also emits a STIX indicator with
    a pattern over the observable, the given kill-chain phases and techniques,
    and the confidence. STIX-specific properties (``hashes``, ``key``,
    ``values``, ``command_line``, ``account_login``, ...) pass through as given.
    """

    id: str = Field(..., description="Local handle referenced by entities and kill_chain stages")
    type: str = Field(..., description="STIX 2.1 observable type, or 'indicator' for a pattern-only artifact")
    value: Optional[str] = Field(default=None, description="The value for ipv4-addr, ipv6-addr, mac-addr, domain-name, url, email-addr")
    name: Optional[str] = Field(default=None, description="Name for file, process, mutex, software, or an indicator")
    description: Optional[str] = Field(default=None)
    indicator_types: List[str] = Field(default_factory=list, description="STIX indicator-type-ov values; empty means a plain observable, not an indicator")
    kill_chain_phases: List[str] = Field(default_factory=list, description="ATT&CK tactic slugs (kill_chain_name mitre-attack)")
    techniques: List[str] = Field(default_factory=list, description="ATT&CK technique ids this observable evidences")
    confidence: Optional[int] = Field(default=None, ge=0, le=100, description="STIX confidence, 0 to 100")
    first_seen: Optional[str] = Field(default=None, description="ISO8601 UTC first appearance in the data")
    last_seen: Optional[str] = Field(default=None, description="ISO8601 UTC last appearance in the data")
    pattern: Optional[str] = Field(default=None, description="Pattern for type indicator")
    pattern_type: Optional[str] = Field(default=None, description="stix, sigma, yara, snort, suricata, pcre")
    rule: Optional[str] = Field(default=None, description="Path or URL to an external detection rule file; use instead of an inline pattern. Sigma rules are referenced this way, never inlined into the attack-flow bundle.")
    date: Optional[str] = None
    hashes: Dict[str, str] = Field(default_factory=dict)
    is_multipart: Optional[bool] = None
    key: Optional[str] = None
    message_id: Optional[str] = None
    path: Optional[str] = None
    size: Optional[int] = Field(default=None, ge=0)
    subject: Optional[str] = None
    values: List[Dict[str, JsonValue]] = Field(default_factory=list)
    command_line: Optional[str] = None
    pid: Optional[int] = Field(default=None, ge=0)
    account_login: Optional[str] = None
    user_id: Optional[str] = None
    properties: Dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Additional STIX properties passed to the Attack Flow builder",
    )

    @field_validator("id")
    @classmethod
    def _v_id(cls, v: str) -> str:
        return _check_handle(v)

    @field_validator("type")
    @classmethod
    def _v_type(cls, v: str) -> str:
        if v not in STIX_OBSERVABLE_TYPES:
            raise ValueError(f"observable type must be a STIX observable type or 'indicator': {v!r}")
        return v

    @field_validator("indicator_types")
    @classmethod
    def _v_ind(cls, v: List[str]) -> List[str]:
        bad = [x for x in v if x not in STIX_INDICATOR_TYPES]
        if bad:
            raise ValueError(f"indicator_types must be from {sorted(STIX_INDICATOR_TYPES)}: {bad}")
        return v

    @field_validator("kill_chain_phases")
    @classmethod
    def _v_kcp(cls, v: List[str]) -> List[str]:
        bad = [x for x in v if x not in ATTACK_TACTICS]
        if bad:
            raise ValueError(f"kill_chain_phases must be ATT&CK tactic slugs {sorted(ATTACK_TACTICS)}: {bad}")
        return v

    @field_validator("techniques")
    @classmethod
    def _v_tech(cls, v: List[str]) -> List[str]:
        return _check_techniques(v)

    @model_validator(mode="after")
    def _v_required_by_type(self) -> "ScenarioObservable":
        if self.type in STIX_VALUE_OBSERVABLES and not self.value:
            raise ValueError(f"observable {self.id!r}: {self.type} needs a value")
        if self.type == "file" and not (self.name or self.hashes):
            raise ValueError(f"observable {self.id!r}: file needs a name or hashes")
        if self.type == "windows-registry-key" and not self.key:
            raise ValueError(f"observable {self.id!r}: windows-registry-key needs key")
        if self.type == "indicator":
            if bool(self.pattern) != bool(self.pattern_type):
                raise ValueError(f"observable {self.id!r}: pattern and pattern_type must be set together")
            if not self.pattern and not self.rule:
                raise ValueError(f"observable {self.id!r}: indicator needs pattern and pattern_type, or a rule reference")
        if self.type == "user-account" and not (self.account_login or self.user_id):
            raise ValueError(f"observable {self.id!r}: user-account needs account_login or user_id")
        if self.first_seen is not None:
            first = _parse_aware_timestamp(self.first_seen, f"observable {self.id}.first_seen")
            if self.last_seen is not None:
                last = _parse_aware_timestamp(self.last_seen, f"observable {self.id}.last_seen")
                if first > last:
                    raise ValueError(f"observable {self.id!r}: first_seen must not be after last_seen")
        elif self.last_seen is not None:
            _parse_aware_timestamp(self.last_seen, f"observable {self.id}.last_seen")
        return self


class KillChainStage(ManifestModel):
    """One ordered stage of the attack; becomes one attack-action per technique."""

    id: str = Field(..., description="Stage handle, e.g. S0")
    name: str = Field(..., description="Short stage name")
    description: Optional[str] = Field(default=None)
    tactic: Optional[str] = Field(default=None, description="ATT&CK tactic slug for the stage")
    techniques: List[str] = Field(..., min_length=1, description="ATT&CK technique ids, one attack-action each")
    assets: List[str] = Field(default_factory=list, description="Entity handles involved (attack-action asset_refs)")
    observables: List[str] = Field(default_factory=list, description="Observable handles evidencing the stage (related-to the action)")
    execution_start: Optional[str] = Field(default=None, description="ISO8601 UTC")
    execution_end: Optional[str] = Field(default=None, description="ISO8601 UTC")
    next: Optional[List[str]] = Field(default=None, description="Following stage handles; defaults to the next stage in order")

    @field_validator("id")
    @classmethod
    def _v_id(cls, v: str) -> str:
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", v):
            raise ValueError(f"stage id must be a simple handle: {v!r}")
        return v

    @field_validator("tactic")
    @classmethod
    def _v_tactic(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ATTACK_TACTICS:
            raise ValueError(f"tactic must be an ATT&CK tactic slug {sorted(ATTACK_TACTICS)}: {v!r}")
        return v

    @field_validator("techniques")
    @classmethod
    def _v_tech(cls, v: List[str]) -> List[str]:
        return _check_techniques(v)

    @model_validator(mode="after")
    def validate_execution_order(self) -> "KillChainStage":
        if self.execution_start is not None:
            start = _parse_aware_timestamp(
                self.execution_start, f"stage {self.id}.execution_start"
            )
            if self.execution_end is not None:
                end = _parse_aware_timestamp(
                    self.execution_end, f"stage {self.id}.execution_end"
                )
                if start > end:
                    raise ValueError(
                        f"stage {self.id!r}: execution_start must not be after execution_end"
                    )
        elif self.execution_end is not None:
            _parse_aware_timestamp(self.execution_end, f"stage {self.id}.execution_end")
        return self


CASE_DISPOSITIONS = {"true-positive", "benign-positive", "false-positive", "inconclusive"}

ALERT_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
ALERT_TEMPLATE_FIELDS = {"count", "first_seen", "last_seen"}
_SQL_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _check_alert_template(v: str, label: str) -> str:
    """Allow only the evidence placeholders in alert text; reject stray braces."""
    if not v or not v.strip():
        raise ValueError(f"{label} must be non-empty")
    names = set(re.findall(r"\{([^{}]*)\}", v))
    unknown = names - ALERT_TEMPLATE_FIELDS
    if unknown:
        raise ValueError(
            f"{label} uses unknown placeholder(s) {sorted(unknown)}; allowed: {sorted(ALERT_TEMPLATE_FIELDS)}"
        )
    stripped = re.sub(r"\{(?:count|first_seen|last_seen)\}", "", v)
    if "{" in stripped or "}" in stripped:
        raise ValueError(f"{label} has an unbalanced or nested brace")
    return v


class AlertEvidence(ManifestModel):
    """The events an entry alert is about: the query that must match them in the loaded catalog.

    A manual (API-created) alert carries no linked events, so this is the machine-checkable
    statement of what the alert covers. The loader runs it before creating the alert and
    refuses to create one when the evidence is missing or the count is off.
    """

    table: str = Field(..., description="Table name in the target catalog schema (e.g. zeek_conn)")
    where: str = Field(..., description="Databricks SQL boolean predicate over that table selecting the alert's events; the SQL rendering of the case's Sigma rule")
    time_column: str = Field(default="time", description="Event-time column used for first_seen / last_seen")
    expected_count: int = Field(..., ge=1, description="Number of rows the predicate matches in a correct load")
    count_tolerance: int = Field(default=0, ge=0, description="Allowed absolute deviation from expected_count")

    @field_validator("table", "time_column")
    @classmethod
    def _v_identifier(cls, v: str) -> str:
        if not _SQL_IDENTIFIER.match(v):
            raise ValueError(f"must be a plain SQL identifier: {v!r}")
        return v

    @field_validator("where")
    @classmethod
    def _v_where(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("where must be non-empty")
        if ";" in v:
            raise ValueError("where must be a single predicate (no ';')")
        return v


class AlertSpec(ManifestModel):
    """The entry alert for a case, created through the Lakewatch alert API by the loader.

    Title and description are the alert's full content (there are no linked events), so they
    must name the entities and pivot an analyst needs, and must not state the verdict.
    ``{count}``, ``{first_seen}``, and ``{last_seen}`` are filled from the evidence query.
    """

    title: str = Field(..., description="Alert title; immutable once created")
    description: str = Field(..., description="Alert body: behavior, entities, time, and investigative pivot; no verdict")
    severity: str = Field(..., description="One of Critical, High, Medium, Low, Informational")
    alert_type: Literal["SECURITY_ALERT"] = "SECURITY_ALERT"
    alert_state: Literal["OPEN", "IN_PROGRESS"] = "OPEN"
    collection: str = Field(default="triage_queue", description="Alert collection name in the target catalog schema")
    anchors: List[str] = Field(default_factory=list, description="Strings (hosts, users, indicators) that must appear in the evidence rows")
    annotations: Dict[str, str] = Field(default_factory=dict, description="Extra alert annotations; keep scenario and verdict words out")
    evidence: AlertEvidence

    @field_validator("title")
    @classmethod
    def _v_title(cls, v: str) -> str:
        return _check_alert_template(v, "alert.title")

    @field_validator("description")
    @classmethod
    def _v_description(cls, v: str) -> str:
        return _check_alert_template(v, "alert.description")

    @field_validator("severity")
    @classmethod
    def _v_severity(cls, v: str) -> str:
        if v not in ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(ALERT_SEVERITIES)}: {v!r}")
        return v

    @field_validator("collection")
    @classmethod
    def _v_collection(cls, v: str) -> str:
        if not _SQL_IDENTIFIER.match(v):
            raise ValueError(f"collection must be a plain identifier: {v!r}")
        return v

    @field_validator("anchors")
    @classmethod
    def _v_anchors(cls, v: List[str]) -> List[str]:
        if any(not a or not a.strip() for a in v):
            raise ValueError("anchors must be non-empty strings")
        return v


class ScenarioCase(ManifestModel):
    """One eval case: an entry detection paired with its expected verdict."""

    id: str = Field(..., description="Case handle, e.g. cloud-exfil-entry")
    name: str = Field(..., description="Short case name")
    rule: str = Field(..., description="Path or URL to the detection rule that seeds the case; usually the dataset's entry-point Sigma rule")
    disposition: str = Field(..., description="Expected disposition: true-positive, benign-positive, false-positive, or inconclusive (the supplied evidence does not support a decisive verdict)")
    benign_explanations: List[str] = Field(default_factory=list, description="Defensible-but-wrong conclusions with their reasons; distractor ground truth for judging")
    notes: Optional[str] = None
    alert: Optional[AlertSpec] = Field(default=None, description="Entry alert created through the Lakewatch alert API by `echolake create-lakewatch-alerts`; rendered into the README by `echolake render-alerts`")

    @field_validator("id")
    @classmethod
    def _v_id(cls, v: str) -> str:
        return _check_handle(v)

    @field_validator("disposition")
    @classmethod
    def _v_disposition(cls, v: str) -> str:
        if v not in CASE_DISPOSITIONS:
            raise ValueError(f"disposition must be one of {sorted(CASE_DISPOSITIONS)}: {v!r}")
        return v


class DatasetManifest(ManifestModel):
    """Complete dataset manifest (dataset.yaml)."""

    manifest_version: Literal["1.0.0"] = MANIFEST_VERSION
    metadata: DatasetMetadata
    files: DatasetFiles = Field(default_factory=DatasetFiles)
    dependencies: List[DatasetDependency] = Field(default_factory=list)
    defaults: Optional[DatasetDefaults] = Field(default=None)
    environment: Optional[DatasetEnvironment] = None
    provenance: Optional[DatasetProvenance] = None
    badactors_quality: Optional[BadactorsQuality] = None
    entities: List[ScenarioEntity] = Field(default_factory=list, description="Scenario entities in STIX 2.1 vocabulary")
    observables: List[ScenarioObservable] = Field(default_factory=list, description="Observables and indicators present in the data")
    kill_chain: List[KillChainStage] = Field(default_factory=list, description="Ordered attack stages; source of the Attack Flow actions")
    cases: List[ScenarioCase] = Field(default_factory=list, description="Eval cases pairing entry detection rules with expected dispositions and benign explanations")
    notes: Optional[str] = None
    extensions: Dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _v_scenario_refs(self) -> "DatasetManifest":
        """Every handle reference must resolve, and handles must be unique."""
        ent = [e.id for e in self.entities]
        obs = [o.id for o in self.observables]
        stg = [k.id for k in self.kill_chain]
        cse = [c.id for c in self.cases]
        for label, ids in (("entities", ent), ("observables", obs), ("kill_chain", stg), ("cases", cse)):
            dup = {x for x in ids if ids.count(x) > 1}
            if dup:
                raise ValueError(f"duplicate {label} ids: {sorted(dup)}")
        obs_set, ent_set, stg_set = set(obs), set(ent), set(stg)
        for e in self.entities:
            missing = [h for h in e.observables if h not in obs_set]
            if missing:
                raise ValueError(f"entity {e.id!r} references unknown observables: {missing}")
        for k in self.kill_chain:
            missing = [h for h in k.assets if h not in ent_set]
            if missing:
                raise ValueError(f"stage {k.id!r} references unknown entities: {missing}")
            missing = [h for h in k.observables if h not in obs_set]
            if missing:
                raise ValueError(f"stage {k.id!r} references unknown observables: {missing}")
            if k.next:
                missing = [h for h in k.next if h not in stg_set]
                if missing:
                    raise ValueError(f"stage {k.id!r} references unknown next stages: {missing}")
        if self.kill_chain and not self.entities:
            raise ValueError("kill_chain requires at least one entity")
        if self.kill_chain and self.metadata.attack_flow is None:
            raise ValueError("kill_chain requires metadata.attack_flow")

        declared_techniques = {
            technique.id
            for technique in (
                self.metadata.mitre_attack.techniques
                if self.metadata.mitre_attack is not None
                else []
            )
        }
        used_techniques = {
            technique
            for observable in self.observables
            for technique in observable.techniques
        }
        used_techniques.update(
            technique for stage in self.kill_chain for technique in stage.techniques
        )
        undeclared = sorted(used_techniques - declared_techniques)
        if undeclared:
            raise ValueError(f"scenario uses undeclared MITRE ATT&CK techniques: {undeclared}")

        dependency_refs = [dependency.dataset for dependency in self.dependencies]
        duplicate_dependencies = sorted(
            {value for value in dependency_refs if dependency_refs.count(value) > 1}
        )
        if duplicate_dependencies:
            raise ValueError(f"duplicate dataset dependencies: {duplicate_dependencies}")

        bundled_counts = [entry.event_count for entry in self.files.bundled]
        if (
            self.provenance is not None
            and self.provenance.regenerated is not None
            and bundled_counts
            and all(count is not None for count in bundled_counts)
        ):
            packaged_total = sum(count for count in bundled_counts if count is not None)
            if self.provenance.regenerated.total_events != packaged_total:
                raise ValueError(
                    "provenance.regenerated.total_events must equal declared bundled event counts"
                )
        if self.badactors_quality is not None and bundled_counts and all(
            count is not None for count in bundled_counts
        ):
            packaged_total = sum(count for count in bundled_counts if count is not None)
            if self.badactors_quality.attribution.technique_events != packaged_total:
                raise ValueError(
                    "badactors_quality.attribution.technique_events must equal declared bundled event counts"
                )
        return self

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

        nondefault_data = self.model_dump(
            exclude_none=True,
            exclude_defaults=True,
            by_alias=True,
        )
        explicit_data = self.model_dump(
            exclude_none=False,
            exclude_unset=True,
            by_alias=True,
        )
        data = self._merge_serialized(nondefault_data, explicit_data)
        data = {"manifest_version": self.manifest_version, **data}

        with open(path, 'w') as f:
            yaml.safe_dump(
                data,
                f,
                default_flow_style=False,
                sort_keys=False
            )

    @staticmethod
    def _merge_serialized(base: Any, explicit: Any) -> Any:
        """Union changed defaults with explicitly authored default values."""
        if isinstance(base, list) and isinstance(explicit, list):
            if len(base) != len(explicit):
                return explicit
            return [
                DatasetManifest._merge_serialized(base_item, explicit_item)
                for base_item, explicit_item in zip(base, explicit)
            ]
        if not isinstance(base, dict) or not isinstance(explicit, dict):
            return explicit
        result = base.copy()
        for key, value in explicit.items():
            if (
                key in result
                and isinstance(result[key], (dict, list))
                and isinstance(value, type(result[key]))
            ):
                result[key] = DatasetManifest._merge_serialized(result[key], value)
            else:
                result[key] = value
        return result

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
        # A referenced Attack Flow file must also exist when declared.
        if self.metadata.attack_flow is not None:
            flow_path = base_path / self.metadata.attack_flow.path
            if not flow_path.exists():
                missing.append(self.metadata.attack_flow.path)
        return missing


class ResolvedDataset(ManifestModel):
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
            defaults_dict = self.manifest.defaults.model_dump(
                exclude_none=False,
                exclude_unset=True,
            )
            defaults_dict.pop("replay", None)
            authored_defaults = self.manifest.defaults.model_fields_set
            if "echo" in authored_defaults:
                effective_echo = self.manifest.defaults.echo
            elif "replay" in authored_defaults:
                effective_echo = self.manifest.defaults.replay
                defaults_dict["echo"] = None
            else:
                effective_echo = None
            if effective_echo is not None:
                defaults_dict["echo"] = effective_echo.model_dump(
                    exclude_none=False,
                    exclude_unset=True,
                )
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
