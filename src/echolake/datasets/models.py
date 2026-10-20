"""Pydantic models for dataset manifests."""

import re
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


class AttackFlowRef(BaseModel):
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
        """Validate path doesn't escape the dataset directory."""
        path = Path(v)
        if '..' in path.parts:
            raise ValueError(f"Path cannot contain '..': {v}")
        if path.is_absolute():
            raise ValueError(f"Path must be relative: {v}")
        return v

    @field_validator('format')
    @classmethod
    def validate_format(cls, v: str) -> str:
        """Validate Attack Flow format."""
        valid_formats = ["stix-2.1", "afb"]
        if v not in valid_formats:
            raise ValueError(f"Invalid Attack Flow format: {v}. Must be one of {valid_formats}")
        return v


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
    attack_flow: Optional[AttackFlowRef] = Field(
        default=None,
        description="Reference to a companion MITRE Attack Flow document (ordered attack graph)"
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
        description="Schema type (raw)",
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
        description="Schema type (raw)",
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
    return ids


class ScenarioEntity(BaseModel):
    """A host, account, organization, adversary, tool, or attacker infrastructure.

    `type` is the STIX 2.1 object type used to represent it. STIX-specific
    properties (``infrastructure_types``, ``identity_class``, ``account_login``,
    ``account_type``, ``is_service_account``, ``threat_actor_types``, ``sectors``,
    ``tool_types``, ``aliases``, ...) are passed through as given and validated
    by the STIX library when the Attack Flow is built.
    """

    model_config = {"extra": "allow"}

    id: str = Field(..., description="Local handle referenced by kill_chain stages and other entities")
    type: str = Field(..., description="STIX 2.1 type: infrastructure, identity, threat-actor, tool, malware, user-account")
    name: Optional[str] = Field(default=None, description="Display name (required for every type except user-account)")
    description: Optional[str] = Field(default=None)
    role: Optional[str] = Field(default=None, description="Role in the scenario, e.g. patient-zero, pivot, target, attacker, victim")
    observables: List[str] = Field(
        default_factory=list,
        description="Handles of observables that compose this entity (an infrastructure's IP, FQDN, accounts); emitted as consists-of",
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
        extra = self.model_extra or {}
        if self.type == "user-account":
            if not extra.get("account_login") and not extra.get("user_id"):
                raise ValueError(f"entity {self.id!r}: user-account needs account_login or user_id")
        elif not self.name:
            raise ValueError(f"entity {self.id!r}: {self.type} needs a name")
        if self.type == "identity" and not extra.get("identity_class"):
            raise ValueError(f"entity {self.id!r}: identity needs identity_class (individual, organization, system, group, class, unknown)")
        return self


class ScenarioObservable(BaseModel):
    """A STIX cyber-observable present in the data, optionally marked as an indicator.

    `type` is a STIX 2.1 observable type (or ``indicator`` for a pattern-only
    artifact such as a named pipe, carrying ``pattern`` and ``pattern_type``).
    When ``indicator_types`` is set the builder also emits a STIX indicator with
    a pattern over the observable, the given kill-chain phases and techniques,
    and the confidence. STIX-specific properties (``hashes``, ``key``,
    ``values``, ``command_line``, ``account_login``, ...) pass through as given.
    """

    model_config = {"extra": "allow"}

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
        extra = self.model_extra or {}
        if self.type in STIX_VALUE_OBSERVABLES and not self.value:
            raise ValueError(f"observable {self.id!r}: {self.type} needs a value")
        if self.type == "file" and not (self.name or extra.get("hashes")):
            raise ValueError(f"observable {self.id!r}: file needs a name or hashes")
        if self.type == "windows-registry-key" and not extra.get("key"):
            raise ValueError(f"observable {self.id!r}: windows-registry-key needs key")
        if self.type == "indicator" and not (self.pattern and self.pattern_type):
            raise ValueError(f"observable {self.id!r}: indicator needs pattern and pattern_type")
        if self.type == "user-account" and not (extra.get("account_login") or extra.get("user_id")):
            raise ValueError(f"observable {self.id!r}: user-account needs account_login or user_id")
        return self


class KillChainStage(BaseModel):
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


class DatasetManifest(BaseModel):
    """Complete dataset manifest (dataset.yaml)."""

    metadata: DatasetMetadata
    files: DatasetFiles = Field(default_factory=DatasetFiles)
    dependencies: List[DatasetDependency] = Field(default_factory=list)
    defaults: Optional[DatasetDefaults] = Field(default=None)
    entities: List[ScenarioEntity] = Field(default_factory=list, description="Scenario entities in STIX 2.1 vocabulary")
    observables: List[ScenarioObservable] = Field(default_factory=list, description="Observables and indicators present in the data")
    kill_chain: List[KillChainStage] = Field(default_factory=list, description="Ordered attack stages; source of the Attack Flow actions")

    @model_validator(mode="after")
    def _v_scenario_refs(self) -> "DatasetManifest":
        """Every handle reference must resolve, and handles must be unique."""
        ent = [e.id for e in self.entities]
        obs = [o.id for o in self.observables]
        stg = [k.id for k in self.kill_chain]
        for label, ids in (("entities", ent), ("observables", obs), ("kill_chain", stg)):
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
        # A referenced Attack Flow file must also exist when declared.
        if self.metadata.attack_flow is not None:
            flow_path = base_path / self.metadata.attack_flow.path
            if not flow_path.exists():
                missing.append(self.metadata.attack_flow.path)
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
