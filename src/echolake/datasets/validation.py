"""Offline validation for files declared by a dataset manifest.

The checks in this module deliberately stop at the dataset boundary. Bundled
files and other local artifacts are inspected on disk, while remote references
are checked only for manifest-level consistency.
"""

from __future__ import annotations

import gzip
import json
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
)

from echolake.inputs.timestamp_registry import TimestampRegistry
from echolake.inputs.formats import get_format

if TYPE_CHECKING:
    from .models import DatasetManifest


@dataclass(frozen=True)
class ValidationIssue:
    """One machine-readable manifest validation finding."""

    severity: str
    code: str
    message: str
    location: str
    path: Optional[str] = None


@dataclass
class ManifestValidationReport:
    """Structured result returned by :func:`validate_manifest_files`."""

    errors: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)
    files_checked: int = 0
    counts_checked: int = 0

    @property
    def valid(self) -> bool:
        """Whether validation completed without errors."""

        return not self.errors

    @property
    def is_valid(self) -> bool:
        """Read-only alias for callers that prefer an ``is_`` predicate."""

        return self.valid

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation suitable for CI output."""

        return {
            "valid": self.valid,
            "errors": [asdict(issue) for issue in self.errors],
            "warnings": [asdict(issue) for issue in self.warnings],
            "files_checked": self.files_checked,
            "counts_checked": self.counts_checked,
        }

    def _error(
        self,
        code: str,
        message: str,
        location: str,
        path: Optional[str] = None,
    ) -> None:
        self.errors.append(ValidationIssue("error", code, message, location, path))

    def _warning(
        self,
        code: str,
        message: str,
        location: str,
        path: Optional[str] = None,
    ) -> None:
        self.warnings.append(ValidationIssue("warning", code, message, location, path))


def _field_value(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _items(value: Any) -> List[Any]:
    if value is None:
        return []
    return list(value)


def _text_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    enum_value = getattr(value, "value", value)
    if isinstance(enum_value, str):
        return enum_value
    return str(enum_value)


def _has_control_characters(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def _validate_sourcetype(
    value: Any,
    location: str,
    report: ManifestValidationReport,
    *,
    required: bool,
    registry: Optional[TimestampRegistry],
) -> None:
    if value is None:
        return

    if not isinstance(value, str):
        report._error(
            "invalid_sourcetype",
            "Sourcetype must be a string.",
            location,
        )
        return

    if not value.strip():
        report._error(
            "invalid_sourcetype",
            "Sourcetype must not be blank.",
            location,
        )
        return

    if value != value.strip() or _has_control_characters(value):
        report._error(
            "invalid_sourcetype",
            "Sourcetype must not contain surrounding whitespace or control characters.",
            location,
        )
        return

    if required and registry is not None and not registry.supports(value):
        report._warning(
            "unregistered_sourcetype",
            "Bundled sourcetype {!r} has no TimestampRegistry entry; timestamp "
            "extraction will use dataset or generic fallback rules.".format(value),
            location,
        )


def _local_path_key(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        return str(PurePosixPath(value))
    except (TypeError, ValueError):
        return value


def _validate_local_path_syntax(
    value: Any,
    location: str,
    report: ManifestValidationReport,
) -> Optional[PurePosixPath]:
    if not isinstance(value, str) or not value:
        report._error(
            "invalid_local_path",
            "Local path must be a non-empty string.",
            location,
            value if isinstance(value, str) else None,
        )
        return None

    if "\\" in value or "\x00" in value:
        report._error(
            "invalid_local_path",
            "Local paths must use POSIX separators and contain no NUL bytes.",
            location,
            value,
        )
        return None

    if "://" in value or (len(value) >= 2 and value[0].isalpha() and value[1] == ":"):
        report._error(
            "invalid_local_path",
            "Local paths must be relative paths, not URIs or drive-qualified paths.",
            location,
            value,
        )
        return None

    try:
        relative = PurePosixPath(value)
    except (TypeError, ValueError) as error:
        report._error(
            "invalid_local_path",
            "Local path is invalid: {}".format(error),
            location,
            value,
        )
        return None

    if relative.is_absolute() or value.startswith("/"):
        report._error(
            "invalid_local_path",
            "Local path must be relative to the dataset root.",
            location,
            value,
        )
        return None

    if relative == PurePosixPath(".") or value.endswith("/") or ".." in relative.parts:
        report._error(
            "invalid_local_path",
            "Local path must name a file below the dataset root without '..'.",
            location,
            value,
        )
        return None

    return relative


def _resolve_local_file(
    value: Any,
    location: str,
    root: Optional[Path],
    report: ManifestValidationReport,
) -> Optional[Path]:
    relative = _validate_local_path_syntax(value, location, report)
    if relative is None or root is None:
        return None

    candidate = root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except ValueError:
        report._error(
            "path_escape",
            "Resolved path escapes the dataset root.",
            location,
            str(value),
        )
        return None
    except (OSError, RuntimeError) as error:
        report._error(
            "path_resolution_failed",
            "Could not resolve local path: {}".format(error),
            location,
            str(value),
        )
        return None

    if not resolved.exists():
        report._error(
            "missing_local_file",
            "Declared local file does not exist.",
            location,
            str(value),
        )
        return None

    if not resolved.is_file():
        report._error(
            "not_regular_file",
            "Declared local path is not a regular file.",
            location,
            str(value),
        )
        return None

    report.files_checked += 1
    return resolved


def _open_binary(path: Path) -> BinaryIO:
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rb")
    return path.open("rb")


def _windows_xml_event_count(path: Path) -> int:
    """Count the events used by EchoEngine's Windows XML in-place path."""
    count = 0
    depth = 0
    root_is_event = False
    with _open_binary(path) as stream:
        for action, element in ET.iterparse(stream, events=("start", "end")):
            if action == "start":
                tag = element.tag
                local_name = (
                    tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1].lower()
                    if isinstance(tag, str)
                    else ""
                )
                if depth == 0:
                    root_is_event = local_name == "event"
                    if root_is_event:
                        count = 1
                elif depth == 1 and not root_is_event and local_name == "event":
                    count += 1
                depth += 1
            else:
                depth -= 1
                element.clear()
    return count


def _jsonl_event_count(path: Path) -> int:
    count = 0
    with _open_binary(path) as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError(
                    "invalid JSONL record at physical line {}: {}".format(line_number, error)
                ) from error
            if isinstance(value, dict):
                count += 1
    return count


def _json_event_count(path: Path) -> int:
    with _open_binary(path) as stream:
        value = json.load(stream)
    if isinstance(value, list):
        return sum(1 for item in value if isinstance(item, dict))
    if isinstance(value, dict):
        return 1
    return 0


def _parsed_event_count(path: Path, file_format: str) -> int:
    with _open_binary(path) as stream:
        return sum(1 for _ in get_format(file_format).parse(stream))


def _runtime_event_count(path: Path, declared_format: Any, sourcetype: Any) -> int:
    """Count the records EchoLake's declared input path would replay."""
    file_format = (_text_value(declared_format) or "auto").lower()
    normalized_sourcetype = (_text_value(sourcetype) or "").lower()
    if file_format == "xml" and (
        normalized_sourcetype == "xmlwineventlog"
        or normalized_sourcetype.startswith("xmlwineventlog:")
    ):
        return _windows_xml_event_count(path)
    if file_format == "jsonl":
        return _jsonl_event_count(path)
    if file_format == "json":
        return _json_event_count(path)
    return _parsed_event_count(path, file_format)


def _report_duplicate_values(
    values: Iterable[Tuple[Any, str]],
    report: ManifestValidationReport,
    *,
    code: str,
    noun: str,
    normalize_local_path: bool = False,
) -> None:
    seen: Dict[str, str] = {}
    reported = set()
    for value, location in values:
        if not isinstance(value, str):
            continue
        key = _local_path_key(value) if normalize_local_path else value
        if key is None:
            continue
        if key in seen and key not in reported:
            report._error(
                code,
                "Duplicate {} {!r}; first declared at {}.".format(noun, value, seen[key]),
                location,
                value,
            )
            reported.add(key)
        else:
            seen[key] = location


def validate_manifest_files(
    manifest: "DatasetManifest",
    dataset_root: Union[str, Path],
    check_counts: bool = True,
    require_registered_sourcetypes: bool = True,
) -> ManifestValidationReport:
    """Validate a manifest's local files without accessing remote objects.

    The dataset root and every local path are resolved before containment is
    checked, so symlinks cannot make a declared path escape the dataset. Remote
    references are never opened, downloaded, checksum-verified, or looked up in
    the timestamp registry.
    """

    report = ManifestValidationReport()

    try:
        root = Path(dataset_root).resolve(strict=False)
    except (TypeError, OSError, RuntimeError) as error:
        report._error(
            "invalid_dataset_root",
            "Could not resolve dataset root: {}".format(error),
            "dataset_root",
        )
        root = None
    else:
        if not root.exists():
            report._error(
                "missing_dataset_root",
                "Dataset root does not exist.",
                "dataset_root",
                str(dataset_root),
            )
            root = None
        elif not root.is_dir():
            report._error(
                "invalid_dataset_root",
                "Dataset root is not a directory.",
                "dataset_root",
                str(dataset_root),
            )
            root = None

    files = _field_value(manifest, "files")
    bundled = _items(_field_value(files, "bundled", []))
    references = _items(_field_value(files, "references", []))

    _report_duplicate_values(
        (
            (_field_value(item, "path"), "files.bundled[{}].path".format(index))
            for index, item in enumerate(bundled)
        ),
        report,
        code="duplicate_bundled_path",
        noun="bundled path",
        normalize_local_path=True,
    )
    _report_duplicate_values(
        (
            (_field_value(item, "uri"), "files.references[{}].uri".format(index))
            for index, item in enumerate(references)
        ),
        report,
        code="duplicate_reference_uri",
        noun="reference URI",
    )

    registry: Optional[TimestampRegistry] = None
    if bundled and require_registered_sourcetypes:
        try:
            registry = TimestampRegistry.get()
        except Exception as error:  # pragma: no cover - protects CI from registry I/O failures
            report._error(
                "timestamp_registry_unavailable",
                "TimestampRegistry could not be loaded: {}".format(error),
                "files.bundled",
            )
    elif bundled:
        report._warning(
            "registry_check_skipped",
            "TimestampRegistry membership checks were disabled for bundled inputs.",
            "files.bundled",
        )

    for index, bundled_file in enumerate(bundled):
        base_location = "files.bundled[{}]".format(index)
        declared_path = _field_value(bundled_file, "path")
        resolved = _resolve_local_file(
            declared_path,
            base_location + ".path",
            root,
            report,
        )

        schema = _text_value(
            _field_value(
                bundled_file,
                "schema_type",
                _field_value(bundled_file, "schema"),
            )
        )
        if schema not in {None, "raw"}:
            report._error(
                "unsupported_runtime_schema",
                "Bundled inputs support only schema 'raw' or an omitted schema.",
                base_location + ".schema",
                str(declared_path) if declared_path is not None else None,
            )

        sourcetype = _field_value(bundled_file, "sourcetype")
        _validate_sourcetype(
            sourcetype,
            base_location + ".sourcetype",
            report,
            required=require_registered_sourcetypes,
            registry=registry,
        )
        if sourcetype is None:
            report._warning(
                "missing_sourcetype",
                "Bundled input has no sourcetype; timestamp extraction will use "
                "dataset or generic fallback rules.",
                base_location + ".sourcetype",
                str(declared_path) if declared_path is not None else None,
            )

        if not check_counts:
            continue

        expected_count = _field_value(bundled_file, "event_count")
        if expected_count is None:
            report._warning(
                "event_count_missing",
                "Bundled input has no event_count, so its runtime replay count was not checked.",
                base_location + ".event_count",
                str(declared_path) if declared_path is not None else None,
            )
            continue
        if isinstance(expected_count, bool) or not isinstance(expected_count, int):
            report._error(
                "invalid_event_count",
                "event_count must be a non-negative integer.",
                base_location + ".event_count",
                str(declared_path) if declared_path is not None else None,
            )
            continue
        if expected_count < 0:
            report._error(
                "invalid_event_count",
                "event_count must be a non-negative integer.",
                base_location + ".event_count",
                str(declared_path) if declared_path is not None else None,
            )
            continue
        if resolved is None:
            continue

        try:
            actual_count = _runtime_event_count(
                resolved,
                _field_value(bundled_file, "format", "auto"),
                sourcetype,
            )
        except Exception as error:
            report._error(
                "content_count_failed",
                "Could not count runtime replay records: {}".format(error),
                base_location + ".event_count",
                str(declared_path),
            )
            continue

        report.counts_checked += 1
        if actual_count != expected_count:
            report._error(
                "event_count_mismatch",
                "Declared event_count {} does not match runtime replay count {}.".format(
                    expected_count,
                    actual_count,
                ),
                base_location + ".event_count",
                str(declared_path),
            )

    for index, reference in enumerate(references):
        _validate_sourcetype(
            _field_value(reference, "sourcetype"),
            "files.references[{}].sourcetype".format(index),
            report,
            required=False,
            registry=None,
        )

    if references:
        report._warning(
            "remote_content_unchecked",
            "{} remote reference(s) were checked statically; content, checksums, and "
            "TimestampRegistry membership were not checked.".format(len(references)),
            "files.references",
        )

    metadata = _field_value(manifest, "metadata")
    attack_flow = _field_value(metadata, "attack_flow")
    if attack_flow is not None:
        _resolve_local_file(
            _field_value(attack_flow, "path"),
            "metadata.attack_flow.path",
            root,
            report,
        )

    for index, observable in enumerate(_items(_field_value(manifest, "observables", []))):
        rule = _field_value(observable, "rule")
        if rule is None:
            continue
        location = "observables[{}].rule".format(index)
        if isinstance(rule, str) and rule.lower().startswith(("http://", "https://")):
            report._warning(
                "external_rule_unchecked",
                "External observable rule was not downloaded or inspected.",
                location,
                rule,
            )
            continue
        _resolve_local_file(rule, location, root, report)

    if not check_counts and bundled:
        report._warning(
            "count_checks_skipped",
            "Runtime replay count checks were disabled for bundled inputs.",
            "files.bundled",
        )

    return report


__all__ = [
    "ManifestValidationReport",
    "ValidationIssue",
    "validate_manifest_files",
]
