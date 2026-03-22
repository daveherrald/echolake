"""Utility functions for datasets."""

import re
from pathlib import Path
from typing import Tuple, Optional


def parse_semver(version: str) -> Tuple[int, int, int]:
    """
    Parse semantic version string.

    Args:
        version: Version string (e.g., "1.2.3", "v1.2.3")

    Returns:
        Tuple of (major, minor, patch)

    Raises:
        ValueError: If version format is invalid
    """
    # Strip 'v' prefix if present
    version = version.lstrip('v')

    # Match semver pattern: major.minor.patch
    pattern = r'^(\d+)\.(\d+)\.(\d+)(?:-.+)?$'
    match = re.match(pattern, version)

    if not match:
        raise ValueError(
            f"Invalid semantic version: {version}. Expected format: major.minor.patch"
        )

    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two semantic versions.

    Args:
        v1: First version
        v2: Second version

    Returns:
        -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2

    Raises:
        ValueError: If either version is invalid
    """
    maj1, min1, pat1 = parse_semver(v1)
    maj2, min2, pat2 = parse_semver(v2)

    if (maj1, min1, pat1) < (maj2, min2, pat2):
        return -1
    elif (maj1, min1, pat1) > (maj2, min2, pat2):
        return 1
    else:
        return 0


def satisfies_version_constraint(version: str, constraint: str) -> bool:
    """
    Check if a version satisfies a version constraint.

    Supports:
    - Exact: "1.2.3"
    - Wildcard: "*", "1.x", "1.2.x"
    - Range: ">=1.2.0", "<=2.0.0", ">1.0.0", "<2.0.0"
    - Caret: "^1.2.3" (compatible with 1.x.x)
    - Tilde: "~1.2.3" (compatible with 1.2.x)

    Args:
        version: Version to check
        constraint: Version constraint

    Returns:
        True if version satisfies constraint

    Raises:
        ValueError: If version or constraint is invalid
    """
    # Wildcard: accept any version
    if constraint == "*":
        return True

    # Parse version
    major, minor, patch = parse_semver(version)

    # Wildcard with x: "1.x" or "1.2.x"
    if 'x' in constraint.lower():
        parts = constraint.lower().split('.')
        if len(parts) == 2 and parts[1] == 'x':
            # "1.x" matches "1.*.*"
            constraint_major = int(parts[0])
            return major == constraint_major
        elif len(parts) == 3 and parts[2] == 'x':
            # "1.2.x" matches "1.2.*"
            constraint_major = int(parts[0])
            constraint_minor = int(parts[1])
            return major == constraint_major and minor == constraint_minor
        else:
            raise ValueError(f"Invalid x wildcard format: {constraint}")

    # Caret: ^1.2.3 means >=1.2.3 and <2.0.0
    if constraint.startswith('^'):
        base_version = constraint[1:]
        base_major, base_minor, base_patch = parse_semver(base_version)
        return (
            major == base_major and
            (minor > base_minor or (minor == base_minor and patch >= base_patch))
        )

    # Tilde: ~1.2.3 means >=1.2.3 and <1.3.0
    if constraint.startswith('~'):
        base_version = constraint[1:]
        base_major, base_minor, base_patch = parse_semver(base_version)
        return (
            major == base_major and
            minor == base_minor and
            patch >= base_patch
        )

    # Range operators
    if constraint.startswith('>='):
        return compare_versions(version, constraint[2:]) >= 0
    elif constraint.startswith('<='):
        return compare_versions(version, constraint[2:]) <= 0
    elif constraint.startswith('>'):
        return compare_versions(version, constraint[1:]) > 0
    elif constraint.startswith('<'):
        return compare_versions(version, constraint[1:]) < 0
    elif constraint.startswith('='):
        return compare_versions(version, constraint[1:]) == 0

    # Exact version
    return compare_versions(version, constraint) == 0


def parse_dataset_ref(ref: str) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Parse dataset reference into components.

    Formats:
    - "org/name" -> ("org/name", None, None)
    - "org/name@1.2.0" -> ("org/name", "1.2.0", None)
    - "github:org/repo/path" -> ("org/repo/path", None, "github")
    - "github:org/repo/path@v1.0.0" -> ("org/repo/path", "v1.0.0", "github")
    - "local:/path/to/dataset" -> ("/path/to/dataset", None, "local")
    - "https://example.com/dataset.yaml" -> ("https://example.com/dataset.yaml", None, "https")

    Args:
        ref: Dataset reference string

    Returns:
        Tuple of (path, version, scheme)
        - path: The path/identifier for the dataset
        - version: Optional version constraint
        - scheme: Optional scheme (github, local, http, https)
    """
    # Extract version if present (format: ref@version)
    version = None
    if '@' in ref and not ref.startswith('http'):
        ref, version = ref.rsplit('@', 1)

    # Check for explicit schemes
    if ref.startswith('github:'):
        return ref[7:], version, 'github'
    elif ref.startswith('local:'):
        return ref[6:], version, 'local'
    elif ref.startswith('http://') or ref.startswith('https://'):
        scheme = 'https' if ref.startswith('https://') else 'http'
        return ref, version, scheme
    elif ref.startswith('s3://'):
        return ref, version, 's3'
    elif ref.startswith('gs://'):
        return ref, version, 'gs'

    # Default: short form like "org/name"
    return ref, version, None


def normalize_path(path: str) -> Path:
    """
    Normalize and validate a file path.

    Args:
        path: Path string

    Returns:
        Normalized Path object

    Raises:
        ValueError: If path is invalid or attempts directory traversal
    """
    p = Path(path)

    # Prevent directory traversal
    if '..' in p.parts:
        raise ValueError(f"Path cannot contain '..': {path}")

    # Expand user home directory
    if str(p).startswith('~'):
        p = p.expanduser()

    return p.resolve()


def get_cache_dir() -> Path:
    """
    Get the cache directory for datasets.

    Returns:
        Path to cache directory (~/.echolake/cache/datasets)
    """
    cache_dir = Path.home() / '.echolake' / 'cache' / 'datasets'
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_config_dir() -> Path:
    """
    Get the config directory for EchoLake.

    Returns:
        Path to config directory (~/.echolake)
    """
    config_dir = Path.home() / '.echolake'
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir
