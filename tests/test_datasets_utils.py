"""Tests for dataset utilities."""

import pytest
from echolake.datasets.utils import (
    parse_semver,
    compare_versions,
    satisfies_version_constraint,
    parse_dataset_ref,
    normalize_path,
)


def test_parse_semver():
    """Test semantic version parsing."""
    assert parse_semver("1.2.3") == (1, 2, 3)
    assert parse_semver("v1.2.3") == (1, 2, 3)
    assert parse_semver("0.1.0") == (0, 1, 0)
    assert parse_semver("10.20.30") == (10, 20, 30)

    # With pre-release
    assert parse_semver("1.2.3-alpha") == (1, 2, 3)
    assert parse_semver("1.2.3-beta.1") == (1, 2, 3)


def test_parse_semver_invalid():
    """Test invalid semantic versions."""
    with pytest.raises(ValueError):
        parse_semver("1.2")

    with pytest.raises(ValueError):
        parse_semver("1")

    with pytest.raises(ValueError):
        parse_semver("invalid")


def test_compare_versions():
    """Test version comparison."""
    assert compare_versions("1.0.0", "2.0.0") == -1
    assert compare_versions("2.0.0", "1.0.0") == 1
    assert compare_versions("1.2.3", "1.2.3") == 0

    assert compare_versions("1.2.3", "1.2.4") == -1
    assert compare_versions("1.2.3", "1.3.0") == -1
    assert compare_versions("2.0.0", "1.9.9") == 1


def test_satisfies_version_constraint_wildcard():
    """Test wildcard version constraints."""
    assert satisfies_version_constraint("1.2.3", "*")
    assert satisfies_version_constraint("0.0.1", "*")
    assert satisfies_version_constraint("99.99.99", "*")


def test_satisfies_version_constraint_exact():
    """Test exact version constraints."""
    assert satisfies_version_constraint("1.2.3", "1.2.3")
    assert not satisfies_version_constraint("1.2.4", "1.2.3")
    assert not satisfies_version_constraint("1.2.3", "1.2.4")


def test_satisfies_version_constraint_x():
    """Test x wildcard constraints."""
    assert satisfies_version_constraint("1.2.3", "1.x")
    assert satisfies_version_constraint("1.9.9", "1.x")
    assert not satisfies_version_constraint("2.0.0", "1.x")

    assert satisfies_version_constraint("1.2.3", "1.2.x")
    assert satisfies_version_constraint("1.2.9", "1.2.x")
    assert not satisfies_version_constraint("1.3.0", "1.2.x")


def test_satisfies_version_constraint_caret():
    """Test caret (^) constraints."""
    # ^1.2.3 means >=1.2.3 and <2.0.0
    assert satisfies_version_constraint("1.2.3", "^1.2.3")
    assert satisfies_version_constraint("1.2.4", "^1.2.3")
    assert satisfies_version_constraint("1.9.9", "^1.2.3")
    assert not satisfies_version_constraint("2.0.0", "^1.2.3")
    assert not satisfies_version_constraint("1.2.2", "^1.2.3")


def test_satisfies_version_constraint_tilde():
    """Test tilde (~) constraints."""
    # ~1.2.3 means >=1.2.3 and <1.3.0
    assert satisfies_version_constraint("1.2.3", "~1.2.3")
    assert satisfies_version_constraint("1.2.4", "~1.2.3")
    assert not satisfies_version_constraint("1.3.0", "~1.2.3")
    assert not satisfies_version_constraint("1.2.2", "~1.2.3")


def test_satisfies_version_constraint_range():
    """Test range constraints."""
    # >=
    assert satisfies_version_constraint("1.2.3", ">=1.2.0")
    assert satisfies_version_constraint("2.0.0", ">=1.2.0")
    assert not satisfies_version_constraint("1.1.0", ">=1.2.0")

    # <=
    assert satisfies_version_constraint("1.2.0", "<=1.2.3")
    assert satisfies_version_constraint("1.0.0", "<=1.2.3")
    assert not satisfies_version_constraint("1.3.0", "<=1.2.3")

    # >
    assert satisfies_version_constraint("1.2.4", ">1.2.3")
    assert not satisfies_version_constraint("1.2.3", ">1.2.3")

    # <
    assert satisfies_version_constraint("1.2.2", "<1.2.3")
    assert not satisfies_version_constraint("1.2.3", "<1.2.3")


def test_parse_dataset_ref_simple():
    """Test parsing simple dataset references."""
    path, version, scheme = parse_dataset_ref("org/name")
    assert path == "org/name"
    assert version is None
    assert scheme is None


def test_parse_dataset_ref_with_version():
    """Test parsing dataset references with version."""
    path, version, scheme = parse_dataset_ref("org/name@1.2.3")
    assert path == "org/name"
    assert version == "1.2.3"
    assert scheme is None


def test_parse_dataset_ref_github():
    """Test parsing GitHub dataset references."""
    path, version, scheme = parse_dataset_ref("github:org/repo/path")
    assert path == "org/repo/path"
    assert version is None
    assert scheme == "github"

    path, version, scheme = parse_dataset_ref("github:org/repo/path@v1.0.0")
    assert path == "org/repo/path"
    assert version == "v1.0.0"
    assert scheme == "github"


def test_parse_dataset_ref_local():
    """Test parsing local dataset references."""
    path, version, scheme = parse_dataset_ref("local:/path/to/dataset")
    assert path == "/path/to/dataset"
    assert version is None
    assert scheme == "local"


def test_parse_dataset_ref_http():
    """Test parsing HTTP/HTTPS dataset references."""
    path, version, scheme = parse_dataset_ref("https://example.com/dataset.yaml")
    assert path == "https://example.com/dataset.yaml"
    assert version is None
    assert scheme == "https"

    path, version, scheme = parse_dataset_ref("http://example.com/dataset.yaml")
    assert path == "http://example.com/dataset.yaml"
    assert version is None
    assert scheme == "http"


def test_parse_dataset_ref_s3():
    """Test parsing S3 dataset references."""
    path, version, scheme = parse_dataset_ref("s3://bucket/path/to/dataset")
    assert path == "s3://bucket/path/to/dataset"
    assert version is None
    assert scheme == "s3"


def test_normalize_path():
    """Test path normalization."""
    # Should prevent directory traversal
    with pytest.raises(ValueError, match="cannot contain"):
        normalize_path("../../../etc/passwd")

    # Should expand home directory
    import os
    home_path = normalize_path("~/test")
    assert "~" not in str(home_path)
    assert str(home_path).startswith(os.path.expanduser("~"))
