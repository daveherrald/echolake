"""Tests for GitHub integration."""

import pytest
from unittest.mock import Mock, patch
from echolake.datasets.github import GitHubClient


def test_parse_github_ref():
    """Test parsing GitHub references."""
    client = GitHubClient()

    # Basic reference
    org, repo, path, version = client.parse_github_ref("org/repo/path")
    assert org == "org"
    assert repo == "repo"
    assert path == "path"
    assert version is None

    # With version
    org, repo, path, version = client.parse_github_ref("org/repo/path@v1.0.0")
    assert org == "org"
    assert repo == "repo"
    assert path == "path"
    assert version == "v1.0.0"

    # Nested path
    org, repo, path, version = client.parse_github_ref("org/repo/dir/subdir")
    assert org == "org"
    assert repo == "repo"
    assert path == "dir/subdir"
    assert version is None

    # Just org/repo
    org, repo, path, version = client.parse_github_ref("org/repo")
    assert org == "org"
    assert repo == "repo"
    assert path == ""
    assert version is None


def test_parse_github_ref_invalid():
    """Test invalid GitHub references."""
    client = GitHubClient()

    with pytest.raises(ValueError, match="Invalid GitHub reference"):
        client.parse_github_ref("invalid")


def test_resolve_version_latest():
    """Test resolving latest version."""
    client = GitHubClient()

    with patch.object(client, 'get_releases') as mock_releases:
        mock_releases.return_value = [
            {"tag_name": "v1.2.0"},
            {"tag_name": "v1.1.0"},
        ]

        version = client.resolve_version("org", "repo", "latest")
        assert version == "v1.2.0"


def test_resolve_version_constraint():
    """Test resolving version constraint."""
    client = GitHubClient()

    with patch.object(client, 'get_releases') as mock_releases:
        mock_releases.return_value = [
            {"tag_name": "v2.0.0"},
            {"tag_name": "v1.2.0"},
            {"tag_name": "v1.1.0"},
        ]

        # Test >=1.0.0
        version = client.resolve_version("org", "repo", ">=1.0.0")
        assert version == "v2.0.0"  # Highest matching version

        # Test 1.x
        version = client.resolve_version("org", "repo", "1.x")
        assert version == "v1.2.0"  # Highest 1.x version


def test_resolve_version_branch():
    """Test resolving branch name."""
    client = GitHubClient()

    # Branch names should be returned as-is
    version = client.resolve_version("org", "repo", "main")
    assert version == "main"

    version = client.resolve_version("org", "repo", "develop")
    assert version == "develop"


def test_get_raw_content():
    """Test getting raw content from GitHub."""
    client = GitHubClient()

    with patch('requests.get') as mock_get:
        mock_response = Mock()
        mock_response.text = "file content"
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        content = client.get_raw_content("org", "repo", "path/to/file.txt", "main")

        assert content == "file content"
        mock_get.assert_called_once()
        assert "raw.githubusercontent.com" in mock_get.call_args[0][0]


def test_download_dataset(tmp_path):
    """Test downloading a dataset from GitHub."""
    client = GitHubClient()

    manifest_yaml = """
metadata:
  name: "github-dataset"
  version: "1.0.0"
  description: "Test GitHub dataset"
files:
  bundled:
    - path: "logs/test.jsonl"
      format: "jsonl"
"""

    with patch.object(client, 'resolve_version') as mock_resolve, \
         patch.object(client, 'get_raw_content') as mock_get_raw, \
         patch('echolake.datasets.github.requests.get') as mock_requests_get:

        mock_resolve.return_value = "v1.0.0"

        # Mock manifest download (still uses get_raw_content)
        mock_get_raw.return_value = manifest_yaml

        # Mock bundled file download (now uses requests.get directly)
        mock_response = Mock()
        mock_response.content = b'{"test": "data"}\n'
        mock_response.raise_for_status = Mock()
        mock_requests_get.return_value = mock_response

        from echolake.datasets.cache import DatasetCache
        cache = DatasetCache(cache_dir=tmp_path / "cache")

        manifest, cache_path, resolved_version = client.download_dataset(
            org="org",
            repo="repo",
            path="datasets/test",
            version=">=1.0.0",
            cache=cache,
        )

        assert manifest.metadata.name == "github-dataset"
        assert resolved_version == "v1.0.0"
        assert cache_path.exists()
        assert (cache_path / "dataset.yaml").exists()
        assert (cache_path / "logs" / "test.jsonl").exists()


def test_github_client_with_token():
    """Test GitHub client with authentication token."""
    client = GitHubClient(token="test-token")

    headers = client._get_headers()
    assert "Authorization" in headers
    assert headers["Authorization"] == "token test-token"


def test_github_client_without_token():
    """Test GitHub client without authentication token."""
    client = GitHubClient(token=None)

    headers = client._get_headers()
    assert "Authorization" not in headers
