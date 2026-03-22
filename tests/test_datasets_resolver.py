"""Tests for dataset resolver."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import yaml

from echolake.datasets.resolver import DatasetResolver
from echolake.datasets.cache import DatasetCache
from echolake.datasets.models import DatasetManifest


def test_resolve_local_directory():
    """Test resolving local dataset from directory."""
    resolver = DatasetResolver()
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset-nodeps"

    resolved = resolver.resolve(f"local:{fixture_path}")

    assert resolved.manifest.metadata.name == "test-dataset-nodeps"
    assert resolved.manifest.metadata.version == "1.0.0"
    assert resolved.base_path == fixture_path
    assert len(resolved.get_all_bundled_files()) == 1


def test_resolve_local_manifest_file():
    """Test resolving local dataset from manifest file."""
    resolver = DatasetResolver()
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset-nodeps" / "dataset.yaml"

    resolved = resolver.resolve(f"local:{fixture_path}")

    assert resolved.manifest.metadata.name == "test-dataset-nodeps"
    assert resolved.base_path == fixture_path.parent


def test_resolve_local_not_found():
    """Test error when local dataset not found."""
    resolver = DatasetResolver()

    with pytest.raises(FileNotFoundError):
        resolver.resolve("local:/nonexistent/path")


def test_resolve_http_with_mock(tmp_path):
    """Test resolving HTTP dataset with mocked requests."""
    # Create mock manifest
    manifest_data = {
        "metadata": {
            "name": "http-dataset",
            "version": "1.0.0",
            "description": "Test HTTP dataset",
        },
        "files": {
            "bundled": [
                {
                    "path": "logs/test.jsonl",
                    "format": "jsonl",
                }
            ]
        }
    }

    manifest_yaml = yaml.safe_dump(manifest_data)

    # Mock HTTP responses
    with patch('requests.get') as mock_get:
        # Mock manifest download
        manifest_response = Mock()
        manifest_response.text = manifest_yaml
        manifest_response.raise_for_status = Mock()

        # Mock file download
        file_response = Mock()
        file_response.iter_content = Mock(return_value=[b'{"test": "data"}\n'])
        file_response.raise_for_status = Mock()

        # Setup mock to return different responses
        def get_side_effect(url, *args, **kwargs):
            if url.endswith("dataset.yaml"):
                return manifest_response
            else:
                return file_response

        mock_get.side_effect = get_side_effect

        # Use custom cache directory
        cache = DatasetCache(cache_dir=tmp_path / "cache")
        resolver = DatasetResolver(cache=cache)

        # Resolve
        resolved = resolver.resolve("https://example.com/datasets/test")

        assert resolved.manifest.metadata.name == "http-dataset"
        assert resolved.manifest.metadata.version == "1.0.0"
        assert resolved.base_path.exists()


def test_cache_usage(tmp_path):
    """Test that resolver uses cache on second request."""
    manifest_data = {
        "metadata": {
            "name": "cached-dataset",
            "version": "1.0.0",
            "description": "Test caching",
        },
        "files": {
            "bundled": []
        }
    }

    manifest_yaml = yaml.safe_dump(manifest_data)

    with patch('requests.get') as mock_get:
        # Mock manifest download
        manifest_response = Mock()
        manifest_response.text = manifest_yaml
        manifest_response.raise_for_status = Mock()

        mock_get.return_value = manifest_response

        # Use custom cache directory
        cache = DatasetCache(cache_dir=tmp_path / "cache")
        resolver = DatasetResolver(cache=cache)

        # First resolve - should download
        resolved1 = resolver.resolve("https://example.com/datasets/cached")
        assert mock_get.call_count == 1

        # Second resolve - should use cache
        resolved2 = resolver.resolve("https://example.com/datasets/cached")
        assert mock_get.call_count == 1  # No additional calls

        assert resolved1.manifest.metadata.name == resolved2.manifest.metadata.name


def test_force_download(tmp_path):
    """Test force download bypasses cache."""
    manifest_data = {
        "metadata": {
            "name": "force-dataset",
            "version": "1.0.0",
            "description": "Test force download",
        },
        "files": {
            "bundled": []
        }
    }

    manifest_yaml = yaml.safe_dump(manifest_data)

    with patch('requests.get') as mock_get:
        # Mock manifest download
        manifest_response = Mock()
        manifest_response.text = manifest_yaml
        manifest_response.raise_for_status = Mock()

        mock_get.return_value = manifest_response

        # Use custom cache directory
        cache = DatasetCache(cache_dir=tmp_path / "cache")
        resolver = DatasetResolver(cache=cache)

        # First resolve
        resolver.resolve("https://example.com/datasets/force")
        assert mock_get.call_count == 1

        # Second resolve with force - should download again
        resolver.resolve("https://example.com/datasets/force", force_download=True)
        assert mock_get.call_count == 2


def test_list_cached(tmp_path):
    """Test listing cached datasets."""
    # Create a fake cached dataset
    cache = DatasetCache(cache_dir=tmp_path / "cache")

    manifest = DatasetManifest(
        metadata={
            "name": "cached-set",
            "version": "1.0.0",
            "description": "Cached test set",
        }
    )

    cache_path = cache.get_cache_path("example.com/test")
    cache_path.mkdir(parents=True, exist_ok=True)
    manifest.to_file(cache_path / "dataset.yaml")

    # List cached
    resolver = DatasetResolver(cache=cache)
    cached = resolver.list_cached()

    assert "example.com/test" in cached
    assert cached["example.com/test"]["name"] == "cached-set"
    assert cached["example.com/test"]["version"] == "1.0.0"
