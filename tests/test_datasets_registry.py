"""Tests for dataset registry."""

import pytest
from pathlib import Path
from echolake.datasets.registry import DatasetRegistry, Repository


def test_repository_creation():
    """Test creating a repository."""
    repo = Repository(
        name="test-repo",
        url="github:org/repo",
        description="Test repository",
        enabled=True,
    )

    assert repo.name == "test-repo"
    assert repo.url == "github:org/repo"
    assert repo.description == "Test repository"
    assert repo.enabled is True


def test_repository_to_dict():
    """Test converting repository to dictionary."""
    repo = Repository(
        name="test-repo",
        url="github:org/repo",
        description="Test repository",
    )

    data = repo.to_dict()
    assert data["name"] == "test-repo"
    assert data["url"] == "github:org/repo"
    assert data["description"] == "Test repository"


def test_repository_from_dict():
    """Test creating repository from dictionary."""
    data = {
        "name": "test-repo",
        "url": "github:org/repo",
        "description": "Test repository",
        "enabled": True,
    }

    repo = Repository.from_dict(data)
    assert repo.name == "test-repo"
    assert repo.url == "github:org/repo"


def test_registry_load_empty(tmp_path):
    """Test registry with no config file."""
    config_file = tmp_path / "repositories.yaml"
    registry = DatasetRegistry(config_file=config_file)

    assert len(registry.repositories) == 0


def test_registry_save_and_load(tmp_path):
    """Test saving and loading repositories."""
    config_file = tmp_path / "repositories.yaml"
    registry = DatasetRegistry(config_file=config_file)

    # Add repository
    registry.add_repository(
        name="test",
        url="github:org/repo",
        description="Test repo",
    )

    assert len(registry.repositories) == 1

    # Create new registry instance and load
    registry2 = DatasetRegistry(config_file=config_file)
    assert len(registry2.repositories) == 1
    assert registry2.repositories[0].name == "test"


def test_registry_remove_repository(tmp_path):
    """Test removing a repository."""
    config_file = tmp_path / "repositories.yaml"
    registry = DatasetRegistry(config_file=config_file)

    # Add repositories
    registry.add_repository("repo1", "github:org/repo1")
    registry.add_repository("repo2", "github:org/repo2")
    assert len(registry.repositories) == 2

    # Remove one
    removed = registry.remove_repository("repo1")
    assert removed is True
    assert len(registry.repositories) == 1
    assert registry.repositories[0].name == "repo2"

    # Try to remove non-existent
    removed = registry.remove_repository("nonexistent")
    assert removed is False


def test_search_datasets():
    """Test searching datasets (with mocked catalog)."""
    from unittest.mock import Mock, patch

    registry = DatasetRegistry(config_file=Path("/tmp/nonexistent"))

    # Add a mock repository
    repo = Repository(
        name="test-repo",
        url="github:org/repo",
        enabled=True,
    )
    registry.repositories.append(repo)

    # Mock catalog
    mock_catalog = {
        "name": "test-catalog",
        "datasets": [
            {
                "name": "auth-logs",
                "path": "auth",
                "version": "1.0.0",
                "description": "Authentication logs for testing",
                "tags": ["authentication", "security"],
            },
            {
                "name": "network-logs",
                "path": "network",
                "version": "1.0.0",
                "description": "Network traffic logs",
                "tags": ["network"],
            },
        ],
    }

    with patch.object(registry, 'get_catalog', return_value=mock_catalog):
        # Search for "auth"
        results = registry.search_datasets("auth")
        assert len(results) == 1
        assert results[0]["name"] == "auth-logs"

        # Search for "network"
        results = registry.search_datasets("network")
        assert len(results) == 1
        assert results[0]["name"] == "network-logs"

        # Search in tags
        results = registry.search_datasets("security", search_in=["tags"])
        assert len(results) == 1
        assert results[0]["name"] == "auth-logs"


def test_list_datasets_with_filters():
    """Test listing datasets with filters."""
    from unittest.mock import patch

    registry = DatasetRegistry(config_file=Path("/tmp/nonexistent"))

    # Add a mock repository
    repo = Repository(
        name="test-repo",
        url="github:org/repo",
        enabled=True,
    )
    registry.repositories.append(repo)

    # Mock catalog
    mock_catalog = {
        "datasets": [
            {
                "name": "dataset1",
                "path": "dataset1",
                "version": "1.0.0",
                "tags": ["tag1", "tag2"],
                "mitre_attack": {
                    "techniques": [
                        {"id": "T1078", "name": "Valid Accounts"}
                    ],
                },
            },
            {
                "name": "dataset2",
                "path": "dataset2",
                "version": "1.0.0",
                "tags": ["tag3"],
            },
        ],
    }

    with patch.object(registry, 'get_catalog', return_value=mock_catalog):
        # Filter by tag
        results = registry.list_datasets(tags=["tag1"])
        assert len(results) == 1
        assert results[0]["name"] == "dataset1"

        # Filter by MITRE technique
        results = registry.list_datasets(mitre_technique="T1078")
        assert len(results) == 1
        assert results[0]["name"] == "dataset1"

        # No filter
        results = registry.list_datasets()
        assert len(results) == 2
