"""Tests for the legacy dataset loader helpers backed by typed models."""

from pathlib import Path

import pytest

from echolake.datasets import DatasetManifest as PublicDatasetManifest
from echolake.datasets import get_bundled_files, get_dataset_defaults, load_dataset
from echolake.datasets.models import DatasetManifest


def test_public_manifest_is_canonical_model():
    assert PublicDatasetManifest is DatasetManifest


def test_loader_helpers_keep_their_legacy_return_shapes():
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset-nodeps"

    dataset_path, manifest = load_dataset(f"local:{fixture_path}")

    assert dataset_path == fixture_path.resolve()
    assert isinstance(manifest, DatasetManifest)
    assert manifest.metadata["name"] == "test-dataset-nodeps"
    assert manifest.metadata.get("name") == "test-dataset-nodeps"
    assert "name" in manifest.metadata
    assert "missing" not in manifest.metadata
    assert "name" in manifest.metadata.keys()
    assert dict(manifest.metadata.items())["name"] == "test-dataset-nodeps"
    assert manifest.files.get("bundled") is manifest.files.bundled
    assert manifest.files.bundled[0].get("path") == "logs/test.jsonl"
    assert manifest.files.bundled[0]["format"] == "jsonl"
    assert get_bundled_files(dataset_path, manifest) == [
        dataset_path / "logs" / "test.jsonl"
    ]
    defaults = get_dataset_defaults(manifest)
    assert isinstance(defaults, dict)
    assert defaults["schema_type"] == "raw"
    assert defaults["echo"] == {"delta_factor": 1.0}


def test_loader_defaults_are_empty_when_omitted():
    manifest = DatasetManifest.model_validate(
        {
            "metadata": {
                "name": "without-defaults",
                "version": "1.0.0",
                "description": "No defaults block",
            }
        }
    )

    assert get_dataset_defaults(manifest) == {}


def test_loader_defaults_preserve_explicit_nulls():
    manifest = DatasetManifest.model_validate(
        {
            "metadata": {
                "name": "null-default",
                "version": "1.0.0",
                "description": "Explicit null",
            },
            "defaults": {"echo": {"ceiling_time": None}},
        }
    )

    assert get_dataset_defaults(manifest)["echo"]["ceiling_time"] is None


def test_legacy_mapping_omits_unauthored_optional_fields():
    manifest = DatasetManifest.model_validate(
        {
            "metadata": {
                "name": "mapping",
                "version": "1.0.0",
                "description": "Mapping compatibility",
            }
        }
    )

    assert manifest.metadata.get("author", "fallback") == "fallback"
    assert "author" not in manifest.metadata
    assert len(manifest.metadata) == 3
    assert dict(manifest.metadata) == {
        "name": "mapping",
        "version": "1.0.0",
        "description": "Mapping compatibility",
    }
    with pytest.raises(KeyError):
        _ = manifest.metadata["author"]
