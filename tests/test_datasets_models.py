"""Tests for dataset models."""

import pytest
from pathlib import Path
from echolake.datasets.models import (
    DatasetManifest,
    DatasetMetadata,
    BundledFile,
    FileReference,
    MitreAttackTechnique,
    MitreAttackInfo,
    ResolvedDataset,
)


def test_load_valid_manifest():
    """Test loading a valid manifest file."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset" / "dataset.yaml"
    manifest = DatasetManifest.from_file(fixture_path)

    assert manifest.metadata.name == "test-dataset"
    assert manifest.metadata.version == "1.0.0"
    assert manifest.metadata.description == "Test dataset for unit tests"
    assert "test" in manifest.metadata.tags
    assert "authentication" in manifest.metadata.tags


def test_metadata_mitre_attack():
    """Test MITRE ATT&CK metadata parsing."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset" / "dataset.yaml"
    manifest = DatasetManifest.from_file(fixture_path)

    assert manifest.metadata.mitre_attack is not None
    assert len(manifest.metadata.mitre_attack.techniques) == 1
    assert manifest.metadata.mitre_attack.techniques[0].id == "T1078"
    assert manifest.metadata.mitre_attack.techniques[0].name == "Valid Accounts"
    assert "persistence" in manifest.metadata.mitre_attack.techniques[0].tactics


def test_bundled_files():
    """Test bundled files parsing."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset" / "dataset.yaml"
    manifest = DatasetManifest.from_file(fixture_path)

    assert len(manifest.files.bundled) == 2
    assert manifest.files.bundled[0].path == "logs/auth.jsonl"
    assert manifest.files.bundled[0].format == "jsonl"
    assert manifest.files.bundled[0].schema_type == "lakehouse_bronze"
    assert manifest.files.bundled[0].event_count == 100


def test_file_references():
    """Test file references parsing."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset" / "dataset.yaml"
    manifest = DatasetManifest.from_file(fixture_path)

    assert len(manifest.files.references) == 1
    assert manifest.files.references[0].uri == "s3://test-bucket/common/dns.jsonl"
    assert manifest.files.references[0].checksum == "sha256:abc123def456"


def test_dependencies():
    """Test dependencies parsing."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset" / "dataset.yaml"
    manifest = DatasetManifest.from_file(fixture_path)

    assert len(manifest.dependencies) == 1
    assert manifest.dependencies[0].dataset == "common/baseline"
    assert manifest.dependencies[0].version == ">=1.0.0"


def test_defaults():
    """Test defaults parsing."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset" / "dataset.yaml"
    manifest = DatasetManifest.from_file(fixture_path)

    assert manifest.defaults is not None
    # YAML fixture uses 'replay' key; model_validator migrates it to 'echo'
    assert manifest.defaults.echo is not None
    assert manifest.defaults.echo["delta_factor"] == 1.0
    assert manifest.defaults.schema_type == "lakehouse_bronze"


def test_validate_files_exist():
    """Test file existence validation."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset" / "dataset.yaml"
    manifest = DatasetManifest.from_file(fixture_path)
    base_path = Path(__file__).parent / "fixtures" / "sample-dataset"

    missing = manifest.validate_files_exist(base_path)
    assert len(missing) == 0


def test_validate_files_missing():
    """Test detection of missing files."""
    manifest = DatasetManifest(
        metadata=DatasetMetadata(
            name="test",
            version="1.0.0",
            description="Test"
        )
    )
    manifest.files.bundled.append(
        BundledFile(path="logs/missing.jsonl")
    )

    base_path = Path(__file__).parent / "fixtures" / "sample-dataset"
    missing = manifest.validate_files_exist(base_path)
    assert "logs/missing.jsonl" in missing


def test_bundled_file_path_validation():
    """Test path validation prevents directory traversal."""
    with pytest.raises(ValueError, match="cannot contain"):
        BundledFile(path="../../../etc/passwd")

    with pytest.raises(ValueError, match="must be relative"):
        BundledFile(path="/etc/passwd")


def test_file_reference_uri_validation():
    """Test URI validation."""
    # Valid URIs
    FileReference(uri="s3://bucket/path")
    FileReference(uri="gs://bucket/path")
    FileReference(uri="https://example.com/file.jsonl")

    # Invalid URI
    with pytest.raises(ValueError, match="URI must start with"):
        FileReference(uri="invalid://bucket/path")


def test_checksum_validation():
    """Test checksum format validation."""
    # Valid checksums
    FileReference(uri="s3://bucket/path", checksum="sha256:abc123")
    FileReference(uri="s3://bucket/path", checksum="sha512:def456")

    # Invalid format
    with pytest.raises(ValueError, match="format 'algorithm:value'"):
        FileReference(uri="s3://bucket/path", checksum="invalid")

    # Invalid algorithm
    with pytest.raises(ValueError, match="algorithm must be one of"):
        FileReference(uri="s3://bucket/path", checksum="invalid:abc123")


def test_mitre_technique_id_validation():
    """Test MITRE technique ID validation."""
    # Valid technique ID
    MitreAttackTechnique(id="T1078", name="Valid Accounts")

    # Invalid technique ID
    with pytest.raises(ValueError, match="must start with 'T'"):
        MitreAttackTechnique(id="1078", name="Invalid")


def test_semver_validation():
    """Test semantic version validation."""
    # Valid versions
    DatasetMetadata(name="test", version="1.0.0", description="Test")
    DatasetMetadata(name="test", version="1.2.3", description="Test")

    # Invalid version
    with pytest.raises(ValueError, match="Invalid semantic version"):
        DatasetMetadata(name="test", version="1.0", description="Test")


def test_resolved_dataset_file_collection():
    """Test resolved dataset file collection."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset" / "dataset.yaml"
    manifest = DatasetManifest.from_file(fixture_path)
    base_path = Path(__file__).parent / "fixtures" / "sample-dataset"

    resolved = ResolvedDataset(
        manifest=manifest,
        base_path=base_path
    )

    bundled_files = resolved.get_all_bundled_files()
    assert len(bundled_files) == 2
    assert all(isinstance(f, Path) for f in bundled_files)
    assert all(f.exists() for f in bundled_files)

    file_refs = resolved.get_all_file_references()
    assert len(file_refs) == 1
    assert file_refs[0].uri == "s3://test-bucket/common/dns.jsonl"


def test_resolved_dataset_merged_defaults():
    """Test merged defaults from dataset."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample-dataset" / "dataset.yaml"
    manifest = DatasetManifest.from_file(fixture_path)
    base_path = Path(__file__).parent / "fixtures" / "sample-dataset"

    resolved = ResolvedDataset(
        manifest=manifest,
        base_path=base_path
    )

    defaults = resolved.get_merged_defaults()
    # YAML fixture uses 'replay' key; model_validator migrates it to 'echo'
    assert defaults["echo"]["delta_factor"] == 1.0
    assert defaults["schema_type"] == "lakehouse_bronze"


def test_manifest_save_and_load(tmp_path):
    """Test saving and loading manifest."""
    manifest = DatasetManifest(
        metadata=DatasetMetadata(
            name="test-save",
            version="1.0.0",
            description="Test save/load"
        )
    )
    manifest.files.bundled.append(
        BundledFile(path="logs/test.jsonl")
    )

    # Save
    manifest_path = tmp_path / "dataset.yaml"
    manifest.to_file(manifest_path)
    assert manifest_path.exists()

    # Load
    loaded = DatasetManifest.from_file(manifest_path)
    assert loaded.metadata.name == "test-save"
    assert len(loaded.files.bundled) == 1


def test_bundled_file_sourcetype():
    """Test sourcetype field on BundledFile."""
    bf = BundledFile(path="logs/test.csv", format="csv", sourcetype="WinEventLog:Security")
    assert bf.sourcetype == "WinEventLog:Security"


def test_bundled_file_sourcetype_optional():
    """Test sourcetype field defaults to None."""
    bf = BundledFile(path="logs/test.jsonl")
    assert bf.sourcetype is None


def test_file_reference_sourcetype():
    """Test sourcetype field on FileReference."""
    fr = FileReference(uri="s3://bucket/test.csv", sourcetype="stream:dns")
    assert fr.sourcetype == "stream:dns"


def test_file_reference_sourcetype_optional():
    """Test sourcetype field defaults to None on FileReference."""
    fr = FileReference(uri="s3://bucket/test.csv")
    assert fr.sourcetype is None
