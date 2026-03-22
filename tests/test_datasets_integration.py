"""Integration tests for dataset echo."""

import pytest
from pathlib import Path
from echolake.core.config import Config, DatasetConfig, OutputConfig, OutputDestinationConfig
from echolake.core.echo import EchoEngine
from echolake.datasets.models import DatasetManifest


def test_replay_with_dataset(tmp_path):
    """Test replaying with a dataset."""
    # Use the sample dataset without dependencies
    dataset_path = Path(__file__).parent / "fixtures" / "sample-dataset-nodeps"

    # Create config with dataset
    config = Config(
        dataset=DatasetConfig(ref=f"local:{dataset_path}"),
        output=OutputConfig(
            destination=OutputDestinationConfig(
                type="local",
                path=str(tmp_path / "output"),
            ),
            format="jsonl",
        ),
    )

    # Create and run echo engine in dry-run mode
    engine = EchoEngine(config, dry_run=True)
    stats = engine.run()

    # Verify stats
    assert stats.event_count > 0
    assert stats.errors == 0


def test_dataset_defaults_merge(tmp_path):
    """Test that dataset defaults are properly merged."""
    dataset_path = Path(__file__).parent / "fixtures" / "sample-dataset-nodeps"

    # Create config with dataset and override delta_factor
    config = Config(
        dataset=DatasetConfig(
            ref=f"local:{dataset_path}",
            overrides={
                "echo": {
                    "delta_factor": 2.0,  # Override dataset default of 1.0
                }
            }
        ),
        output=OutputConfig(
            destination=OutputDestinationConfig(
                type="local",
                path=str(tmp_path / "output"),
            ),
            format="jsonl",
        ),
    )

    # Create echo engine
    engine = EchoEngine(config, dry_run=True)

    # Verify delta_factor was overridden
    assert engine.config.echo.delta_factor == 2.0


def test_dataset_input_auto_config(tmp_path):
    """Test that input is auto-configured from dataset."""
    dataset_path = Path(__file__).parent / "fixtures" / "sample-dataset-nodeps"

    # Create config with only dataset and output
    config = Config(
        dataset=DatasetConfig(ref=f"local:{dataset_path}"),
        output=OutputConfig(
            destination=OutputDestinationConfig(
                type="local",
                path=str(tmp_path / "output"),
            ),
            format="jsonl",
        ),
    )

    # Create echo engine
    engine = EchoEngine(config, dry_run=True)

    # Verify input was auto-configured
    assert engine.config.input is not None
    assert engine.config.input.source.type == "local"
    # Input path will be a temp directory with dataset files
    assert engine.config.input.source.path is not None
    assert Path(engine.config.input.source.path).exists()


def test_config_file_with_dataset(tmp_path):
    """Test loading config file with dataset."""
    import yaml

    # Create config file
    config_file = tmp_path / "echolake.yaml"
    config_data = {
        "dataset": {
            "ref": "local:" + str(Path(__file__).parent / "fixtures" / "sample-dataset-nodeps"),
        },
        "output": {
            "destination": {
                "type": "local",
                "path": str(tmp_path / "output"),
            },
            "format": "jsonl",
        },
    }

    with open(config_file, 'w') as f:
        yaml.safe_dump(config_data, f)

    # Load config
    config = Config.from_file(config_file)

    assert config.dataset is not None
    assert config.dataset.ref.startswith("local:")

    # Create echo engine
    engine = EchoEngine(config, dry_run=True)
    stats = engine.run()

    assert stats.event_count > 0


def test_dataset_manifest_metadata_accessible():
    """Test that dataset manifest is accessible after resolution."""
    dataset_path = Path(__file__).parent / "fixtures" / "sample-dataset-nodeps"

    config = Config(
        dataset=DatasetConfig(ref=f"local:{dataset_path}"),
        output=OutputConfig(
            destination=OutputDestinationConfig(
                type="local",
                path="/tmp/test-output",
            ),
            format="jsonl",
        ),
    )

    engine = EchoEngine(config, dry_run=True)

    # Verify resolved dataset is accessible
    assert engine.resolved_dataset is not None
    assert engine.resolved_dataset.manifest.metadata.name == "test-dataset-nodeps"
    assert engine.resolved_dataset.manifest.metadata.version == "1.0.0"
