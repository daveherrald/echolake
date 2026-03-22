"""Tests for echo profiles and destinations models."""

import pytest
import tempfile
from pathlib import Path
import yaml

from echolake.profiles.models import (
    EchoProfile,
    EchoProfileMetadata,
    EchoConfig,
    DatasetReference,
    Destination,
    DestinationMetadata,
    DestinationConnection,
    CredentialsConfig,
)


class TestEchoConfig:
    """Test EchoConfig model."""

    def test_default_values(self):
        """Test default configuration values."""
        config = EchoConfig()
        assert config.delta_factor == 1.0
        assert config.base_time == "earliest"
        assert config.target_time == "now-1h"
        assert config.prevent_future is True

    def test_custom_values(self):
        """Test custom configuration values."""
        config = EchoConfig(
            delta_factor=0.5,
            base_time="latest",
            target_time="now-2h",
            prevent_future=False
        )
        assert config.delta_factor == 0.5
        assert config.base_time == "latest"
        assert config.target_time == "now-2h"
        assert config.prevent_future is False


class TestDatasetReference:
    """Test DatasetReference model."""

    def test_minimal_dataset_ref(self):
        """Test minimal dataset reference."""
        ref = DatasetReference(ref="local:meta-datasets/test")
        assert ref.ref == "local:meta-datasets/test"
        assert ref.version == "*"
        assert ref.description is None
        assert ref.schema_type is None
        assert ref.echo is None

    def test_full_dataset_ref(self):
        """Test dataset reference with all fields."""
        echo_cfg = EchoConfig(delta_factor=2.0, target_time="now-2h")
        ref = DatasetReference(
            ref="local:datasets/test",
            version=">=1.0.0",
            description="Test dataset",
            schema="lakehouse_bronze",
            echo=echo_cfg
        )
        assert ref.ref == "local:datasets/test"
        assert ref.version == ">=1.0.0"
        assert ref.description == "Test dataset"
        assert ref.schema_type == "lakehouse_bronze"
        assert ref.echo.delta_factor == 2.0
        assert ref.echo.target_time == "now-2h"


class TestEchoProfile:
    """Test EchoProfile model."""

    def test_minimal_profile(self):
        """Test minimal echo profile."""
        profile = EchoProfile(
            profile=EchoProfileMetadata(name="test-profile"),
            datasets=[DatasetReference(ref="local:datasets/test")]
        )
        assert profile.profile.name == "test-profile"
        assert len(profile.datasets) == 1
        assert profile.datasets[0].ref == "local:datasets/test"

    def test_full_profile(self):
        """Test echo profile with all fields."""
        profile = EchoProfile(
            profile=EchoProfileMetadata(
                name="test-profile",
                version="1.0.0",
                description="Test profile",
                author="test@example.com",
                tags=["test", "simulation"]
            ),
            datasets=[
                DatasetReference(ref="local:datasets/test1"),
                DatasetReference(ref="local:datasets/test2", version=">=2.0.0"),
            ],
            echo=EchoConfig(delta_factor=0.5),
            schema="raw",
            defaults={"custom": "value"}
        )
        assert profile.profile.name == "test-profile"
        assert profile.profile.version == "1.0.0"
        assert len(profile.datasets) == 2
        assert profile.echo.delta_factor == 0.5
        assert profile.schema_type == "raw"
        assert profile.defaults["custom"] == "value"

    def test_multiple_datasets(self):
        """Test profile with multiple datasets."""
        profile = EchoProfile(
            profile=EchoProfileMetadata(name="multi-dataset"),
            datasets=[
                DatasetReference(ref="local:datasets/test1"),
                DatasetReference(ref="local:datasets/test2"),
                DatasetReference(ref="local:datasets/test3"),
                DatasetReference(ref="local:datasets/test4"),
                DatasetReference(ref="local:datasets/test5"),
            ]
        )
        assert len(profile.datasets) == 5
        assert profile.datasets[0].ref == "local:datasets/test1"
        assert profile.datasets[4].ref == "local:datasets/test5"

    def test_per_dataset_echo_override(self):
        """Test per-dataset echo configuration override."""
        global_echo = EchoConfig(delta_factor=1.0, target_time="now-1h")
        dataset_echo = EchoConfig(delta_factor=2.0, target_time="now-2h")

        profile = EchoProfile(
            profile=EchoProfileMetadata(name="override-test"),
            datasets=[
                DatasetReference(ref="local:datasets/test1"),
                DatasetReference(
                    ref="local:datasets/test2",
                    echo=dataset_echo
                ),
            ],
            echo=global_echo
        )

        # Global echo config
        assert profile.echo.delta_factor == 1.0
        assert profile.echo.target_time == "now-1h"

        # Dataset without override uses global
        assert profile.datasets[0].echo is None

        # Dataset with override
        assert profile.datasets[1].echo.delta_factor == 2.0
        assert profile.datasets[1].echo.target_time == "now-2h"

    def test_from_file(self, tmp_path):
        """Test loading profile from YAML file."""
        profile_data = {
            "profile": {
                "name": "test-profile",
                "version": "1.0.0",
                "description": "Test profile"
            },
            "datasets": [
                {"ref": "local:datasets/test1"},
                {"ref": "local:datasets/test2", "version": ">=1.0.0"}
            ],
            "replay": {
                "delta_factor": 0.5,
                "base_time": "earliest",
                "target_time": "now-1h"
            },
            "schema": "raw"
        }

        profile_file = tmp_path / "test-profile.yaml"
        with open(profile_file, "w") as f:
            yaml.safe_dump(profile_data, f)

        profile = EchoProfile.from_file(profile_file)
        assert profile.profile.name == "test-profile"
        assert len(profile.datasets) == 2
        # YAML uses 'replay' key; model_validator migrates it to 'echo'
        assert profile.echo.delta_factor == 0.5

    def test_to_file(self, tmp_path):
        """Test saving profile to YAML file."""
        profile = EchoProfile(
            profile=EchoProfileMetadata(
                name="test-profile",
                version="1.0.0",
                description="Test profile"
            ),
            datasets=[
                DatasetReference(ref="local:datasets/test1"),
                DatasetReference(ref="local:datasets/test2")
            ],
            echo=EchoConfig(delta_factor=0.5)
        )

        profile_file = tmp_path / "output-profile.yaml"
        profile.to_file(profile_file)

        assert profile_file.exists()

        # Load back and verify
        loaded = EchoProfile.from_file(profile_file)
        assert loaded.profile.name == "test-profile"
        assert len(loaded.datasets) == 2
        assert loaded.echo.delta_factor == 0.5

    def test_file_not_found(self):
        """Test loading from non-existent file."""
        with pytest.raises(FileNotFoundError):
            EchoProfile.from_file("/nonexistent/path.yaml")


class TestDestination:
    """Test Destination model."""

    def test_minimal_destination(self):
        """Test minimal destination configuration."""
        dest = Destination(
            destination=DestinationMetadata(name="test-dest"),
            type="local"
        )
        assert dest.destination.name == "test-dest"
        assert dest.type == "local"
        assert dest.format == "jsonl"

    def test_chronicle_destination(self):
        """Test Google Chronicle destination."""
        dest = Destination(
            destination=DestinationMetadata(name="chronicle-prod"),
            type="chronicle",
            connection=DestinationConnection(
                project_id="security-prod",
                log_type="WINDOWS_SYSMON",
                region="us-central1"
            )
        )
        assert dest.type == "chronicle"
        assert dest.connection.project_id == "security-prod"
        assert dest.connection.log_type == "WINDOWS_SYSMON"

    def test_s3_destination(self):
        """Test AWS S3 destination."""
        dest = Destination(
            destination=DestinationMetadata(name="s3-archive"),
            type="s3",
            connection=DestinationConnection(
                bucket="security-datasets",
                prefix="replays/2025-01-28/",
                region="us-west-2"
            )
        )
        assert dest.type == "s3"
        assert dest.connection.bucket == "security-datasets"
        assert dest.connection.prefix == "replays/2025-01-28/"
        assert dest.connection.region == "us-west-2"

    def test_local_destination(self):
        """Test local filesystem destination."""
        dest = Destination(
            destination=DestinationMetadata(name="local-output"),
            type="local",
            connection=DestinationConnection(
                path="/tmp/echolake-output/"
            )
        )
        assert dest.type == "local"
        assert dest.connection.path == "/tmp/echolake-output/"

    def test_custom_destination_type(self):
        """Test custom destination type (extensibility)."""
        # Should not error on custom types
        dest = Destination(
            destination=DestinationMetadata(name="custom-dest"),
            type="my_custom_type",
            connection=DestinationConnection(
                extra={"custom_field": "value"}
            )
        )
        assert dest.type == "my_custom_type"
        assert dest.connection.extra["custom_field"] == "value"

    def test_from_file(self, tmp_path):
        """Test loading destination from YAML file."""
        dest_data = {
            "destination": {
                "name": "test-dest",
                "description": "Test destination"
            },
            "type": "s3",
            "connection": {
                "bucket": "security-datasets",
                "region": "us-west-2"
            },
            "format": "jsonl"
        }

        dest_file = tmp_path / "test-dest.yaml"
        with open(dest_file, "w") as f:
            yaml.safe_dump(dest_data, f)

        dest = Destination.from_file(dest_file)
        assert dest.destination.name == "test-dest"
        assert dest.type == "s3"
        assert dest.connection.bucket == "security-datasets"

    def test_to_file(self, tmp_path):
        """Test saving destination to YAML file."""
        dest = Destination(
            destination=DestinationMetadata(name="test-dest"),
            type="s3",
            connection=DestinationConnection(
                bucket="test-bucket",
                region="us-west-2"
            )
        )

        dest_file = tmp_path / "output-dest.yaml"
        dest.to_file(dest_file)

        assert dest_file.exists()

        # Load back and verify
        loaded = Destination.from_file(dest_file)
        assert loaded.destination.name == "test-dest"
        assert loaded.type == "s3"
        assert loaded.connection.bucket == "test-bucket"


class TestCredentialsConfig:
    """Test CredentialsConfig model."""

    def test_token_credentials(self):
        """Test token-based credentials."""
        creds = CredentialsConfig(token="abc123")
        assert creds.token == "abc123"

    def test_username_password_credentials(self):
        """Test username/password credentials."""
        creds = CredentialsConfig(
            username="user",
            password="pass"
        )
        assert creds.username == "user"
        assert creds.password == "pass"

    def test_credentials_file(self):
        """Test credentials file reference."""
        creds = CredentialsConfig(
            credentials_file="/path/to/service-account.json"
        )
        assert creds.credentials_file == "/path/to/service-account.json"

    def test_aws_credentials(self):
        """Test AWS-specific credentials."""
        creds = CredentialsConfig(
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )
        assert creds.aws_access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert creds.aws_secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    def test_from_file(self, tmp_path):
        """Test loading credentials from YAML file."""
        creds_data = {
            "credentials": {
                "local-output": {
                    "token": "abc123"
                },
                "chronicle-prod": {
                    "credentials_file": "/path/to/sa.json"
                },
                "s3-archive": {
                    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                }
            }
        }

        creds_file = tmp_path / "credentials.yaml"
        with open(creds_file, "w") as f:
            yaml.safe_dump(creds_data, f)

        creds_map = CredentialsConfig.from_file(creds_file)

        assert "local-output" in creds_map
        assert creds_map["local-output"].token == "abc123"

        assert "chronicle-prod" in creds_map
        assert creds_map["chronicle-prod"].credentials_file == "/path/to/sa.json"

        assert "s3-archive" in creds_map
        assert creds_map["s3-archive"].aws_access_key_id == "AKIAIOSFODNN7EXAMPLE"

    def test_from_file_missing_credentials_key(self, tmp_path):
        """Test loading from file without 'credentials' key."""
        bad_data = {
            "local-output": {
                "token": "abc123"
            }
        }

        creds_file = tmp_path / "bad-credentials.yaml"
        with open(creds_file, "w") as f:
            yaml.safe_dump(bad_data, f)

        with pytest.raises(ValueError, match="must have 'credentials' key"):
            CredentialsConfig.from_file(creds_file)

    def test_from_env(self, monkeypatch):
        """Test loading credentials from environment variables."""
        monkeypatch.setenv("TOKEN", "abc123")
        monkeypatch.setenv("USERNAME", "testuser")
        monkeypatch.setenv("PASSWORD", "testpass")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")

        creds = CredentialsConfig.from_env()

        assert creds.token == "abc123"
        assert creds.username == "testuser"
        assert creds.password == "testpass"
        assert creds.aws_access_key_id == "AKIAIOSFODNN7EXAMPLE"

    def test_from_env_with_prefix(self, monkeypatch):
        """Test loading credentials with prefix from environment."""
        monkeypatch.setenv("CHRONICLE_TOKEN", "chronicle123")
        monkeypatch.setenv("CHRONICLE_USERNAME", "chronicleuser")

        creds = CredentialsConfig.from_env(prefix="CHRONICLE_")

        assert creds.token == "chronicle123"
        assert creds.username == "chronicleuser"

    def test_extensible_extra_fields(self):
        """Test extensible extra fields."""
        creds = CredentialsConfig(
            extra={
                "custom_field": "custom_value",
                "another_field": 12345
            }
        )
        assert creds.extra["custom_field"] == "custom_value"
        assert creds.extra["another_field"] == 12345
