"""Tests for profile and destination discovery."""

import pytest
import tempfile
from pathlib import Path

from echolake.profiles import (
    find_profiles,
    find_destinations,
    load_profile,
    load_destination,
)
from echolake.profiles.models import (
    EchoProfile,
    EchoProfileMetadata,
    DatasetReference,
    Destination,
    DestinationMetadata,
    DestinationConnection,
)


class TestFindProfiles:
    """Test find_profiles function."""

    def test_find_profiles_in_examples(self):
        """Test finding profiles in examples directory."""
        # Should find the example profiles
        profiles = find_profiles()

        assert len(profiles) >= 7  # At least the 7 example profiles
        profile_names = [p["name"] for p in profiles]

        assert "getting-started" in profile_names
        assert "weekly-apt-simulation" in profile_names
        assert "ransomware-incident" in profile_names

    def test_find_profiles_custom_path(self, tmp_path):
        """Test finding profiles in custom path."""
        # Create a test profile
        profile_dir = tmp_path / "test-profiles"
        profile_dir.mkdir()

        profile = EchoProfile(
            profile=EchoProfileMetadata(
                name="test-profile",
                version="1.0.0",
                description="Test profile"
            ),
            datasets=[DatasetReference(ref="local:test")]
        )
        profile.to_file(profile_dir / "test-profile.yaml")

        # Search custom path
        profiles = find_profiles([profile_dir])

        assert len(profiles) == 1
        assert profiles[0]["name"] == "test-profile"
        assert profiles[0]["version"] == "1.0.0"

    def test_find_profiles_empty_directory(self, tmp_path):
        """Test finding profiles in empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        profiles = find_profiles([empty_dir])
        assert len(profiles) == 0

    def test_find_profiles_ignores_invalid_files(self, tmp_path):
        """Test that invalid YAML files are ignored."""
        profile_dir = tmp_path / "profiles"
        profile_dir.mkdir()

        # Create invalid YAML
        (profile_dir / "invalid.yaml").write_text("this is not valid yaml: ][")

        # Create valid profile
        profile = EchoProfile(
            profile=EchoProfileMetadata(name="valid", version="1.0.0"),
            datasets=[DatasetReference(ref="local:test")]
        )
        profile.to_file(profile_dir / "valid.yaml")

        profiles = find_profiles([profile_dir])

        # Should only find the valid one
        assert len(profiles) == 1
        assert profiles[0]["name"] == "valid"


class TestFindDestinations:
    """Test find_destinations function."""

    def test_find_destinations_in_examples(self):
        """Test finding destinations in examples directory."""
        # Should find the example destinations
        destinations = find_destinations()

        assert len(destinations) >= 6  # At least the 6 example destinations
        dest_names = [d["name"] for d in destinations]

        assert "local-output" in dest_names
        assert "stdout-debug" in dest_names

    def test_find_destinations_custom_path(self, tmp_path):
        """Test finding destinations in custom path."""
        # Create a test destination
        dest_dir = tmp_path / "test-destinations"
        dest_dir.mkdir()

        dest = Destination(
            destination=DestinationMetadata(
                name="test-dest",
                description="Test destination"
            ),
            type="local"
        )
        dest.to_file(dest_dir / "test-dest.yaml")

        # Search custom path
        destinations = find_destinations([dest_dir])

        assert len(destinations) == 1
        assert destinations[0]["name"] == "test-dest"
        assert destinations[0]["type"] == "local"

    def test_find_destinations_filter_by_type(self, tmp_path):
        """Test finding destinations filters correctly by type."""
        dest_dir = tmp_path / "destinations"
        dest_dir.mkdir()

        # Create multiple destination types
        Destination(
            destination=DestinationMetadata(name="dest1"),
            type="local"
        ).to_file(dest_dir / "dest1.yaml")

        Destination(
            destination=DestinationMetadata(name="dest2"),
            type="s3"
        ).to_file(dest_dir / "dest2.yaml")

        Destination(
            destination=DestinationMetadata(name="dest3"),
            type="local"
        ).to_file(dest_dir / "dest3.yaml")

        # Find all
        all_dests = find_destinations([dest_dir])
        assert len(all_dests) == 3

        # Filter by type works at the application level, not in find_destinations
        # So we test that all destinations are found
        local_dests = [d for d in all_dests if d["type"] == "local"]
        assert len(local_dests) == 2


class TestLoadProfile:
    """Test load_profile function."""

    def test_load_profile_by_name(self):
        """Test loading profile by name from examples."""
        profile = load_profile("getting-started")

        assert profile.profile.name == "getting-started"
        assert profile.profile.version == "1.0.0"
        assert len(profile.datasets) == 1

    def test_load_profile_by_path(self, tmp_path):
        """Test loading profile by path."""
        # Create test profile
        profile_path = tmp_path / "my-profile.yaml"
        profile = EchoProfile(
            profile=EchoProfileMetadata(
                name="my-profile",
                version="2.0.0"
            ),
            datasets=[DatasetReference(ref="local:test")]
        )
        profile.to_file(profile_path)

        # Load by absolute path
        loaded = load_profile(str(profile_path))

        assert loaded.profile.name == "my-profile"
        assert loaded.profile.version == "2.0.0"

    def test_load_profile_from_custom_search_path(self, tmp_path):
        """Test loading profile with custom search paths."""
        # Create profile in custom location
        custom_dir = tmp_path / "custom-profiles"
        custom_dir.mkdir()

        profile = EchoProfile(
            profile=EchoProfileMetadata(name="custom", version="1.0.0"),
            datasets=[DatasetReference(ref="local:test")]
        )
        profile.to_file(custom_dir / "custom.yaml")

        # Load with custom search path
        loaded = load_profile("custom", search_paths=[custom_dir])

        assert loaded.profile.name == "custom"

    def test_load_profile_not_found(self):
        """Test loading non-existent profile raises error."""
        with pytest.raises(FileNotFoundError, match="Profile not found"):
            load_profile("nonexistent-profile-12345")

    def test_load_profile_with_yaml_extension(self, tmp_path):
        """Test loading profile with .yaml extension in name."""
        profile_dir = tmp_path / "profiles"
        profile_dir.mkdir()

        profile = EchoProfile(
            profile=EchoProfileMetadata(name="test", version="1.0.0"),
            datasets=[DatasetReference(ref="local:test")]
        )
        profile.to_file(profile_dir / "test.yaml")

        # Should work with .yaml extension
        loaded = load_profile("test.yaml", search_paths=[profile_dir])
        assert loaded.profile.name == "test"


class TestLoadDestination:
    """Test load_destination function."""

    def test_load_destination_by_name(self):
        """Test loading destination by name from examples."""
        dest = load_destination("local-output")

        assert dest.destination.name == "local-output"
        assert dest.type == "local"

    def test_load_destination_by_path(self, tmp_path):
        """Test loading destination by path."""
        # Create test destination
        dest_path = tmp_path / "my-dest.yaml"
        dest = Destination(
            destination=DestinationMetadata(name="my-dest"),
            type="stdout"
        )
        dest.to_file(dest_path)

        # Load by absolute path
        loaded = load_destination(str(dest_path))

        assert loaded.destination.name == "my-dest"
        assert loaded.type == "stdout"

    def test_load_destination_from_custom_search_path(self, tmp_path):
        """Test loading destination with custom search paths."""
        # Create destination in custom location
        custom_dir = tmp_path / "custom-destinations"
        custom_dir.mkdir()

        dest = Destination(
            destination=DestinationMetadata(name="custom"),
            type="local"
        )
        dest.to_file(custom_dir / "custom.yaml")

        # Load with custom search path
        loaded = load_destination("custom", search_paths=[custom_dir])

        assert loaded.destination.name == "custom"

    def test_load_destination_not_found(self):
        """Test loading non-existent destination raises error."""
        with pytest.raises(FileNotFoundError, match="Destination not found"):
            load_destination("nonexistent-dest-12345")

    def test_load_destination_multiple_types(self):
        """Test loading different destination types."""
        # Test stdout
        stdout_dest = load_destination("stdout-debug")
        assert stdout_dest.type == "stdout"

        # Test local
        local_dest = load_destination("local-output")
        assert local_dest.type == "local"


class TestProfileMetadata:
    """Test that profile metadata is extracted correctly."""

    def test_profile_metadata_extraction(self, tmp_path):
        """Test that all metadata fields are extracted."""
        profile_dir = tmp_path / "profiles"
        profile_dir.mkdir()

        profile = EchoProfile(
            profile=EchoProfileMetadata(
                name="full-metadata",
                version="3.2.1",
                description="Full metadata profile",
                author="test@example.com",
                tags=["tag1", "tag2", "tag3"]
            ),
            datasets=[
                DatasetReference(ref="local:dataset1"),
                DatasetReference(ref="local:dataset2"),
            ]
        )
        profile.to_file(profile_dir / "full.yaml")

        profiles = find_profiles([profile_dir])

        assert len(profiles) == 1
        p = profiles[0]

        assert p["name"] == "full-metadata"
        assert p["version"] == "3.2.1"
        assert p["description"] == "Full metadata profile"
        assert p["author"] == "test@example.com"
        assert p["tags"] == ["tag1", "tag2", "tag3"]
        assert p["datasets_count"] == 2


class TestDestinationMetadata:
    """Test that destination metadata is extracted correctly."""

    def test_destination_metadata_extraction(self, tmp_path):
        """Test that all metadata fields are extracted."""
        dest_dir = tmp_path / "destinations"
        dest_dir.mkdir()

        dest = Destination(
            destination=DestinationMetadata(
                name="full-dest",
                description="Full metadata destination",
                tags=["prod", "critical"]
            ),
            type="s3",
            connection=DestinationConnection(
                bucket="my-bucket",
                region="us-west-2"
            )
        )
        dest.to_file(dest_dir / "full.yaml")

        destinations = find_destinations([dest_dir])

        assert len(destinations) == 1
        d = destinations[0]

        assert d["name"] == "full-dest"
        assert d["description"] == "Full metadata destination"
        assert d["type"] == "s3"
        assert d["tags"] == ["prod", "critical"]


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_nonexistent_search_path(self):
        """Test that nonexistent search paths are handled gracefully."""
        nonexistent = Path("/nonexistent/path/that/does/not/exist")

        # Should not raise error, just return empty list
        profiles = find_profiles([nonexistent])
        assert profiles == []

        destinations = find_destinations([nonexistent])
        assert destinations == []

    def test_mixed_valid_invalid_paths(self, tmp_path):
        """Test searching mix of valid and invalid paths."""
        valid_dir = tmp_path / "valid"
        valid_dir.mkdir()

        profile = EchoProfile(
            profile=EchoProfileMetadata(name="test", version="1.0.0"),
            datasets=[DatasetReference(ref="local:test")]
        )
        profile.to_file(valid_dir / "test.yaml")

        nonexistent = tmp_path / "nonexistent"

        # Should find profile in valid dir, ignore nonexistent
        profiles = find_profiles([valid_dir, nonexistent])
        assert len(profiles) == 1
        assert profiles[0]["name"] == "test"

    def test_profile_in_subdirectory(self, tmp_path):
        """Test finding profiles in subdirectories."""
        base_dir = tmp_path / "profiles"
        sub_dir = base_dir / "category1" / "subcategory"
        sub_dir.mkdir(parents=True)

        profile = EchoProfile(
            profile=EchoProfileMetadata(name="nested", version="1.0.0"),
            datasets=[DatasetReference(ref="local:test")]
        )
        profile.to_file(sub_dir / "nested.yaml")

        # Should find profiles recursively
        profiles = find_profiles([base_dir])
        assert len(profiles) == 1
        assert profiles[0]["name"] == "nested"
