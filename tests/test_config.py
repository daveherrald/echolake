"""Tests for configuration management."""

import pytest
import yaml
from pathlib import Path
from echolake.core.config import (
    Config,
    InputConfig,
    InputSourceConfig,
    OutputConfig,
    OutputDestinationConfig,
    EchoConfig,
)


class TestConfig:
    """Tests for Config."""

    def test_default_config(self):
        """Test default configuration."""
        config = Config()
        assert config.echo.delta_factor == 1.0
        assert config.echo.prevent_future is True

    def test_from_dict(self):
        """Test creating config from dictionary."""
        data = {
            'echo': {
                'delta_factor': 2.0,
                'target_time': 'now'
            },
            'input': {
                'source': {
                    'type': 'local',
                    'path': '/tmp/data'
                },
                'format': 'jsonl'
            }
        }

        config = Config.from_dict(data)
        assert config.echo.delta_factor == 2.0
        assert config.input.source.type == 'local'
        assert config.input.format == 'jsonl'

    def test_from_file(self, temp_dir):
        """Test loading config from YAML file."""
        config_file = temp_dir / 'config.yaml'

        config_data = {
            'echo': {
                'delta_factor': 1.5
            },
            'input': {
                'source': {
                    'type': 'local',
                    'path': '/data'
                },
                'format': 'json'
            },
            'output': {
                'destination': {
                    'type': 'local',
                    'path': '/output'
                },
                'format': 'jsonl'
            }
        }

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = Config.from_file(config_file)
        assert config.echo.delta_factor == 1.5
        assert config.input.source.path == '/data'
        assert config.output.format == 'jsonl'

    def test_validation_error_invalid_format(self):
        """Test that invalid format raises validation error."""
        with pytest.raises(ValueError, match="Invalid format"):
            InputConfig(
                source=InputSourceConfig(type='local', path='/data'),
                format='invalid_format'
            )

    def test_validation_error_invalid_source_type(self):
        """Test that invalid source type raises validation error."""
        with pytest.raises(ValueError, match="Invalid source type"):
            InputSourceConfig(type='invalid_type', path='/data')

    def test_merge_configs(self):
        """Test merging two configs."""
        base = Config.from_dict({
            'echo': {'delta_factor': 1.0, 'prevent_future': True},
            'input': {
                'source': {'type': 'local', 'path': '/base'},
                'format': 'jsonl'
            }
        })

        override = Config.from_dict({
            'echo': {'delta_factor': 2.0},
            'input': {
                'source': {'type': 'local', 'path': '/override'}
            }
        })

        merged = base.merge(override)

        assert merged.echo.delta_factor == 2.0  # Overridden
        assert merged.echo.prevent_future is True  # Preserved from base
        assert merged.input.source.path == '/override'  # Overridden
        assert merged.input.format == 'jsonl'  # Preserved from base


class TestInputSourceConfig:
    """Tests for InputSourceConfig."""

    def test_local_source(self):
        """Test local source configuration."""
        source = InputSourceConfig(
            type='local',
            path='/tmp/data',
            pattern='*.json'
        )

        assert source.type == 'local'
        assert source.path == '/tmp/data'
        assert source.pattern == '*.json'

    def test_s3_source(self):
        """Test S3 source configuration."""
        source = InputSourceConfig(
            type='s3',
            bucket='my-bucket',
            prefix='logs/',
            pattern='*.jsonl'
        )

        assert source.type == 's3'
        assert source.bucket == 'my-bucket'
        assert source.prefix == 'logs/'


class TestEchoConfig:
    """Tests for EchoConfig."""

    def test_default_echo_config(self):
        """Test default echo configuration."""
        config = EchoConfig()

        assert config.delta_factor == 1.0
        assert config.base_time == 'auto'
        assert config.target_time == 'now'
        assert config.prevent_future is True

    def test_invalid_delta_factor(self):
        """Test that negative delta_factor raises error."""
        with pytest.raises(ValueError, match="delta_factor must be positive"):
            EchoConfig(delta_factor=-1.0)

    def test_invalid_delta_factor_zero(self):
        """Test that zero delta_factor raises error."""
        with pytest.raises(ValueError, match="delta_factor must be positive"):
            EchoConfig(delta_factor=0.0)
