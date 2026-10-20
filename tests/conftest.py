"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path
import tempfile
import shutil
from datetime import datetime


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    tmpdir = tempfile.mkdtemp()
    yield Path(tmpdir)
    shutil.rmtree(tmpdir)


@pytest.fixture
def sample_jsonl_data():
    """Sample JSONL data for testing."""
    return [
        {
            "timestamp": "2024-01-01T10:00:00Z",
            "message": "Event 1",
            "severity": "INFO"
        },
        {
            "timestamp": "2024-01-01T10:05:00Z",
            "message": "Event 2",
            "severity": "WARN"
        },
        {
            "timestamp": "2024-01-01T10:10:00Z",
            "message": "Event 3",
            "severity": "ERROR"
        },
    ]
