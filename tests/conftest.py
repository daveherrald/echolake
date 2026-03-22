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


@pytest.fixture
def sample_lakehouse_data():
    """Sample Lakehouse Bronze data for testing."""
    return [
        {
            "_event_time": "2024-01-01T10:00:00Z",
            "_ingest_time": "2024-01-01T10:00:05Z",
            "_source": "test-source",
            "data": {"field1": "value1"}
        },
        {
            "_event_time": "2024-01-01T10:05:00Z",
            "_ingest_time": "2024-01-01T10:05:05Z",
            "_source": "test-source",
            "data": {"field1": "value2"}
        },
    ]


@pytest.fixture
def sample_ocsf_data():
    """Sample OCSF data for testing."""
    return [
        {
            "class_uid": 1001,
            "class_name": "File Activity",
            "time": 1704103200000,  # 2024-01-01T10:00:00Z in ms
            "severity_id": 1,
            "message": "File accessed"
        },
        {
            "class_uid": 1001,
            "class_name": "File Activity",
            "time": 1704103500000,  # 2024-01-01T10:05:00Z in ms
            "severity_id": 2,
            "message": "File modified"
        },
    ]
