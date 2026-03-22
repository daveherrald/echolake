"""Tests for compression through output destinations."""

import gzip
import bz2
from unittest.mock import MagicMock, patch

import pytest

from echolake.outputs.destinations.local import LocalDestination
from echolake.outputs.base import OutputDestination


class TestCompressionHelpers:
    """Test base class compression utilities."""

    def test_compress_bytes_gzip(self):
        dest = LocalDestination(path="/tmp/test_unused", compression=None)
        data = b"hello world"
        compressed = dest._compress_bytes(data, "gzip")
        assert gzip.decompress(compressed) == data

    def test_compress_bytes_bzip2(self):
        dest = LocalDestination(path="/tmp/test_unused", compression=None)
        data = b"hello world"
        compressed = dest._compress_bytes(data, "bzip2")
        assert bz2.decompress(compressed) == data

    def test_compress_bytes_none(self):
        dest = LocalDestination(path="/tmp/test_unused", compression=None)
        data = b"hello world"
        assert dest._compress_bytes(data, None) == data

    def test_compression_extension_gzip(self):
        assert OutputDestination._compression_extension("gzip") == ".gz"

    def test_compression_extension_bzip2(self):
        assert OutputDestination._compression_extension("bzip2") == ".bz2"

    def test_compression_extension_none(self):
        assert OutputDestination._compression_extension(None) == ""


class TestLocalDestinationGzip:
    """Test LocalDestination with gzip compression."""

    def test_gzip_write_and_read(self, tmp_path):
        """Write events with gzip, verify file extension and content."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{filename}",
            compression="gzip",
        )
        events = ['{"msg": "event1"}', '{"msg": "event2"}']
        dest.write("test.jsonl", events)

        output_file = tmp_path / "test.jsonl.gz"
        assert output_file.exists()

        # Decompress and verify content
        with gzip.open(output_file, "rt") as f:
            lines = f.read().strip().split("\n")
        assert lines == events

    def test_gzip_append(self, tmp_path):
        """Two write() calls should produce readable concatenated gzip."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{filename}",
            compression="gzip",
        )
        dest.write("test.jsonl", ['{"batch": 1}'])
        dest.write("test.jsonl", ['{"batch": 2}'])

        output_file = tmp_path / "test.jsonl.gz"
        with gzip.open(output_file, "rt") as f:
            lines = f.read().strip().split("\n")
        assert lines == ['{"batch": 1}', '{"batch": 2}']

    def test_gzip_with_sourcetype_routing(self, tmp_path):
        """Gzip works with sourcetype path templates."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{sourcetype}/{filename}",
            compression="gzip",
        )
        dest.write("events.jsonl", ['{"src": "win"}'], metadata={"sourcetype": "WinEventLog"})

        output_file = tmp_path / "WinEventLog" / "events.jsonl.gz"
        assert output_file.exists()

        with gzip.open(output_file, "rt") as f:
            content = f.read().strip()
        assert content == '{"src": "win"}'


class TestLocalDestinationBzip2:
    """Test LocalDestination with bzip2 compression."""

    def test_bzip2_write_and_read(self, tmp_path):
        """Write events with bzip2, verify file extension and content."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{filename}",
            compression="bzip2",
        )
        events = ['{"msg": "event1"}', '{"msg": "event2"}']
        dest.write("test.jsonl", events)

        output_file = tmp_path / "test.jsonl.bz2"
        assert output_file.exists()

        with bz2.open(output_file, "rt") as f:
            lines = f.read().strip().split("\n")
        assert lines == events


class TestLocalDestinationNoCompression:
    """Test that no compression preserves existing behavior."""

    def test_no_compression_plain_file(self, tmp_path):
        """Without compression, output is a plain text file."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{filename}",
        )
        events = ['{"msg": "test"}']
        dest.write("test.jsonl", events)

        output_file = tmp_path / "test.jsonl"
        assert output_file.exists()
        assert output_file.read_text().strip() == '{"msg": "test"}'

        # No .gz file should exist
        assert not (tmp_path / "test.jsonl.gz").exists()


class TestPathExtension:
    """Test compression extension logic in path generation."""

    def test_gz_extension_appended(self, tmp_path):
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{filename}",
            compression="gzip",
        )
        path = dest._generate_path("data.jsonl")
        assert str(path).endswith(".jsonl.gz")

    def test_no_double_extension(self, tmp_path):
        """If template already ends with .gz, don't double it."""
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{filename}.gz",
            compression="gzip",
        )
        path = dest._generate_path("data.jsonl")
        assert str(path).endswith(".jsonl.gz")
        assert not str(path).endswith(".gz.gz")

    def test_bz2_extension_appended(self, tmp_path):
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{filename}",
            compression="bzip2",
        )
        path = dest._generate_path("data.jsonl")
        assert str(path).endswith(".jsonl.bz2")

    def test_no_extension_without_compression(self, tmp_path):
        dest = LocalDestination(
            path=str(tmp_path),
            path_template="{filename}",
        )
        path = dest._generate_path("data.jsonl")
        assert str(path).endswith(".jsonl")
        assert not str(path).endswith(".gz")


class TestS3DestinationCompression:
    """Test S3Destination compression (mocked)."""

    @patch("echolake.outputs.destinations.s3.BOTO3_AVAILABLE", True)
    @patch("echolake.outputs.destinations.s3.boto3")
    def test_s3_gzip_compressed_upload(self, mock_boto3):
        """Verify compressed bytes are passed to put_object."""
        from echolake.outputs.destinations.s3 import S3Destination

        mock_client = MagicMock()
        mock_boto3.Session.return_value.client.return_value = mock_client

        dest = S3Destination(
            bucket="test-bucket",
            path_template="{filename}",
            compression="gzip",
        )
        dest.write("test.jsonl", ['{"msg": "hello"}'])

        # Verify put_object was called
        mock_client.put_object.assert_called_once()
        call_kwargs = mock_client.put_object.call_args[1]

        assert call_kwargs["Bucket"] == "test-bucket"
        assert call_kwargs["Key"].endswith(".gz")

        # Verify body is gzip-compressed
        body = call_kwargs["Body"]
        decompressed = gzip.decompress(body).decode("utf-8")
        assert '{"msg": "hello"}' in decompressed

    @patch("echolake.outputs.destinations.s3.BOTO3_AVAILABLE", True)
    @patch("echolake.outputs.destinations.s3.boto3")
    def test_s3_no_compression_raw_upload(self, mock_boto3):
        """Without compression, raw bytes are uploaded."""
        from echolake.outputs.destinations.s3 import S3Destination

        mock_client = MagicMock()
        mock_boto3.Session.return_value.client.return_value = mock_client

        dest = S3Destination(
            bucket="test-bucket",
            path_template="{filename}",
        )
        dest.write("test.jsonl", ['{"msg": "hello"}'])

        call_kwargs = mock_client.put_object.call_args[1]
        assert not call_kwargs["Key"].endswith(".gz")
        assert call_kwargs["Body"] == b'{"msg": "hello"}'


class TestGCSDestinationCompression:
    """Test GCSDestination compression (mocked)."""

    @patch("echolake.outputs.destinations.gcs.GCS_AVAILABLE", True)
    @patch("echolake.outputs.destinations.gcs.storage")
    def test_gcs_gzip_compressed_upload(self, mock_storage):
        """Verify compressed bytes are uploaded with correct content type."""
        from echolake.outputs.destinations.gcs import GCSDestination

        mock_blob = MagicMock()
        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_blob
        mock_client = MagicMock()
        mock_client.bucket.return_value = mock_bucket
        mock_storage.Client.return_value = mock_client

        dest = GCSDestination(
            bucket="test-bucket",
            path_template="{filename}",
            compression="gzip",
        )
        dest.write("test.jsonl", ['{"msg": "hello"}'])

        mock_blob.upload_from_string.assert_called_once()
        call_args = mock_blob.upload_from_string.call_args

        # Check content type
        assert call_args[1]["content_type"] == "application/gzip"

        # Verify body is gzip-compressed
        body = call_args[0][0]
        decompressed = gzip.decompress(body).decode("utf-8")
        assert '{"msg": "hello"}' in decompressed


class TestAzureDestinationCompression:
    """Test AzureBlobDestination compression (mocked)."""

    @patch("echolake.outputs.destinations.azure_blob.AZURE_AVAILABLE", True)
    @patch("echolake.outputs.destinations.azure_blob.BlobServiceClient")
    def test_azure_gzip_compressed_upload(self, mock_bsc_class):
        """Verify compressed bytes are uploaded."""
        from echolake.outputs.destinations.azure_blob import AzureBlobDestination

        mock_blob_client = MagicMock()
        mock_container_client = MagicMock()
        mock_container_client.get_blob_client.return_value = mock_blob_client
        mock_bsc = MagicMock()
        mock_bsc.get_container_client.return_value = mock_container_client
        mock_bsc_class.from_connection_string.return_value = mock_bsc

        dest = AzureBlobDestination(
            container="test-container",
            path_template="{filename}",
            connection_string="DefaultEndpointsProtocol=https;AccountName=test",
            compression="gzip",
        )
        dest.write("test.jsonl", ['{"msg": "hello"}'])

        mock_blob_client.upload_blob.assert_called_once()
        call_args = mock_blob_client.upload_blob.call_args

        # Verify body is gzip-compressed
        body = call_args[0][0]
        decompressed = gzip.decompress(body).decode("utf-8")
        assert '{"msg": "hello"}' in decompressed

        # Verify blob name has .gz extension
        blob_name = mock_container_client.get_blob_client.call_args[0][0]
        assert blob_name.endswith(".gz")
