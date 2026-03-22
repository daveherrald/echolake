"""AWS S3 input source."""

from typing import Iterator, Optional
import fnmatch

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from ..base import InputSource


class S3Source(InputSource):
    """Input source for AWS S3."""

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        pattern: str = "*",
        profile: Optional[str] = None,
        region: Optional[str] = None,
    ):
        """
        Initialize S3 source.

        Args:
            bucket: S3 bucket name
            prefix: Key prefix (folder path)
            pattern: File pattern for matching
            profile: AWS profile name (optional)
            region: AWS region (optional)
        """
        if not BOTO3_AVAILABLE:
            raise ImportError("boto3 is required for S3 source. Install with: pip install boto3")

        self.bucket = bucket
        self.prefix = prefix.rstrip('/')
        self.pattern = pattern

        # Initialize S3 client
        session_kwargs = {}
        if profile:
            session_kwargs['profile_name'] = profile
        if region:
            session_kwargs['region_name'] = region

        session = boto3.Session(**session_kwargs)
        self.s3_client = session.client('s3')

        # Verify bucket access
        try:
            self.s3_client.head_bucket(Bucket=bucket)
        except (ClientError, NoCredentialsError) as e:
            raise ConnectionError(f"Cannot access S3 bucket {bucket}: {e}")

    def list_files(self) -> Iterator[str]:
        """
        List files in S3 bucket matching pattern.

        Yields:
            S3 keys (paths)
        """
        paginator = self.s3_client.get_paginator('list_objects_v2')

        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            if 'Contents' not in page:
                continue

            for obj in page['Contents']:
                key = obj['Key']

                # Skip directories (keys ending with /)
                if key.endswith('/'):
                    continue

                # Check pattern match
                filename = key.split('/')[-1]
                if fnmatch.fnmatch(filename, self.pattern):
                    yield key

    def read_file(self, file_id: str, chunk_size: int = 8 * 1024 * 1024) -> Iterator[bytes]:
        """
        Read file from S3 in chunks (streaming).

        Args:
            file_id: S3 key
            chunk_size: Chunk size in bytes (default: 8MB)

        Yields:
            Chunks of file content as bytes
        """
        try:
            response = self.s3_client.get_object(Bucket=self.bucket, Key=file_id)
            # S3's Body is a streaming object - read in chunks
            stream = response['Body']
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        except ClientError:
            # Skip files that can't be read
            pass

    def close(self):
        """Clean up resources."""
        # boto3 client doesn't need explicit cleanup
        pass
