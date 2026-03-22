"""AWS S3 output destination."""

import re
import logging
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from ..base import OutputDestination

logger = logging.getLogger(__name__)

# S3 multipart upload minimum part size is 5 MB
MIN_PART_SIZE = 5 * 1024 * 1024  # 5 MB


class S3Destination(OutputDestination):
    """Output destination for AWS S3 using streaming multipart upload."""

    def __init__(
        self,
        bucket: str,
        path_template: str = "output/{filename}",
        profile: Optional[str] = None,
        region: Optional[str] = None,
        compression: Optional[str] = None,
    ):
        if not BOTO3_AVAILABLE:
            raise ImportError("boto3 is required for S3 destination. Install with: pip install boto3")

        self.bucket = bucket
        self.path_template = path_template
        self.compression = compression

        # Per-key streaming state: key -> {upload_id, parts, buffer, part_number}
        self._uploads: Dict[str, dict] = {}

        # Initialize S3 client
        session_kwargs = {}
        if profile:
            session_kwargs['profile_name'] = profile
        if region:
            session_kwargs['region_name'] = region

        session = boto3.Session(**session_kwargs)
        self.s3_client = session.client('s3')

    def write(self, source_file_id: str, events: List[str], batch_size: int = 1000, metadata: Optional[Dict[str, str]] = None):
        """
        Write events to S3 using streaming multipart upload.

        Events are appended to a per-key buffer. When the buffer exceeds
        MIN_PART_SIZE, a part is uploaded. This keeps memory bounded.
        """
        output_key = self._generate_key(source_file_id, metadata=metadata)

        # Initialize multipart upload for this key if needed
        if output_key not in self._uploads:
            if self.compression:
                # For compressed output, we must buffer everything (can't stream compress parts)
                self._uploads[output_key] = {
                    'mode': 'buffered',
                    'buffer': [],
                }
            else:
                try:
                    response = self.s3_client.create_multipart_upload(
                        Bucket=self.bucket,
                        Key=output_key,
                    )
                    self._uploads[output_key] = {
                        'mode': 'multipart',
                        'upload_id': response['UploadId'],
                        'parts': [],
                        'buffer': b'',
                        'part_number': 1,
                    }
                except ClientError as e:
                    raise IOError(f"Failed to create multipart upload for {output_key}: {e}")

        state = self._uploads[output_key]

        if state['mode'] == 'buffered':
            state['buffer'].extend(events)
            return

        # Append events to byte buffer
        chunk = ('\n'.join(events) + '\n').encode('utf-8')
        state['buffer'] += chunk

        # Upload part if buffer exceeds minimum part size
        while len(state['buffer']) >= MIN_PART_SIZE:
            self._upload_part(output_key, state)

    def _upload_part(self, key: str, state: dict):
        """Upload one part from the buffer."""
        # Take MIN_PART_SIZE bytes from buffer
        part_data = state['buffer'][:MIN_PART_SIZE]
        state['buffer'] = state['buffer'][MIN_PART_SIZE:]

        part_num = state['part_number']
        try:
            response = self.s3_client.upload_part(
                Bucket=self.bucket,
                Key=key,
                UploadId=state['upload_id'],
                PartNumber=part_num,
                Body=part_data,
            )
            state['parts'].append({
                'ETag': response['ETag'],
                'PartNumber': part_num,
            })
            state['part_number'] += 1
        except ClientError as e:
            # Abort the multipart upload on failure
            self.s3_client.abort_multipart_upload(
                Bucket=self.bucket,
                Key=key,
                UploadId=state['upload_id'],
            )
            raise IOError(f"Failed to upload part {part_num} for {key}: {e}")

    def flush(self):
        """Finalize all multipart uploads and upload buffered compressed objects."""
        for key, state in self._uploads.items():
            if state['mode'] == 'buffered':
                # Compressed: upload entire buffer as single object
                events = state['buffer']
                if not events:
                    continue
                content = '\n'.join(events)
                content_bytes = content.encode('utf-8')
                content_bytes = self._compress_bytes(content_bytes, self.compression)
                try:
                    self.s3_client.put_object(
                        Bucket=self.bucket,
                        Key=key,
                        Body=content_bytes,
                    )
                except ClientError as e:
                    raise IOError(f"Failed to write to S3: {e}")
            else:
                # Multipart: flush remaining buffer and complete
                upload_id = state['upload_id']

                # Upload any remaining data in buffer
                if state['buffer']:
                    if state['parts']:
                        # We have prior parts — upload remainder as final part
                        part_num = state['part_number']
                        try:
                            response = self.s3_client.upload_part(
                                Bucket=self.bucket,
                                Key=key,
                                UploadId=upload_id,
                                PartNumber=part_num,
                                Body=state['buffer'],
                            )
                            state['parts'].append({
                                'ETag': response['ETag'],
                                'PartNumber': part_num,
                            })
                        except ClientError as e:
                            self.s3_client.abort_multipart_upload(
                                Bucket=self.bucket, Key=key, UploadId=upload_id)
                            raise IOError(f"Failed to upload final part for {key}: {e}")
                    else:
                        # No prior parts (file smaller than MIN_PART_SIZE)
                        # Abort multipart and use simple put_object
                        self.s3_client.abort_multipart_upload(
                            Bucket=self.bucket, Key=key, UploadId=upload_id)
                        try:
                            self.s3_client.put_object(
                                Bucket=self.bucket,
                                Key=key,
                                Body=state['buffer'],
                            )
                        except ClientError as e:
                            raise IOError(f"Failed to write to S3: {e}")
                        continue

                # Complete multipart upload
                if state['parts']:
                    try:
                        self.s3_client.complete_multipart_upload(
                            Bucket=self.bucket,
                            Key=key,
                            UploadId=upload_id,
                            MultipartUpload={'Parts': state['parts']},
                        )
                    except ClientError as e:
                        self.s3_client.abort_multipart_upload(
                            Bucket=self.bucket, Key=key, UploadId=upload_id)
                        raise IOError(f"Failed to complete multipart upload for {key}: {e}")
                else:
                    # No data at all — abort
                    self.s3_client.abort_multipart_upload(
                        Bucket=self.bucket, Key=key, UploadId=upload_id)

        self._uploads.clear()

    def _generate_key(self, source_file_id: str, metadata: Optional[Dict[str, str]] = None) -> str:
        """Generate output key from template."""
        now = datetime.utcnow()
        source_filename = Path(source_file_id).name

        variables = {
            'filename': source_filename,
            'year': now.strftime('%Y'),
            'month': now.strftime('%m'),
            'day': now.strftime('%d'),
            'hour': now.strftime('%H'),
            'minute': now.strftime('%M'),
        }

        if metadata and 'sourcetype' in metadata:
            variables['sourcetype'] = re.sub(r'[:/\\]', '-', metadata['sourcetype'])
        else:
            variables['sourcetype'] = 'unknown'

        key = self.path_template.format(**variables)

        ext = self._compression_extension(self.compression)
        if ext and not key.endswith(ext):
            key += ext

        return key

    def close(self):
        """Flush any remaining buffered events and clean up."""
        self.flush()
