"""Databricks-specific utilities and notebook-friendly API."""

from typing import Optional, Dict, Any
from ..core.config import (
    Config,
    InputConfig,
    InputSourceConfig,
    OutputConfig,
    OutputDestinationConfig,
    EchoConfig,
    EchoStats,
)
from ..core.echo import EchoEngine


class Replay:
    """
    Notebook-friendly API for EchoLake in Databricks.

    Example usage in Databricks notebook:
        from echolake import Replay

        replay = Replay()
        replay.input_source("dbfs:/mnt/logs", format="jsonl", schema="lakehouse_bronze")
        replay.output_destination("dbfs:/mnt/replayed", format="jsonl")
        replay.set_timestamp_options(delta_factor=2.0, prevent_future=True)
        stats = replay.run()
        print(f"Replayed {stats.event_count} events")
    """

    def __init__(self):
        """Initialize Replay instance."""
        self.config = Config()
        self._input_configured = False
        self._output_configured = False

    def input_source(
        self,
        path: str,
        format: str = "jsonl",
        schema: Optional[str] = None,
        source_type: str = "auto",
        pattern: str = "*",
    ) -> 'Replay':
        """
        Configure input source.

        Args:
            path: Input path (local, DBFS, S3, GCS, etc.)
            format: Input format (json, jsonl, text, xml)
            schema: Schema type (lakehouse_bronze, ocsf, raw)
            source_type: Source type (auto, local, s3, gcs, azure)
            pattern: File pattern for matching

        Returns:
            Self for chaining
        """
        # Auto-detect source type
        if source_type == "auto":
            if path.startswith("dbfs:/") or path.startswith("/dbfs/"):
                source_type = "local"
                if path.startswith("dbfs:/"):
                    path = "/dbfs/" + path[6:]
            elif path.startswith("s3://"):
                source_type = "s3"
                path = path[5:]
            elif path.startswith("gs://") or path.startswith("gcs://"):
                source_type = "gcs"
                path = path[5:] if path.startswith("gs://") else path[6:]
            else:
                source_type = "local"

        source_config = InputSourceConfig(
            type=source_type,
            path=path if source_type == "local" else None,
            bucket=path.split('/')[0] if source_type in ["s3", "gcs", "azure"] else None,
            prefix='/'.join(path.split('/')[1:]) if source_type in ["s3", "gcs", "azure"] else "",
            pattern=pattern,
        )

        self.config.input = InputConfig(
            source=source_config,
            format=format,
            schema=schema,
        )

        self._input_configured = True
        return self

    def output_destination(
        self,
        path: str,
        format: str = "jsonl",
        dest_type: str = "auto",
        compression: Optional[str] = None,
        batch_size: int = 1000,
    ) -> 'Replay':
        """
        Configure output destination.

        Args:
            path: Output path (local, DBFS, S3, GCS, etc.)
            format: Output format (json, jsonl, text)
            dest_type: Destination type (auto, local, s3, gcs, azure)
            compression: Compression (gzip, bzip2, None)
            batch_size: Batch size for writing

        Returns:
            Self for chaining
        """
        # Auto-detect destination type
        if dest_type == "auto":
            if path.startswith("dbfs:/") or path.startswith("/dbfs/"):
                dest_type = "local"
                if path.startswith("dbfs:/"):
                    path = "/dbfs/" + path[6:]
            elif path.startswith("s3://"):
                dest_type = "s3"
                path = path[5:]
            elif path.startswith("gs://") or path.startswith("gcs://"):
                dest_type = "gcs"
                path = path[5:] if path.startswith("gs://") else path[6:]
            else:
                dest_type = "local"

        dest_config = OutputDestinationConfig(
            type=dest_type,
            path=path if dest_type == "local" else None,
            bucket=path.split('/')[0] if dest_type in ["s3", "gcs", "azure"] else None,
            path_template='{filename}',
        )

        self.config.output = OutputConfig(
            destination=dest_config,
            format=format,
            compression=compression,
            batch_size=batch_size,
        )

        self._output_configured = True
        return self

    def set_timestamp_options(
        self,
        delta_factor: float = 1.0,
        base_time: str = "auto",
        target_time: str = "now",
        prevent_future: bool = True,
        ceiling_time: Optional[str] = "now",
    ) -> 'Replay':
        """
        Configure timestamp manipulation options.

        Args:
            delta_factor: Time delta multiplication factor
            base_time: Base time reference (auto, earliest, or ISO8601)
            target_time: Target time for replay (now or ISO8601)
            prevent_future: Prevent timestamps in the future
            ceiling_time: Maximum allowed timestamp

        Returns:
            Self for chaining
        """
        self.config.echo = EchoConfig(
            delta_factor=delta_factor,
            base_time=base_time,
            target_time=target_time,
            prevent_future=prevent_future,
            ceiling_time=ceiling_time,
        )

        return self

    def run(self) -> EchoStats:
        """
        Run the replay process.

        Returns:
            EchoStats with operation statistics

        Raises:
            ValueError: If input or output not configured
        """
        if not self._input_configured:
            raise ValueError("Input source not configured. Call input_source() first.")

        if not self._output_configured:
            raise ValueError("Output destination not configured. Call output_destination() first.")

        engine = EchoEngine(self.config)
        return engine.run()

    def validate(self) -> Dict[str, Any]:
        """
        Validate configuration without running echo.

        Returns:
            Dictionary with validation results
        """
        errors = []

        if not self._input_configured:
            errors.append("Input source not configured")

        if not self._output_configured:
            errors.append("Output destination not configured")

        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'config': self.config.model_dump() if len(errors) == 0 else None,
        }


__all__ = ['Replay']
