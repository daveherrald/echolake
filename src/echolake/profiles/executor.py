"""Profile execution - converts profiles to EchoEngine configs and executes."""

from pathlib import Path
from typing import List, Optional, Dict, Any
import logging

from ..core.config import (
    Config,
    EchoConfig as CoreEchoConfig,
    InputConfig,
    InputSourceConfig,
    OutputConfig,
    OutputDestinationConfig,
)
from ..core.echo import EchoEngine
from .models import EchoProfile, Destination, CredentialsConfig

logger = logging.getLogger(__name__)


class ProfileExecutor:
    """
    Executes echo profiles by converting them to EchoEngine configs.

    Handles:
    - Profile-to-config conversion
    - Multiple datasets (sequential execution)
    - Multiple destinations (parallel fan-out)
    - Credentials loading and merging
    - Runtime overrides
    """

    def __init__(
        self,
        profile: EchoProfile,
        destinations: List[Destination],
        credentials: Optional[Dict[str, CredentialsConfig]] = None,
        overrides: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize profile executor.

        Args:
            profile: EchoProfile to execute
            destinations: List of Destination objects
            credentials: Optional credentials dict (dest_name -> CredentialsConfig)
            overrides: Optional runtime overrides (delta_factor, target_time, etc.)
        """
        self.profile = profile
        self.destinations = destinations
        self.credentials = credentials or {}
        self.overrides = overrides or {}

    def execute(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Execute the echo profile.

        Args:
            dry_run: If True, don't write output (for preview/testing)

        Returns:
            Dict with execution results and statistics
        """
        logger.info(f"Executing profile: {self.profile.profile.name}")

        results = {
            "profile": self.profile.profile.name,
            "version": self.profile.profile.version,
            "datasets": [],
            "destinations": [d.destination.name for d in self.destinations],
            "total_events": 0,
            "total_modified": 0,
            "errors": 0,
        }

        # Execute each dataset in sequence
        for i, dataset_ref in enumerate(self.profile.datasets, 1):
            logger.info(f"Processing dataset {i}/{len(self.profile.datasets)}: {dataset_ref.ref}")

            try:
                dataset_stats = self._execute_dataset(dataset_ref, dry_run)
                results["datasets"].append(dataset_stats)
                results["total_events"] += dataset_stats.get("event_count", 0)
                results["total_modified"] += dataset_stats.get("events_modified", 0)

            except Exception as e:
                logger.error(f"Error processing dataset {dataset_ref.ref}: {e}")
                results["errors"] += 1
                results["datasets"].append({
                    "ref": dataset_ref.ref,
                    "error": str(e),
                })

        return results

    def _execute_dataset(self, dataset_ref, dry_run: bool = False) -> Dict[str, Any]:
        """
        Execute a single dataset with all destinations.

        Args:
            dataset_ref: DatasetReference to execute
            dry_run: If True, don't write output

        Returns:
            Dict with dataset execution statistics
        """
        # Get echo config for this dataset
        # Priority: per-dataset override > profile default > system default
        echo_config = self._get_echo_config(dataset_ref)

        # For now, we'll execute to the first destination
        # TODO: Support multiple destinations in parallel
        destination = self.destinations[0]

        # Convert to EchoEngine Config
        config = self._build_config(dataset_ref, destination, echo_config)

        # Execute with EchoEngine
        engine = EchoEngine(config, dry_run=dry_run)
        stats = engine.run()

        # Convert stats to dict
        return {
            "ref": dataset_ref.ref,
            "description": dataset_ref.description,
            "event_count": stats.event_count,
            "events_modified": stats.events_modified,
            "errors": stats.errors,
            "original_earliest": stats.original_earliest_time.isoformat() if stats.original_earliest_time else None,
            "original_latest": stats.original_latest_time.isoformat() if stats.original_latest_time else None,
            "new_earliest": stats.new_earliest_time.isoformat() if stats.new_earliest_time else None,
            "new_latest": stats.new_latest_time.isoformat() if stats.new_latest_time else None,
        }

    def _get_echo_config(self, dataset_ref) -> CoreEchoConfig:
        """
        Get echo configuration for a dataset.

        Priority (highest to lowest):
        1. Runtime overrides (CLI args)
        2. Per-dataset overrides (in profile)
        3. Profile-level defaults
        4. System defaults

        Args:
            dataset_ref: DatasetReference

        Returns:
            CoreEchoConfig
        """
        # Start with system defaults
        config = CoreEchoConfig()

        # Apply profile-level defaults (check 'echo' first, fall back to 'replay' for compat)
        profile_echo = self.profile.echo or self.profile.replay
        if profile_echo:
            if profile_echo.delta_factor is not None:
                config.delta_factor = profile_echo.delta_factor
            if profile_echo.base_time is not None:
                config.base_time = profile_echo.base_time
            if profile_echo.target_time is not None:
                config.target_time = profile_echo.target_time
            if profile_echo.prevent_future is not None:
                config.prevent_future = profile_echo.prevent_future

        # Apply per-dataset overrides (check 'echo' first, fall back to 'replay' for compat)
        dataset_echo = dataset_ref.echo or dataset_ref.replay
        if dataset_echo:
            if dataset_echo.delta_factor is not None:
                config.delta_factor = dataset_echo.delta_factor
            if dataset_echo.base_time is not None:
                config.base_time = dataset_echo.base_time
            if dataset_echo.target_time is not None:
                config.target_time = dataset_echo.target_time
            if dataset_echo.prevent_future is not None:
                config.prevent_future = dataset_echo.prevent_future

        # Apply runtime overrides (CLI args)
        if "delta_factor" in self.overrides:
            config.delta_factor = self.overrides["delta_factor"]
        if "base_time" in self.overrides:
            config.base_time = self.overrides["base_time"]
        if "target_time" in self.overrides:
            config.target_time = self.overrides["target_time"]
        if "prevent_future" in self.overrides:
            config.prevent_future = self.overrides["prevent_future"]

        return config

    def _build_config(
        self,
        dataset_ref,
        destination: Destination,
        echo_config: CoreEchoConfig,
    ) -> Config:
        """
        Build a Config object for EchoEngine.

        Args:
            dataset_ref: DatasetReference to echo
            destination: Destination to write to
            echo_config: Echo configuration

        Returns:
            Config object for EchoEngine
        """
        # Parse dataset reference
        # For now, only support local: references
        # Format: local:path/to/dataset or local:/absolute/path
        ref = dataset_ref.ref
        if not ref.startswith("local:"):
            raise ValueError(f"Only local: dataset references are currently supported, got: {ref}")

        dataset_path = ref[6:]  # Remove "local:" prefix

        # Resolve path
        if dataset_path.startswith("/"):
            # Absolute path
            resolved_path = Path(dataset_path)
        else:
            # Relative to current directory
            resolved_path = Path.cwd() / dataset_path

        if not resolved_path.exists():
            raise FileNotFoundError(f"Dataset not found: {resolved_path}")

        # Build input config
        # Point to the dataset directory
        input_config = InputConfig(
            source=InputSourceConfig(
                type="local",
                path=str(resolved_path),
                pattern="*.jsonl",  # Default pattern
            ),
            format="jsonl",  # Default format
            schema_type=dataset_ref.schema_type or self.profile.schema_type or "raw",
        )

        # Build output config from destination
        output_config = self._build_output_config(destination)

        # Create full config
        config = Config(
            input=input_config,
            output=output_config,
            echo=echo_config,
        )

        return config

    def _build_output_config(self, destination: Destination) -> OutputConfig:
        """
        Build output config from destination.

        Args:
            destination: Destination object

        Returns:
            OutputConfig
        """
        # Build destination config based on type
        dest_type = destination.type.lower()
        conn = destination.connection

        if dest_type == "local":
            dest_config = OutputDestinationConfig(
                type="local",
                path=conn.path or "./output",
            )

        elif dest_type == "stdout":
            dest_config = OutputDestinationConfig(
                type="stdout",
            )

        elif dest_type == "s3":
            dest_config = OutputDestinationConfig(
                type="s3",
                bucket=conn.bucket,
                path_template=conn.prefix or "{filename}",
            )

        elif dest_type == "gcs":
            dest_config = OutputDestinationConfig(
                type="gcs",
                bucket=conn.bucket,
                path_template=conn.prefix or "{filename}",
            )

        elif dest_type in ["azure", "azure_blob"]:
            dest_config = OutputDestinationConfig(
                type="azure",
                bucket=conn.bucket,  # Container name
                path_template=conn.prefix or "{filename}",
            )

        elif dest_type == "chronicle":
            # Chronicle not yet implemented in outputs
            # For now, fall back to local
            logger.warning(f"Chronicle destination not yet implemented, using local output")
            dest_config = OutputDestinationConfig(
                type="local",
                path="./output",
            )

        else:
            raise ValueError(f"Unsupported destination type: {dest_type}")

        # Build output config
        output_config = OutputConfig(
            destination=dest_config,
            format=destination.format or "jsonl",
            compression=destination.compression,
        )

        return output_config


def load_credentials_file(path: Optional[Path] = None) -> Dict[str, CredentialsConfig]:
    """
    Load credentials from file.

    Args:
        path: Path to credentials file (defaults to ~/.echolake/credentials.yaml)

    Returns:
        Dict mapping destination names to CredentialsConfig
    """
    if path is None:
        path = Path.home() / ".echolake" / "credentials.yaml"

    if not path.exists():
        logger.debug(f"Credentials file not found: {path}")
        return {}

    try:
        return CredentialsConfig.from_file(path)
    except Exception as e:
        logger.warning(f"Error loading credentials from {path}: {e}")
        return {}
