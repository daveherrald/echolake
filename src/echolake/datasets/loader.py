"""Dataset manifest loading."""

from pathlib import Path
from typing import Any, Dict, List, Tuple

from .models import DatasetManifest


def load_dataset(dataset_ref: str) -> Tuple[Path, DatasetManifest]:
    """
    Load a dataset manifest from a reference.

    Args:
        dataset_ref: Dataset reference (e.g., "local:./my-datasets/web-server-logs")

    Returns:
        Tuple of (dataset_root_path, manifest)

    Raises:
        ValueError: If dataset reference is invalid or not found
        FileNotFoundError: If dataset.yaml not found
    """
    # Parse the reference
    if dataset_ref.startswith("local:"):
        dataset_path = Path(dataset_ref[6:])  # Remove "local:" prefix
    else:
        # Assume it's a local path if no prefix
        dataset_path = Path(dataset_ref)

    # Resolve to absolute path
    dataset_path = dataset_path.resolve()

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset path not found: {dataset_path}")

    # Look for dataset.yaml
    manifest_path = dataset_path / "dataset.yaml"
    if not manifest_path.exists():
        raise FileNotFoundError(
            f"Dataset manifest not found: {manifest_path}\n"
            f"Expected dataset.yaml in {dataset_path}"
        )

    # Use the canonical, fully typed manifest contract.
    manifest = DatasetManifest.from_file(manifest_path)

    return dataset_path, manifest


def get_bundled_files(dataset_path: Path, manifest: DatasetManifest) -> List[Path]:
    """
    Get list of bundled file paths from a dataset.

    Args:
        dataset_path: Root path of the dataset
        manifest: Loaded dataset manifest

    Returns:
        List of absolute paths to bundled files
    """
    bundled_files = []

    for file_entry in manifest.files.bundled:
        # Resolve relative to dataset root.
        full_path = dataset_path / file_entry.path
        if full_path.exists():
            bundled_files.append(full_path)

    return bundled_files


def get_dataset_defaults(manifest: DatasetManifest) -> Dict[str, Any]:
    """
    Extract default configuration from dataset manifest.

    Args:
        manifest: Loaded dataset manifest

    Returns:
        Dictionary of default configuration values
    """
    if manifest.defaults is None:
        return {}
    return manifest.defaults.model_dump(
        exclude_none=False,
        exclude_unset=True,
        by_alias=False,
    )
