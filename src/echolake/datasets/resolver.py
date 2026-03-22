"""Dataset resolution and discovery."""

from pathlib import Path
from typing import Optional, Dict, Any
import requests

from .models import DatasetManifest, ResolvedDataset, DatasetDependency
from .cache import DatasetCache
from .github import GitHubClient
from .utils import parse_dataset_ref, satisfies_version_constraint, normalize_path


class DatasetResolver:
    """Resolves dataset references to manifests and files."""

    def __init__(self, cache: Optional[DatasetCache] = None, github_client: Optional[GitHubClient] = None):
        """
        Initialize resolver.

        Args:
            cache: Optional cache manager (creates default if not provided)
            github_client: Optional GitHub client (creates default if not provided)
        """
        self.cache = cache or DatasetCache()
        self.github = github_client or GitHubClient()

    def resolve(
        self,
        ref: str,
        force_download: bool = False,
        timeout: int = 30,
    ) -> ResolvedDataset:
        """
        Resolve a dataset reference to a ResolvedDataset.

        Args:
            ref: Dataset reference (org/name, local:/path, https://url, etc.)
            force_download: Force re-download even if cached
            timeout: Request timeout for downloads

        Returns:
            ResolvedDataset with manifest and base path

        Raises:
            FileNotFoundError: If dataset not found
            ValueError: If reference is invalid
        """
        # Parse reference
        path, version, scheme = parse_dataset_ref(ref)

        # Route to appropriate resolver
        if scheme == "local":
            return self._resolve_local(path)
        elif scheme in ("http", "https"):
            return self._resolve_http(path, version, force_download, timeout)
        elif scheme == "github":
            return self._resolve_github(path, version, force_download, timeout)
        else:
            # Default: try local first, then raise error
            raise ValueError(
                f"Unsupported dataset reference: {ref}. "
                f"Supported formats: local:/path, https://url, github:org/repo/path"
            )

    def _resolve_local(self, path: str) -> ResolvedDataset:
        """
        Resolve local dataset.

        Args:
            path: Local path to dataset directory or manifest

        Returns:
            ResolvedDataset

        Raises:
            FileNotFoundError: If dataset not found
        """
        local_path = Path(path).resolve()

        # Determine manifest path
        if local_path.is_dir():
            manifest_path = local_path / "dataset.yaml"
            base_path = local_path
        else:
            manifest_path = local_path
            base_path = local_path.parent

        if not manifest_path.exists():
            raise FileNotFoundError(f"Manifest not found: {manifest_path}")

        # Load manifest
        manifest = DatasetManifest.from_file(manifest_path)

        # Resolve dependencies (recursive)
        resolved_deps = []
        for dep in manifest.dependencies:
            dep_resolved = self.resolve(dep.dataset)
            resolved_deps.append(dep_resolved)

        return ResolvedDataset(
            manifest=manifest,
            base_path=base_path,
            resolved_dependencies=resolved_deps,
        )

    def _resolve_http(
        self,
        url: str,
        version: Optional[str],
        force_download: bool,
        timeout: int,
    ) -> ResolvedDataset:
        """
        Resolve HTTP/HTTPS dataset.

        Args:
            url: URL to dataset.yaml or base directory
            version: Optional version constraint
            force_download: Force re-download
            timeout: Request timeout

        Returns:
            ResolvedDataset

        Raises:
            requests.RequestException: If download fails
        """
        # Normalize URL to point to dataset.yaml
        if not url.endswith("dataset.yaml"):
            url = f"{url.rstrip('/')}/dataset.yaml"

        # Create cache key from URL
        cache_key = url.replace("://", "/").replace(":", "/")

        # Check cache
        if not force_download and self.cache.is_cached(cache_key, version):
            cached_manifest = self.cache.get_cached_manifest(cache_key, version)
            cache_path = self.cache.get_cache_path(cache_key, version)

            if cached_manifest:
                # Resolve dependencies
                resolved_deps = []
                for dep in cached_manifest.dependencies:
                    dep_resolved = self.resolve(dep.dataset)
                    resolved_deps.append(dep_resolved)

                return ResolvedDataset(
                    manifest=cached_manifest,
                    base_path=cache_path,
                    resolved_dependencies=resolved_deps,
                )

        # Download manifest
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()

        # Parse manifest
        import yaml
        manifest_data = yaml.safe_load(response.text)
        manifest = DatasetManifest(**manifest_data)

        # Determine base URL for bundled files
        base_url = url.rsplit("/", 1)[0]

        # Cache dataset
        cache_path = self.cache.cache_dataset(
            cache_key=cache_key,
            manifest_url=url,
            bundled_files_base_url=base_url,
            manifest=manifest,
            version=version,
            timeout=timeout,
        )

        # Resolve dependencies
        resolved_deps = []
        for dep in manifest.dependencies:
            dep_resolved = self.resolve(dep.dataset)
            resolved_deps.append(dep_resolved)

        return ResolvedDataset(
            manifest=manifest,
            base_path=cache_path,
            resolved_dependencies=resolved_deps,
        )

    def _resolve_github(
        self,
        ref: str,
        version: Optional[str],
        force_download: bool,
        timeout: int,
    ) -> ResolvedDataset:
        """
        Resolve GitHub dataset.

        Args:
            ref: GitHub reference (org/repo/path)
            version: Optional version constraint
            force_download: Force re-download
            timeout: Request timeout

        Returns:
            ResolvedDataset

        Raises:
            requests.RequestException: If download fails
        """
        # Parse GitHub reference
        org, repo, path, ref_version = self.github.parse_github_ref(ref)

        # Use version from ref if not provided separately
        if not version and ref_version:
            version = ref_version

        # Download dataset
        manifest, cache_path, resolved_version = self.github.download_dataset(
            org=org,
            repo=repo,
            path=path,
            version=version,
            cache=self.cache,
            force_download=force_download,
            timeout=timeout,
        )

        # Resolve dependencies
        resolved_deps = []
        for dep in manifest.dependencies:
            dep_resolved = self.resolve(dep.dataset)
            resolved_deps.append(dep_resolved)

        return ResolvedDataset(
            manifest=manifest,
            base_path=cache_path,
            resolved_dependencies=resolved_deps,
        )

    def list_cached(self) -> Dict[str, Any]:
        """
        List all cached datasets.

        Returns:
            Dictionary mapping cache keys to manifest info
        """
        cached = {}

        # Walk cache directory
        for manifest_path in self.cache.cache_dir.rglob("dataset.yaml"):
            try:
                manifest = DatasetManifest.from_file(manifest_path)
                cache_key = str(manifest_path.parent.relative_to(self.cache.cache_dir))

                cached[cache_key] = {
                    "name": manifest.metadata.name,
                    "version": manifest.metadata.version,
                    "description": manifest.metadata.description,
                    "path": str(manifest_path.parent),
                }
            except Exception:
                # Skip invalid manifests
                continue

        return cached
