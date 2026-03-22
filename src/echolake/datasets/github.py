"""GitHub integration for datasets."""

import os
from typing import Optional, List, Dict, Any
import requests

from .models import DatasetManifest
from .cache import DatasetCache
from .utils import satisfies_version_constraint, compare_versions


class GitHubClient:
    """Client for interacting with GitHub API and raw content."""

    def __init__(self, token: Optional[str] = None):
        """
        Initialize GitHub client.

        Args:
            token: Optional GitHub API token (defaults to GITHUB_TOKEN env var)
        """
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.api_base = "https://api.github.com"
        self.raw_base = "https://raw.githubusercontent.com"

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers

    def parse_github_ref(self, ref: str) -> tuple:
        """
        Parse GitHub reference.

        Args:
            ref: GitHub reference (org/repo/path or org/repo/path@version)

        Returns:
            Tuple of (org, repo, path, version)

        Examples:
            "org/repo/path" -> ("org", "repo", "path", None)
            "org/repo/path@v1.0.0" -> ("org", "repo", "path", "v1.0.0")
            "org/repo/dir/subdir" -> ("org", "repo", "dir/subdir", None)
        """
        # Split version if present
        version = None
        if '@' in ref:
            ref, version = ref.rsplit('@', 1)

        # Split into parts
        parts = ref.split('/')

        if len(parts) < 2:
            raise ValueError(f"Invalid GitHub reference: {ref}. Expected org/repo/path")

        org = parts[0]
        repo = parts[1]
        path = '/'.join(parts[2:]) if len(parts) > 2 else ""

        return org, repo, path, version

    def get_releases(self, org: str, repo: str, timeout: int = 30) -> List[Dict[str, Any]]:
        """
        Get releases for a repository.

        Args:
            org: GitHub organization/user
            repo: Repository name
            timeout: Request timeout

        Returns:
            List of release dictionaries

        Raises:
            requests.RequestException: If API request fails
        """
        url = f"{self.api_base}/repos/{org}/{repo}/releases"
        response = requests.get(url, headers=self._get_headers(), timeout=timeout)
        response.raise_for_status()
        return response.json()

    def get_tags(self, org: str, repo: str, timeout: int = 30) -> List[Dict[str, Any]]:
        """
        Get tags for a repository.

        Args:
            org: GitHub organization/user
            repo: Repository name
            timeout: Request timeout

        Returns:
            List of tag dictionaries

        Raises:
            requests.RequestException: If API request fails
        """
        url = f"{self.api_base}/repos/{org}/{repo}/tags"
        response = requests.get(url, headers=self._get_headers(), timeout=timeout)
        response.raise_for_status()
        return response.json()

    def resolve_version(
        self,
        org: str,
        repo: str,
        version_constraint: Optional[str] = None,
        timeout: int = 30,
    ) -> str:
        """
        Resolve version constraint to specific version/tag/branch.

        Args:
            org: GitHub organization/user
            repo: Repository name
            version_constraint: Version constraint (e.g., ">=1.0.0", "latest", "main")
            timeout: Request timeout

        Returns:
            Resolved version/tag/branch name

        Raises:
            ValueError: If no matching version found
            requests.RequestException: If API request fails
        """
        # Default to latest
        if not version_constraint or version_constraint == "*" or version_constraint == "latest":
            # Try to get latest release
            try:
                releases = self.get_releases(org, repo, timeout)
                if releases:
                    return releases[0]["tag_name"]
            except requests.RequestException:
                pass

            # Fall back to main branch
            return "main"

        # If it looks like a branch/commit (not semver or constraint), return as-is
        # Check if it's a semver constraint (starts with operator or v/digit)
        is_version_constraint = (
            version_constraint[0].isdigit() or
            version_constraint.startswith('v') or
            version_constraint.startswith(('>', '<', '=', '^', '~')) or
            'x' in version_constraint.lower()
        )

        if not is_version_constraint:
            # Likely a branch name or commit SHA
            return version_constraint

        # Try to match against releases
        try:
            releases = self.get_releases(org, repo, timeout)
            matching_versions = []

            for release in releases:
                tag = release["tag_name"]
                try:
                    if satisfies_version_constraint(tag, version_constraint):
                        matching_versions.append(tag)
                except ValueError:
                    # Skip tags that don't match semver
                    continue

            if matching_versions:
                # Return the highest matching version
                matching_versions.sort(key=lambda v: tuple(map(int, v.lstrip('v').split('.'))), reverse=True)
                return matching_versions[0]
        except requests.RequestException:
            pass

        # Try to match against tags
        try:
            tags = self.get_tags(org, repo, timeout)
            matching_versions = []

            for tag in tags:
                tag_name = tag["name"]
                try:
                    if satisfies_version_constraint(tag_name, version_constraint):
                        matching_versions.append(tag_name)
                except ValueError:
                    continue

            if matching_versions:
                matching_versions.sort(key=lambda v: tuple(map(int, v.lstrip('v').split('.'))), reverse=True)
                return matching_versions[0]
        except requests.RequestException:
            pass

        # If exact version, try to use it directly
        return version_constraint

    def get_raw_content(
        self,
        org: str,
        repo: str,
        path: str,
        ref: str = "main",
        timeout: int = 30,
    ) -> str:
        """
        Get raw file content from GitHub.

        Args:
            org: GitHub organization/user
            repo: Repository name
            path: File path in repository
            ref: Git ref (branch, tag, commit)
            timeout: Request timeout

        Returns:
            File content as string

        Raises:
            requests.RequestException: If request fails
        """
        url = f"{self.raw_base}/{org}/{repo}/{ref}/{path}"
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.text

    def download_dataset(
        self,
        org: str,
        repo: str,
        path: str,
        version: Optional[str] = None,
        cache: Optional[DatasetCache] = None,
        force_download: bool = False,
        timeout: int = 30,
    ) -> tuple:
        """
        Download dataset from GitHub.

        Args:
            org: GitHub organization/user
            repo: Repository name
            path: Path to dataset directory in repository
            version: Version constraint
            cache: Optional cache manager
            force_download: Force re-download
            timeout: Request timeout

        Returns:
            Tuple of (manifest, cache_path, resolved_version)

        Raises:
            requests.RequestException: If download fails
        """
        # Resolve version
        resolved_version = self.resolve_version(org, repo, version, timeout)

        # Create cache key
        cache_key = f"github.com/{org}/{repo}/{path}" if path else f"github.com/{org}/{repo}"

        # Check cache
        if cache and not force_download:
            if cache.is_cached(cache_key, resolved_version):
                cached_manifest = cache.get_cached_manifest(cache_key, resolved_version)
                cache_path = cache.get_cache_path(cache_key, resolved_version)
                if cached_manifest:
                    return cached_manifest, cache_path, resolved_version

        # Download manifest
        manifest_path = f"{path}/dataset.yaml" if path else "dataset.yaml"
        manifest_content = self.get_raw_content(org, repo, manifest_path, resolved_version, timeout)

        # Parse manifest
        import yaml
        manifest_data = yaml.safe_load(manifest_content)
        manifest = DatasetManifest(**manifest_data)

        # If no cache, return manifest only
        if not cache:
            return manifest, None, resolved_version

        # Download and cache bundled files
        cache_path = cache.get_cache_path(cache_key, resolved_version)
        cache_path.mkdir(parents=True, exist_ok=True)

        # Save manifest
        manifest.to_file(cache_path / "dataset.yaml")

        # Download bundled files
        for bundled_file in manifest.files.bundled:
            file_path = f"{path}/{bundled_file.path}" if path else bundled_file.path
            url = f"{self.raw_base}/{org}/{repo}/{resolved_version}/{file_path}"
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()

            file_dest = cache_path / bundled_file.path
            file_dest.parent.mkdir(parents=True, exist_ok=True)

            with open(file_dest, 'wb') as f:
                f.write(response.content)

        # Create cache metadata
        import time
        metadata_path = cache_path / ".cache_metadata"
        with open(metadata_path, 'w') as f:
            f.write(f"cached_at: {time.time()}\n")
            f.write(f"cache_key: {cache_key}\n")
            f.write(f"version: {resolved_version}\n")
            f.write(f"source: github\n")
            f.write(f"org: {org}\n")
            f.write(f"repo: {repo}\n")

        return manifest, cache_path, resolved_version
