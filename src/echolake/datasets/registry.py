"""Repository and registry management for datasets."""

from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml

from .utils import get_config_dir
from .resolver import DatasetResolver
from .github import GitHubClient
from .cache import DatasetCache


class Repository:
    """Represents a dataset repository."""

    def __init__(
        self,
        name: str,
        url: str,
        description: Optional[str] = None,
        enabled: bool = True,
    ):
        """
        Initialize repository.

        Args:
            name: Repository name
            url: Repository URL (github:org/repo, https://url, etc.)
            description: Optional description
            enabled: Whether repository is enabled
        """
        self.name = name
        self.url = url
        self.description = description
        self.enabled = enabled

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "url": self.url,
            "description": self.description,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Repository':
        """Create from dictionary."""
        return cls(
            name=data["name"],
            url=data["url"],
            description=data.get("description"),
            enabled=data.get("enabled", True),
        )


class DatasetRegistry:
    """Manages dataset repositories and discovery."""

    def __init__(
        self,
        config_file: Optional[Path] = None,
        resolver: Optional[DatasetResolver] = None,
        github_client: Optional[GitHubClient] = None,
    ):
        """
        Initialize registry.

        Args:
            config_file: Optional path to repositories.yaml
            resolver: Optional dataset resolver
            github_client: Optional GitHub client
        """
        self.config_file = config_file or (get_config_dir() / "repositories.yaml")
        self.resolver = resolver or DatasetResolver()
        self.github = github_client or GitHubClient()
        self.repositories: List[Repository] = []
        self._load_repositories()

    def _load_repositories(self) -> None:
        """Load repositories from config file."""
        if not self.config_file.exists():
            # No repositories configured
            return

        try:
            with open(self.config_file, 'r') as f:
                data = yaml.safe_load(f)

            if not data or "repositories" not in data:
                return

            for repo_data in data["repositories"]:
                repo = Repository.from_dict(repo_data)
                self.repositories.append(repo)
        except Exception as e:
            # Log error but don't fail
            print(f"Warning: Failed to load repositories config: {e}")

    def save_repositories(self) -> None:
        """Save repositories to config file."""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "repositories": [repo.to_dict() for repo in self.repositories]
        }

        with open(self.config_file, 'w') as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)

    def add_repository(
        self,
        name: str,
        url: str,
        description: Optional[str] = None,
        enabled: bool = True,
    ) -> None:
        """
        Add a repository.

        Args:
            name: Repository name
            url: Repository URL
            description: Optional description
            enabled: Whether repository is enabled
        """
        repo = Repository(name=name, url=url, description=description, enabled=enabled)
        self.repositories.append(repo)
        self.save_repositories()

    def remove_repository(self, name: str) -> bool:
        """
        Remove a repository by name.

        Args:
            name: Repository name

        Returns:
            True if removed, False if not found
        """
        for i, repo in enumerate(self.repositories):
            if repo.name == name:
                self.repositories.pop(i)
                self.save_repositories()
                return True
        return False

    def get_catalog(self, repository: Repository, timeout: int = 30) -> Optional[Dict[str, Any]]:
        """
        Get catalog from a repository.

        Args:
            repository: Repository to get catalog from
            timeout: Request timeout

        Returns:
            Catalog dictionary or None if not found
        """
        try:
            # Parse repository URL
            if repository.url.startswith("github:"):
                # GitHub repository
                ref = repository.url[7:]  # Remove "github:" prefix
                org, repo_name, path, version = self.github.parse_github_ref(ref)

                # Resolve version
                resolved_version = self.github.resolve_version(org, repo_name, version, timeout)

                # Get catalog.yaml
                catalog_path = f"{path}/catalog.yaml" if path else "catalog.yaml"
                catalog_content = self.github.get_raw_content(
                    org, repo_name, catalog_path, resolved_version, timeout
                )

                return yaml.safe_load(catalog_content)
            else:
                # HTTP/HTTPS URL
                import requests
                catalog_url = f"{repository.url.rstrip('/')}/catalog.yaml"
                response = requests.get(catalog_url, timeout=timeout)
                response.raise_for_status()
                return yaml.safe_load(response.text)
        except Exception:
            # Catalog not available
            return None

    def list_datasets(
        self,
        repository_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        mitre_technique: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        List available datasets from repositories.

        Args:
            repository_name: Optional filter by repository name
            tags: Optional filter by tags
            mitre_technique: Optional filter by MITRE technique ID

        Returns:
            List of dataset information dictionaries
        """
        results = []

        # Filter repositories
        repos_to_search = self.repositories
        if repository_name:
            repos_to_search = [r for r in repos_to_search if r.name == repository_name]

        # Search each repository
        for repo in repos_to_search:
            if not repo.enabled:
                continue

            # Get catalog
            catalog = self.get_catalog(repo)
            if not catalog or "datasets" not in catalog:
                continue

            # Process each dataset in catalog
            for dataset_entry in catalog["datasets"]:
                # Build full reference
                if repo.url.startswith("github:"):
                    base_ref = repo.url[7:]
                    dataset_ref = f"github:{base_ref}/{dataset_entry['path']}"
                else:
                    dataset_ref = f"{repo.url}/{dataset_entry['path']}"

                # Build result
                result = {
                    "name": dataset_entry.get("name", dataset_entry["path"]),
                    "version": dataset_entry.get("version", "unknown"),
                    "description": dataset_entry.get("description", ""),
                    "path": dataset_entry["path"],
                    "repository": repo.name,
                    "reference": dataset_ref,
                }

                # Add optional fields if present
                if "tags" in dataset_entry:
                    result["tags"] = dataset_entry["tags"]
                if "mitre_attack" in dataset_entry:
                    result["mitre_attack"] = dataset_entry["mitre_attack"]

                # Apply filters
                if tags:
                    dataset_tags = dataset_entry.get("tags", [])
                    if not any(tag in dataset_tags for tag in tags):
                        continue

                if mitre_technique:
                    techniques = dataset_entry.get("mitre_attack", {}).get("techniques", [])
                    technique_ids = [t.get("id") if isinstance(t, dict) else t for t in techniques]
                    if mitre_technique not in technique_ids:
                        continue

                results.append(result)

        return results

    def search_datasets(
        self,
        query: str,
        search_in: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search for datasets by query.

        Args:
            query: Search query string
            search_in: Optional list of fields to search in
                      (name, description, tags, mitre_attack)

        Returns:
            List of matching dataset information dictionaries
        """
        if search_in is None:
            search_in = ["name", "description", "tags", "mitre_attack"]

        # Get all datasets
        all_datasets = self.list_datasets()

        # Filter by query
        results = []
        query_lower = query.lower()

        for dataset in all_datasets:
            match = False

            if "name" in search_in:
                if query_lower in dataset.get("name", "").lower():
                    match = True

            if "description" in search_in:
                if query_lower in dataset.get("description", "").lower():
                    match = True

            if "tags" in search_in and "tags" in dataset:
                if any(query_lower in tag.lower() for tag in dataset["tags"]):
                    match = True

            if "mitre_attack" in search_in and "mitre_attack" in dataset:
                mitre_data = dataset["mitre_attack"]

                # Search in techniques
                if "techniques" in mitre_data:
                    for tech in mitre_data["techniques"]:
                        if isinstance(tech, dict):
                            tech_id = tech.get("id", "")
                            tech_name = tech.get("name", "")
                        else:
                            tech_id = tech
                            tech_name = ""

                        if query_lower in tech_id.lower() or query_lower in tech_name.lower():
                            match = True
                            break

                # Search in tactics
                if "tactics" in mitre_data:
                    if any(query_lower in tactic.lower() for tactic in mitre_data["tactics"]):
                        match = True

            if match:
                results.append(dataset)

        return results
