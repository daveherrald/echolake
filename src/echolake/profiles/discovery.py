"""Profile and destination discovery utilities."""

from pathlib import Path
from typing import List, Dict, Optional
from .models import EchoProfile, Destination


def find_profiles(search_paths: Optional[List[Path]] = None) -> List[Dict]:
    """
    Find all echo profiles in search paths.

    Args:
        search_paths: List of paths to search (defaults to standard locations)

    Returns:
        List of profile metadata dictionaries
    """
    if search_paths is None:
        search_paths = _get_default_profile_paths()

    profiles = []

    for search_path in search_paths:
        if not search_path.exists():
            continue

        # Find all .yaml files
        for yaml_file in search_path.glob("**/*.yaml"):
            try:
                # Skip if it looks like a destination
                if "destination" in yaml_file.parts:
                    continue

                # Try to load as profile
                profile = EchoProfile.from_file(yaml_file)

                profiles.append({
                    "name": profile.profile.name,
                    "version": profile.profile.version,
                    "description": profile.profile.description,
                    "author": profile.profile.author,
                    "tags": profile.profile.tags,
                    "path": str(yaml_file),
                    "datasets_count": len(profile.datasets),
                })

            except Exception:
                # Not a valid profile, skip
                continue

    return profiles


def find_destinations(search_paths: Optional[List[Path]] = None) -> List[Dict]:
    """
    Find all destinations in search paths.

    Args:
        search_paths: List of paths to search (defaults to standard locations)

    Returns:
        List of destination metadata dictionaries
    """
    if search_paths is None:
        search_paths = _get_default_destination_paths()

    destinations = []

    for search_path in search_paths:
        if not search_path.exists():
            continue

        # Find all .yaml files
        for yaml_file in search_path.glob("**/*.yaml"):
            try:
                # Try to load as destination
                dest = Destination.from_file(yaml_file)

                destinations.append({
                    "name": dest.destination.name,
                    "description": dest.destination.description,
                    "type": dest.type,
                    "tags": dest.destination.tags,
                    "path": str(yaml_file),
                })

            except Exception:
                # Not a valid destination, skip
                continue

    return destinations


def load_profile(name_or_path: str, search_paths: Optional[List[Path]] = None) -> EchoProfile:
    """
    Load an echo profile by name or path.

    Args:
        name_or_path: Profile name or file path
        search_paths: List of paths to search (defaults to standard locations)

    Returns:
        EchoProfile instance

    Raises:
        FileNotFoundError: If profile not found
    """
    # If it's a path, load directly
    path = Path(name_or_path)
    if path.exists():
        return EchoProfile.from_file(path)

    # If it ends with .yaml, try adding it to search paths
    if name_or_path.endswith(".yaml"):
        for search_path in search_paths or _get_default_profile_paths():
            profile_path = search_path / name_or_path
            if profile_path.exists():
                return EchoProfile.from_file(profile_path)

    # Otherwise, search by name
    if search_paths is None:
        search_paths = _get_default_profile_paths()

    for search_path in search_paths:
        if not search_path.exists():
            continue

        # Try exact match: name.yaml
        profile_path = search_path / f"{name_or_path}.yaml"
        if profile_path.exists():
            try:
                return EchoProfile.from_file(profile_path)
            except Exception:
                pass

        # Try searching in subdirectories
        for yaml_file in search_path.glob(f"**/{name_or_path}.yaml"):
            try:
                return EchoProfile.from_file(yaml_file)
            except Exception:
                continue

    raise FileNotFoundError(f"Profile not found: {name_or_path}")


def load_destination(name_or_path: str, search_paths: Optional[List[Path]] = None) -> Destination:
    """
    Load a destination by name or path.

    Args:
        name_or_path: Destination name or file path
        search_paths: List of paths to search (defaults to standard locations)

    Returns:
        Destination instance

    Raises:
        FileNotFoundError: If destination not found
    """
    # If it's a path, load directly
    path = Path(name_or_path)
    if path.exists():
        return Destination.from_file(path)

    # If it ends with .yaml, try adding it to search paths
    if name_or_path.endswith(".yaml"):
        for search_path in search_paths or _get_default_destination_paths():
            dest_path = search_path / name_or_path
            if dest_path.exists():
                return Destination.from_file(dest_path)

    # Otherwise, search by name
    if search_paths is None:
        search_paths = _get_default_destination_paths()

    for search_path in search_paths:
        if not search_path.exists():
            continue

        # Try exact match: name.yaml
        dest_path = search_path / f"{name_or_path}.yaml"
        if dest_path.exists():
            try:
                return Destination.from_file(dest_path)
            except Exception:
                pass

        # Try searching in subdirectories
        for yaml_file in search_path.glob(f"**/{name_or_path}.yaml"):
            try:
                return Destination.from_file(yaml_file)
            except Exception:
                continue

    raise FileNotFoundError(f"Destination not found: {name_or_path}")


def _get_default_profile_paths() -> List[Path]:
    """
    Get default search paths for profiles.

    Returns:
        List of paths to search
    """
    paths = []

    # Current directory profiles/
    current_profiles = Path.cwd() / "profiles"
    if current_profiles.exists():
        paths.append(current_profiles)

    # Current directory examples/profiles/
    examples_profiles = Path.cwd() / "examples" / "profiles"
    if examples_profiles.exists():
        paths.append(examples_profiles)

    # Home directory ~/.echolake/profiles/
    home_profiles = Path.home() / ".echolake" / "profiles"
    if home_profiles.exists():
        paths.append(home_profiles)

    return paths


def _get_default_destination_paths() -> List[Path]:
    """
    Get default search paths for destinations.

    Returns:
        List of paths to search
    """
    paths = []

    # Current directory destinations/
    current_dests = Path.cwd() / "destinations"
    if current_dests.exists():
        paths.append(current_dests)

    # Current directory examples/destinations/
    examples_dests = Path.cwd() / "examples" / "destinations"
    if examples_dests.exists():
        paths.append(examples_dests)

    # Home directory ~/.echolake/destinations/
    home_dests = Path.home() / ".echolake" / "destinations"
    if home_dests.exists():
        paths.append(home_dests)

    return paths
