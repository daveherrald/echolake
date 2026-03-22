"""Echo profiles and destination management."""

from .models import (
    EchoProfile,
    EchoProfileMetadata,
    EchoConfig,
    DatasetReference,
    Destination,
    DestinationMetadata,
    DestinationConnection,
    CredentialsConfig,
)
from .discovery import (
    find_profiles,
    find_destinations,
    load_profile,
    load_destination,
)
from .executor import (
    ProfileExecutor,
    load_credentials_file,
)

# Backward compatibility aliases
ReplayProfile = EchoProfile
ReplayProfileMetadata = EchoProfileMetadata
ReplayConfig = EchoConfig

__all__ = [
    "EchoProfile",
    "EchoProfileMetadata",
    "EchoConfig",
    "DatasetReference",
    "Destination",
    "DestinationMetadata",
    "DestinationConnection",
    "CredentialsConfig",
    "find_profiles",
    "find_destinations",
    "load_profile",
    "load_destination",
    "ProfileExecutor",
    "load_credentials_file",
    # Backward compat
    "ReplayProfile",
    "ReplayProfileMetadata",
    "ReplayConfig",
]
