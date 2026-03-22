"""
EchoLake - Security Data Echo Tool

A Python tool for echoing security logs and events into SIEMs and security data
lakes. Intelligently manipulates timestamps while preserving event deltas.
"""

__version__ = "0.1.0"

# Core API
from .core.config import Config, EchoConfig, EchoStats
from .core.echo import EchoEngine
from .databricks import Replay
from .models.event import Event

# Backward compatibility aliases
ReplayConfig = EchoConfig
ReplayStats = EchoStats
ReplayEngine = EchoEngine

# Expose main components for programmatic use
__all__ = [
    '__version__',
    'Config',
    'EchoConfig',
    'EchoStats',
    'EchoEngine',
    'Replay',
    'Event',
    # Backward compat
    'ReplayConfig',
    'ReplayStats',
    'ReplayEngine',
]
