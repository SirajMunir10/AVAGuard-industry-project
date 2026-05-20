"""AVAGuard Core - Shared compliance checking library."""

import os as _os

def _read_version():
    current = _os.path.dirname(_os.path.abspath(__file__))
    for _ in range(4):
        vpath = _os.path.join(current, 'VERSION')
        if _os.path.exists(vpath):
            with open(vpath) as f:
                return f.read().strip()
        current = _os.path.dirname(current)
    return "0.1.0"  # fallback only

__version__ = _read_version()

from avaguard_core.graph_api_client import GraphAPIClient
from avaguard_core.auth import AzureAuthenticator
from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus, CISSeverity
from avaguard_core.checks.protocol import CheckProtocol
from avaguard_core.retry import retry

# --- FIX IS HERE: Import 'EnhancedReporter', not 'Reporter' ---
try:
    from avaguard_core.reporter import EnhancedReporter
except ImportError:
    # Fallback or alias if needed
    EnhancedReporter = None

# If legacy code expects 'Reporter', we map it to 'EnhancedReporter'
Reporter = EnhancedReporter

from avaguard_core.logging_config import configure_logging

__all__ = [
    'GraphAPIClient',
    'AzureAuthenticator',
    'BaseCheck',
    'CheckResult',
    'CheckStatus',
    'CISSeverity',
    'EnhancedReporter',
    'Reporter',  # Exporting both names fixes compatibility
    'retry',
    'CheckProtocol',
    'configure_logging'
]