"""
AVAGuard Desktop - Exceptions
"""

class SessionRevokedError(Exception):
    """Raised when the session is revoked and operations should abort."""
    pass
