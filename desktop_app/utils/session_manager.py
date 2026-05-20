import threading

class GlobalSessionManager:
    """
    Singleton SessionManager to provide an atomic cancellation token across all threads.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(GlobalSessionManager, cls).__new__(cls)
                cls._instance._revoked_event = threading.Event()
        return cls._instance

    def revoke(self):
        """Signal that the session is revoked. This instantly alerts all listening threads."""
        self._revoked_event.set()

    def is_revoked(self) -> bool:
        """Check if the session has been revoked."""
        return self._revoked_event.is_set()

    def reset(self):
        """Reset the revocation state, e.g., upon successful re-authentication."""
        self._revoked_event.clear()
