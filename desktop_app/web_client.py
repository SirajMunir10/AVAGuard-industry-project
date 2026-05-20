"""
AVAGuard Desktop - Web Portal API Client

This module handles communication between the desktop application and the web portal.
It provides authentication, scan upload, and sync functionality.
"""

import json
import logging
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from utils.session_manager import GlobalSessionManager

logger = logging.getLogger(__name__)


@dataclass
class AuthToken:
    """Represents an authentication token with expiry tracking."""
    access_token: str
    refresh_token: str
    expires_at: datetime
    user_email: str
    user_role: str
    organization_id: str
    
    @property
    def is_expired(self) -> bool:
        """Check if the access token is expired (with 5 min buffer)."""
        return datetime.now() >= (self.expires_at - timedelta(minutes=5))
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage."""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at.isoformat(),
            "user_email": self.user_email,
            "user_role": self.user_role,
            "organization_id": self.organization_id,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "AuthToken":
        """Create from dictionary."""
        return cls(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_at=datetime.fromisoformat(data["expires_at"]),
            user_email=data["user_email"],
            user_role=data["user_role"],
            organization_id=data["organization_id"],
        )


class SessionRevokedException(Exception):
    pass

class WebPortalClient:
    """
    Client for communicating with AVAGuard Web Portal API.
    
    Usage:
        client = WebPortalClient("http://localhost:8000")
        
        # Login
        if client.login("user@example.com", "password"):
            print(f"Logged in as {client.current_user['email']}")
            
            # Upload scan
            client.upload_scan(scan_id, score, passed, failed, total, results)
            
        # Logout
        client.logout()
    """
    
    def __init__(self, base_url: str, timeout: int = 30):
        """
        Initialize the web portal client.
        
        Args:
            base_url: Base URL of the web portal (e.g., "http://localhost:8000")
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self._token: Optional[AuthToken] = None
        self._current_user: Optional[Dict] = None
        
        # Setup session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )
        self.session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
        self.session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
    
    @property
    def is_authenticated(self) -> bool:
        """Check if client is authenticated with a valid token."""
        return self._token is not None and not self._token.is_expired
    
    @property
    def current_user(self) -> Optional[Dict]:
        """Get current authenticated user info."""
        return self._current_user
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token.access_token}"
        return headers
    
    def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict] = None,
        require_auth: bool = True
    ) -> Tuple[bool, Any]:
        """
        Make an API request.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (e.g., "/api/auth/login/")
            data: Request body data
            require_auth: Whether authentication is required
            
        Returns:
            Tuple of (success: bool, data_or_error: Any)
        """
        if require_auth and not self.is_authenticated:
            msg = "Not authenticated. Please login first."
            logger.error(msg)
            return False, msg
        
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=self._get_headers(),
                json=data,
                timeout=self.timeout,
            )
            
            # --- Revocation detection: 401 path ---
            if response.status_code == 401 and require_auth:
                # Try to refresh token
                if self._refresh_token():
                    # Retry the request with new token
                    response = self.session.request(
                        method=method,
                        url=url,
                        headers=self._get_headers(),
                        json=data,
                        timeout=self.timeout,
                    )
                else:
                    msg = "Session has been revoked by an administrator."
                    logger.error(msg)
                    self._token = None
                    self._current_user = None
                    # NOTE: Do NOT call GlobalSessionManager().revoke() here.
                    # The heartbeat is the sole authority for global revocation.
                    # Callers decide whether this 401 warrants app-wide shutdown.
                    raise SessionRevokedException(msg)

            # --- Revocation detection: 403 path ---
            if response.status_code == 403 and require_auth:
                try:
                    body = response.json()
                    detail = str(body.get('detail', ''))
                except Exception:
                    detail = response.text
                if 'revoked' in detail.lower():
                    msg = f"Session has been revoked (403): {detail}"
                    logger.error(msg)
                    # Raise so the caller can decide: is this a global session revocation
                    # (heartbeat will confirm) or just a stale-data rejection on one endpoint?
                    raise SessionRevokedException(msg)

            response.raise_for_status()
            return True, response.json() if response.content else {}
            
        except SessionRevokedException:
            # Re-raise so callers (SyncWorker) can handle properly
            raise
        except requests.exceptions.ConnectionError:
            msg = f"Connection error: Cannot reach {self.base_url}"
            logger.error(msg)
            return False, msg
        except requests.exceptions.Timeout:
            msg = f"Request timeout after {self.timeout}s"
            logger.error(msg)
            return False, msg
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            try:
                error_detail = e.response.json()
                msg = f"HTTP error {status_code}: {error_detail}"
            except Exception:
                resp_text = e.response.text
                if status_code >= 500:
                    msg = f"Server error ({status_code}). Please contact administrator."
                elif len(resp_text) > 200:
                    msg = f"HTTP error {status_code}: {resp_text[:200]}..."
                else:
                    msg = f"HTTP error {status_code}: {resp_text}"
            logger.error(msg)
            return False, msg
        except Exception as e:
            msg = f"Request error: {e}"
            logger.error(msg)
            return False, msg
    
    def login(self, email: str, password: str) -> bool:
        """
        Authenticate with the web portal.
        
        Args:
            email: User email
            password: User password
            
        Returns:
            True if login successful, False otherwise
        """
        logger.info(f"Attempting login for {email}...")
        
        success, response = self._make_request(
            "POST",
            "/api/auth/login/",
            data={"email": email, "password": password},
            require_auth=False,
        )
        
        if not success:
            logger.error(f"Login failed: {response}")
            return False
        
        try:
            self._token = AuthToken(
                access_token=response["access"],
                refresh_token=response["refresh"],
                expires_at=datetime.now() + timedelta(hours=1),  # JWT default
                user_email=response["user"]["email"],
                user_role=response["user"]["role"],
                organization_id=response["user"]["organization"],
            )
            self._current_user = response["user"]
            logger.info(f"Login successful: {self._token.user_email}")
            return True
            
        except KeyError as e:
            logger.error(f"Invalid login response: missing {e}")
            return False
    
    def _refresh_token(self) -> bool:
        """Refresh the access token using the refresh token."""
        if not self._token:
            return False
        
        logger.info("Refreshing access token...")
        
        success, response = self._make_request(
            "POST",
            "/api/auth/refresh/",
            data={"refresh": self._token.refresh_token},
            require_auth=False,
        )
        
        if success and response and "access" in response:
            self._token = AuthToken(
                access_token=response["access"],
                refresh_token=response.get("refresh", self._token.refresh_token),
                expires_at=datetime.now() + timedelta(hours=1),
                user_email=self._token.user_email,
                user_role=self._token.user_role,
                organization_id=self._token.organization_id,
            )
            logger.info("Token refreshed successfully")
            return True
        
        return False
    
    def logout(self):
        """Clear authentication state."""
        self._token = None
        self._current_user = None
        logger.info("Logged out")
    
    def upload_scan(
        self,
        scan_id: str,
        overall_score: float,
        passed_count: int,
        failed_count: int,
        total_checks: int,
        results: Optional[List[Dict]] = None,
    ) -> Tuple[bool, str]:
        """
        Upload scan results to the web portal.
        
        Args:
            scan_id: UUID of the scan
            overall_score: Compliance score (0-100)
            passed_count: Number of passed checks
            failed_count: Number of failed checks
            total_checks: Total number of checks
            results: Optional list of detailed check results
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        logger.info(f"Uploading scan {scan_id}...")
        
        data = {
            "scan_id": scan_id,
            "overall_score": round(overall_score, 1),
            "passed_count": passed_count,
            "failed_count": failed_count,
            "total_checks": total_checks,
        }
        
        if results:
            data["results"] = results
        
        success, response = self._make_request("POST", "/api/scans/upload/", data=data)
        
        if success:
            logger.info(f"Scan uploaded successfully: {scan_id}")
            return True, "Upload successful"
        else:
            return False, str(response)
    
    def validate_session(self) -> bool:
        """
        Validate that the current session is still active on the server.
        Uses /api/scans/ as a lightweight auth-check proxy.
        Returns True if valid/unknown, False only on explicit 401 auth failure.
        Raises SessionRevokedException if server explicitly returns revoked.
        """
        if not self.is_authenticated:
            return False
        try:
            # Use scan list as a lightweight auth probe — always exists, requires auth
            success, _ = self._make_request("GET", "/api/scans/", require_auth=True)
            return success
        except SessionRevokedException:
            raise
        except Exception:
            # Network errors → optimistically allow (heartbeat catches within 10s)
            return True

    def get_scan_history(self) -> Optional[List[Dict]]:
        """Get scan history for the current organization."""
        return self._make_request("GET", "/api/scans/")
        
    def get_active_policies(self) -> Tuple[bool, Any]:
        """Get active policies for the current organization."""
        return self._make_request("GET", "/api/policies/active/")
    
    def get_dashboard_stats(self) -> Tuple[bool, Any]:
        """Get dashboard statistics for the current organization."""
        return self._make_request("GET", "/api/dashboard/stats/")
    
    def test_connection(self) -> bool:
        """
        Test connection to the web portal.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            response = self.session.get(
                f"{self.base_url}/api/health/",
                timeout=5,
            )
            return response.status_code in [200, 401, 403, 404]  # Server is responding
        except Exception:
            return False


# Convenience function for quick testing
def test_web_client():
    """Test the web client with example usage."""
    client = WebPortalClient("http://localhost:8000")
    
    if client.test_connection():
        print("✓ Connection to web portal successful")
    else:
        print("✗ Cannot connect to web portal")
        return
    
    # Example login (will fail without real credentials)
    if client.login("admin@example.com", "password"):
        print(f"✓ Logged in as {client.current_user['email']}")
        
        # Get dashboard stats
        stats = client.get_dashboard_stats()
        if stats:
            print(f"✓ Dashboard stats: {stats}")
    else:
        print("✗ Login failed")


if __name__ == "__main__":
    test_web_client()
