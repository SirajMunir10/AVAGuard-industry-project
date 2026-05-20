"""Azure AD authentication using MSAL with enhanced security features."""

import logging
import time
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from msal import ConfidentialClientApplication

logger = logging.getLogger(__name__)


@dataclass
class TokenInfo:
    """Token information with expiry tracking."""
    access_token: str
    expires_at: datetime
    token_type: str = "Bearer"
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired (with 5 minute buffer)."""
        return datetime.now() >= (self.expires_at - timedelta(minutes=5))
    
    @property
    def expires_in_seconds(self) -> int:
        """Get seconds until token expires."""
        delta = self.expires_at - datetime.now()
        return max(0, int(delta.total_seconds()))


class AzureAuthenticator:
    """
    Handles Azure AD authentication using service principal.
    
    Enhanced features:
    - Token expiry tracking and automatic refresh
    - Configurable connection timeout
    - Rate limit awareness
    - Token caching
    """
    
    # Default configuration
    DEFAULT_TIMEOUT = 30  # seconds
    TOKEN_REFRESH_BUFFER = 300  # 5 minutes before expiry
    MAX_RETRIES = 3
    RETRY_DELAY = 1  # seconds
    
    def __init__(
        self, 
        tenant_id: str, 
        client_id: str, 
        client_secret: str,
        timeout: int = DEFAULT_TIMEOUT
    ):
        """
        Initialize authenticator.
        
        Args:
            tenant_id: Azure AD Tenant ID
            client_id: App Registration Client ID
            client_secret: App Registration Client Secret
            timeout: Connection timeout in seconds
        """
        self._validate_credentials(tenant_id, client_id, client_secret)
        
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.authority = f"https://login.microsoftonline.com/{tenant_id}"
        self.scope = ["https://graph.microsoft.com/.default"]
        self.timeout = timeout
        
        self._token_info: Optional[TokenInfo] = None
        self._last_rate_limit: Optional[datetime] = None
        self._rate_limit_retry_after: int = 0
        
        # Create MSAL confidential client
        self.app = ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=self.authority
        )
        
        logger.info(f"AzureAuthenticator initialized for tenant: {tenant_id[:8]}...")
    
    def _validate_credentials(self, tenant_id: str, client_id: str, client_secret: str):
        """Validate credential format before use."""
        if not tenant_id or len(tenant_id) < 32:
            raise AuthenticationError("Invalid tenant_id format")
        if not client_id or len(client_id) < 32:
            raise AuthenticationError("Invalid client_id format")
        if not client_secret or len(client_secret) < 10:
            raise AuthenticationError("Invalid client_secret format")
    
    @property
    def is_authenticated(self) -> bool:
        """Check if we have a valid, non-expired token."""
        return self._token_info is not None and not self._token_info.is_expired
    
    @property
    def token_expires_in(self) -> Optional[int]:
        """Get seconds until token expires, or None if no token."""
        if self._token_info:
            return self._token_info.expires_in_seconds
        return None
    
    def get_token(self, force_refresh: bool = False) -> str:
        """
        Get access token for Microsoft Graph API.
        
        Args:
            force_refresh: Force acquiring a new token even if cached
        
        Returns:
            Access token string
            
        Raises:
            AuthenticationError: If authentication fails
            RateLimitError: If rate limited by Azure AD
        """
        # Check rate limit
        if self._is_rate_limited():
            raise RateLimitError(
                f"Rate limited. Retry after {self._rate_limit_retry_after} seconds"
            )
        
        # Return cached token if valid and not forcing refresh
        if not force_refresh and self._token_info and not self._token_info.is_expired:
            logger.debug("Using cached access token")
            return self._token_info.access_token
        
        # Acquire new token with retry logic
        return self._acquire_token_with_retry()
    
    def _acquire_token_with_retry(self) -> str:
        """Acquire token with retry logic for transient failures."""
        last_error = None
        
        for attempt in range(self.MAX_RETRIES):
            try:
                return self._acquire_token()
            except RateLimitError:
                raise  # Don't retry rate limits
            except AuthenticationError as e:
                last_error = e
                if attempt < self.MAX_RETRIES - 1:
                    delay = self.RETRY_DELAY * (2 ** attempt)  # Exponential backoff
                    logger.warning(f"Auth attempt {attempt + 1} failed, retrying in {delay}s: {e}")
                    time.sleep(delay)
        
        raise last_error or AuthenticationError("Token acquisition failed after retries")
    
    def _acquire_token(self) -> str:
        """Acquire a new token from Azure AD."""
        try:
            # Try silent acquisition first (uses MSAL's internal cache)
            accounts = self.app.get_accounts()
            if accounts:
                result = self.app.acquire_token_silent(self.scope, account=accounts[0])
                if result and "access_token" in result:
                    return self._process_token_result(result)
            
            # Acquire new token
            logger.info("Acquiring new access token from Azure AD")
            result = self.app.acquire_token_for_client(scopes=self.scope)
            
            if "access_token" in result:
                return self._process_token_result(result)
            else:
                error_code = result.get("error", "unknown")
                error_msg = result.get("error_description", "Unknown error")
                
                # Check for rate limiting
                if error_code == "throttled" or "rate" in error_msg.lower():
                    self._handle_rate_limit(result)
                    raise RateLimitError(f"Rate limited: {error_msg}")
                
                raise AuthenticationError(f"Failed to acquire token: {error_msg}")
                
        except RateLimitError:
            raise
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            raise AuthenticationError(f"Authentication failed: {str(e)}")
    
    def _process_token_result(self, result: Dict[str, Any]) -> str:
        """Process token result and cache token info."""
        access_token = result["access_token"]
        expires_in = result.get("expires_in", 3600)  # Default 1 hour
        
        self._token_info = TokenInfo(
            access_token=access_token,
            expires_at=datetime.now() + timedelta(seconds=expires_in),
            token_type=result.get("token_type", "Bearer")
        )
        
        logger.info(f"Token acquired, expires in {expires_in}s")
        return access_token
    
    def _is_rate_limited(self) -> bool:
        """Check if we're currently rate limited."""
        if self._last_rate_limit is None:
            return False
        
        elapsed = (datetime.now() - self._last_rate_limit).total_seconds()
        return elapsed < self._rate_limit_retry_after
    
    def _handle_rate_limit(self, result: Dict[str, Any]):
        """Handle rate limit response from Azure AD."""
        self._last_rate_limit = datetime.now()
        # Try to get retry-after from response, default to 60 seconds
        self._rate_limit_retry_after = int(result.get("retry_after", 60))
        logger.warning(f"Rate limited, retry after {self._rate_limit_retry_after}s")
    
    def refresh_token(self) -> str:
        """
        Force refresh the access token.
        
        Returns:
            New access token string
        """
        return self.get_token(force_refresh=True)
    
    def validate_connection(self) -> bool:
        """
        Validate connection to Azure AD by making a test API call.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            token = self.get_token()
            return bool(token)
        except (AuthenticationError, RateLimitError) as e:
            logger.error(f"Connection validation failed: {e}")
            return False
    
    def get_token_info(self) -> Optional[Dict[str, Any]]:
        """
        Get current token information (without exposing the actual token).
        
        Returns:
            Dictionary with token metadata or None
        """
        if not self._token_info:
            return None
        
        return {
            "expires_in_seconds": self._token_info.expires_in_seconds,
            "is_expired": self._token_info.is_expired,
            "token_type": self._token_info.token_type,
            "expires_at": self._token_info.expires_at.isoformat()
        }
    
    def clear_cache(self):
        """Clear cached token and rate limit state."""
        self._token_info = None
        self._last_rate_limit = None
        self._rate_limit_retry_after = 0
        logger.info("Token cache cleared")


class AuthenticationError(Exception):
    """Custom exception for authentication failures."""
    pass


class RateLimitError(Exception):
    """Custom exception for rate limiting."""
    pass
