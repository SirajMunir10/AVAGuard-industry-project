"""Live Microsoft Graph API client for production auditing."""

import json
import logging
import time
from typing import Dict, List, Optional, Any
import requests
import msal

from avaguard_core.retry import retry

logger = logging.getLogger(__name__)

class GraphAPIClient:
    """
    Production-ready Microsoft Graph API Client.
    
    Supports:
    - Client Credentials flow (automated environments)
    - Device Code flow (desktop app / interactive environments)
    - Exponential backoff for 429 Rate Limiting
    - Automatic token refresh
    - Pagination handling (@odata.nextLink)
    """
    
    # Required scopes for compliance auditing
    DEFAULT_SCOPES = ["https://graph.microsoft.com/.default"]
    
    def __init__(self, tenant_id: str, client_id: str, client_secret: Optional[str] = None, use_device_code: bool = False):
        """Initialize the Graph API client with authentication details."""
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_device_code = use_device_code
        self.authority = f"https://login.microsoftonline.com/{tenant_id}"
        
        # Initialize MSAL application
        if self.use_device_code or not self.client_secret:
            self.app = msal.PublicClientApplication(
                self.client_id, 
                authority=self.authority
            )
        else:
            self.app = msal.ConfidentialClientApplication(
                self.client_id, 
                authority=self.authority,
                client_credential=self.client_secret
            )
            
        self._access_token = None
        self._token_expires_at = 0

    def _get_access_token(self) -> str:
        """Get a valid access token, authenticating if necessary or refreshing if expired."""
        # Simple expiration check
        if self._access_token and time.time() < self._token_expires_at - 300: # 5 minute buffer
            return self._access_token

        result = None
        
        # Try from cache first
        accounts = self.app.get_accounts()
        if accounts:
            result = self.app.acquire_token_silent(self.DEFAULT_SCOPES, account=accounts[0])

        if not result:
            if isinstance(self.app, msal.ConfidentialClientApplication):
                # Client Credentials Flow
                result = self.app.acquire_token_for_client(scopes=self.DEFAULT_SCOPES)
            else:
                # Device Code Flow
                flow = self.app.initiate_device_flow(scopes=self.DEFAULT_SCOPES)
                if "user_code" not in flow:
                    raise Exception(f"Failed to create device flow. Err: {flow.get('error')}")
                
                print(f"\\n\\n=== AUTHENTICATION REQUIRED ===")
                print(flow["message"])
                print("Waiting for authentication in browser...")
                print("===============================\\n\\n")
                
                result = self.app.acquire_token_by_device_flow(flow)

        if "access_token" in result:
            self._access_token = result["access_token"]
            # MSAL uses 'expires_in' (seconds relative to now)
            self._token_expires_at = time.time() + result.get("expires_in", 3599)
            return self._access_token
        else:
            error_msg = f"Failed to authenticate: {result.get('error')} - {result.get('error_description')}"
            logger.error(error_msg)
            raise Exception(error_msg)

    def _execute_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Execute HTTP request. Rate limit retries are handled by @retry on the calling methods."""
        headers = kwargs.pop('headers', {})
        headers['Authorization'] = f'Bearer {self._get_access_token()}'
        headers['Accept'] = 'application/json'
        
        response = requests.request(method, url, headers=headers, **kwargs)
        
        # 401 Unauthorized - Token might be invalid despite expiry check (handle once silently)
        if response.status_code == 401:
            logger.warning("Received 401 Unauthorized, clearing token cache and retrying auth once...")
            self._access_token = None
            self._token_expires_at = 0
            headers['Authorization'] = f'Bearer {self._get_access_token()}'
            response = requests.request(method, url, headers=headers, **kwargs)
            
        response.raise_for_status()
        return response

    def get(self, endpoint: str, use_beta: bool = False, params: Optional[Dict] = None) -> Dict:
        """
        Execute a GET request against the Microsoft Graph API.
        This provides parity with `MockGraphAPIClient.get()`.
        """
        version = "beta" if use_beta else "v1.0"
        # Ensure endpoint doesn't start with / if we join it
        endpoint = endpoint.lstrip('/')
        url = f"https://graph.microsoft.com/{version}/{endpoint}"
        
        response = self._execute_request('GET', url, params=params, timeout=30)
        return response.json()

    def get_all_pages(self, endpoint: str, use_beta: bool = False, params: Optional[Dict] = None) -> List[Dict]:
        """
        Fetch all pages of a paginated Graph API response using @odata.nextLink.
        """
        all_items = []
        current_params = params.copy() if params else {}
        
        # First request
        result = self.get(endpoint, use_beta, params=current_params)
        all_items.extend(result.get('value', []))
        
        # Follow pagination links
        while '@odata.nextLink' in result:
            next_url = result['@odata.nextLink']
            # nextLink is an absolute URL, so we bypass `self.get` and use `_execute_request` directly
            response = self._execute_request('GET', next_url, timeout=30)
            result = response.json()
            all_items.extend(result.get('value', []))
            
        return all_items

    def batch_request(self, requests: List[Dict]) -> Dict:
        """
        Execute a JSON batch request.
        https://learn.microsoft.com/en-us/graph/json-batching
        """
        url = "https://graph.microsoft.com/v1.0/$batch"
        payload = {"requests": requests}
        response = self._execute_request('POST', url, json=payload, timeout=60)
        return response.json()

    @retry(max_retries=3, backoff_base=2.0, max_wait=30.0)
    def get_users(self, select: Optional[List[str]] = None) -> List[Dict]:
        params = {}
        if select:
            params['$select'] = ','.join(select)
        return self.get_all_pages('users', params=params)
        
    @retry(max_retries=3, backoff_base=2.0, max_wait=30.0)
    def get_groups(self) -> List[Dict]:
        return self.get_all_pages('groups')
        
    @retry(max_retries=3, backoff_base=2.0, max_wait=30.0)
    def get_directory_roles(self) -> List[Dict]:
        return self.get_all_pages('directoryRoles')
        
    @retry(max_retries=3, backoff_base=2.0, max_wait=30.0)
    def get_role_members(self, role_id: str) -> List[Dict]:
        return self.get_all_pages(f'directoryRoles/{role_id}/members')
        
    @retry(max_retries=3, backoff_base=2.0, max_wait=30.0)
    def get_domains(self) -> List[Dict]:
        return self.get_all_pages('domains')
        
    @retry(max_retries=3, backoff_base=2.0, max_wait=30.0)
    def get_organization(self) -> Dict:
        # Organization is usually a top-level single item, but endpoints return a collection
        result = self.get_all_pages('organization')
        if result:
            return result[0]
        return {}

    @retry(max_retries=3, backoff_base=2.0, max_wait=30.0)
    def get_conditional_access_policies(self) -> List[Dict]:
        return self.get_all_pages('policies/conditionalAccessPolicies')

    @retry(max_retries=3, backoff_base=2.0, max_wait=30.0)
    def get_authentication_methods_policy(self) -> Dict:
        return self.get('policies/authenticationMethodsPolicy')
        
    @retry(max_retries=3, backoff_base=2.0, max_wait=30.0)
    def get_identity_protection_policy(self, policy_id: str) -> Dict:
        if policy_id == "securityDefaults":
            try:
                return self.get('policies/identitySecurityDefaultsEnforcementPolicy')
            except Exception:
                return {}
        elif policy_id == "signInRiskPolicy":
            try:
                return self.get('identityProtection/riskPolicies/signInRiskPolicy')
            except Exception:
                return {}
        return {}

    @retry(max_retries=3, backoff_base=2.0, max_wait=30.0)
    def get_policies(self) -> Dict:
        """Get authorizationPolicy (matched with the mock client behavior)"""
        try:
            return self.get('policies/authorizationPolicy')
        except Exception:
            return {}

    @retry(max_retries=3, backoff_base=2.0, max_wait=30.0)
    def get_service_principals(self) -> List[Dict]:
        return self.get_all_pages('servicePrincipals')
