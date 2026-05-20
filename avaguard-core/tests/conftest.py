"""
AVAGuard Core - Test Configuration

Provides fixtures and mock data for testing.
"""

import pytest
from typing import Dict, List, Any
from unittest.mock import MagicMock
from datetime import datetime, timedelta


class MockGraphClient:
    """Mock Microsoft Graph API client for testing."""
    
    is_mock_client = True
    
    def __init__(self, mock_data: Dict[str, Any] = None):
        self.mock_data = mock_data or self._default_mock_data()
        self._call_log: List[Dict] = []
    
    def _default_mock_data(self) -> Dict[str, Any]:
        """Generate default mock data for testing."""
        return {
            "users": [
                {
                    "id": "user-1",
                    "userPrincipalName": "admin@test.com",
                    "displayName": "Test Admin",
                    "accountEnabled": True,
                    "userType": "Member",
                    "jobTitle": "IT Administrator",
                    "department": "IT",
                    "isPrivileged": True,
                    "isMfaRegistered": True,
                    "authenticationMethods": [
                        {"type": "microsoftAuthenticator"},
                        {"type": "phoneAuthenticationMethod"}
                    ],
                    "createdDateTime": (datetime.now() - timedelta(days=365)).isoformat()
                },
                {
                    "id": "user-2",
                    "userPrincipalName": "security@test.com",
                    "displayName": "Security Officer",
                    "accountEnabled": True,
                    "userType": "Member",
                    "jobTitle": "Security Administrator",
                    "department": "Security",
                    "isPrivileged": True,
                    "isMfaRegistered": False,
                    "authenticationMethods": [],
                    "createdDateTime": (datetime.now() - timedelta(days=180)).isoformat()
                },
                {
                    "id": "user-3",
                    "userPrincipalName": "regular@test.com",
                    "displayName": "Regular User",
                    "accountEnabled": True,
                    "userType": "Member",
                    "jobTitle": "Developer",
                    "department": "Engineering",
                    "isPrivileged": False,
                    "isMfaRegistered": True,
                    "authenticationMethods": [
                        {"type": "phoneAuthenticationMethod"}
                    ],
                    "createdDateTime": (datetime.now() - timedelta(days=90)).isoformat()
                },
                {
                    "id": "user-4",
                    "userPrincipalName": "disabled@test.com",
                    "displayName": "Disabled Admin",
                    "accountEnabled": False,
                    "userType": "Member",
                    "jobTitle": "Former Admin",
                    "department": "IT",
                    "isPrivileged": True,
                    "isMfaRegistered": False,
                    "authenticationMethods": [],
                    "createdDateTime": (datetime.now() - timedelta(days=500)).isoformat()
                },
                {
                    "id": "user-5",
                    "userPrincipalName": "guest@external.com",
                    "displayName": "Guest User",
                    "accountEnabled": True,
                    "userType": "Guest",
                    "jobTitle": "",
                    "department": "",
                    "isPrivileged": False,
                    "isMfaRegistered": False,
                    "authenticationMethods": [],
                    "createdDateTime": (datetime.now() - timedelta(days=30)).isoformat()
                }
            ],
            "groups": [
                {
                    "id": "group-1",
                    "displayName": "Domain Admins",
                    "groupTypes": ["Unified"],
                    "memberCount": 5
                },
                {
                    "id": "group-2",
                    "displayName": "Security Group",
                    "groupTypes": [],
                    "memberCount": 10
                }
            ],
            "domains": [
                {
                    "id": "test.com",
                    "isDefault": True,
                    "isVerified": True,
                    "authenticationType": "Managed"
                },
                {
                    "id": "legacy.com",
                    "isDefault": False,
                    "isVerified": True,
                    "authenticationType": "Federated"
                }
            ],
            "conditionalAccessPolicies": [
                {
                    "id": "policy-1",
                    "displayName": "Require MFA for Admins",
                    "state": "enabled",
                    "conditions": {
                        "users": {
                            "includeRoles": ["Global Administrator"]
                        }
                    },
                    "grantControls": {
                        "builtInControls": ["mfa"]
                    }
                }
            ],
            "securityDefaults": {
                "isEnabled": False
            },
            "directoryRoles": [
                {
                    "id": "role-1",
                    "displayName": "Global Administrator",
                    "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10"
                }
            ]
        }
    
    def get_users(self, select: str = None) -> List[Dict]:
        """Get mock users."""
        self._log_call("get_users", {"select": select})
        return self.mock_data.get("users", [])
    
    def get_groups(self) -> List[Dict]:
        """Get mock groups."""
        self._log_call("get_groups", {})
        return self.mock_data.get("groups", [])
    
    def get_domains(self) -> List[Dict]:
        """Get mock domains."""
        self._log_call("get_domains", {})
        return self.mock_data.get("domains", [])
    
    def get_directory_roles(self) -> List[Dict]:
        """Get mock directory roles."""
        self._log_call("get_directory_roles", {})
        return self.mock_data.get("directoryRoles", [])
    
    def get_role_members(self, role_id: str) -> List[Dict]:
        """Get mock role members."""
        self._log_call("get_role_members", {"role_id": role_id})
        # Return privileged users as role members
        return [u for u in self.mock_data.get("users", []) if u.get("isPrivileged")]
    
    def get_conditional_access_policies(self) -> List[Dict]:
        """Get mock conditional access policies."""
        self._log_call("get_conditional_access_policies", {})
        return self.mock_data.get("conditionalAccessPolicies", [])
    
    def get_identity_protection_policy(self, policy_id: str) -> Dict:
        """Get mock identity protection policy."""
        self._log_call("get_identity_protection_policy", {"policy_id": policy_id})
        if policy_id == "securityDefaults":
            return self.mock_data.get("securityDefaults", {})
        return {}
    
    def get(self, endpoint: str, use_beta: bool = False, params: Dict = None) -> Dict:
        """Generic GET request handler."""
        self._log_call("get", {"endpoint": endpoint, "use_beta": use_beta, "params": params})
        
        # Handle various endpoints
        if "/users" in endpoint:
            return {"value": self.mock_data.get("users", [])}
        elif "/groups" in endpoint:
            return {"value": self.mock_data.get("groups", [])}
        elif "/securityDefaults" in endpoint:
            return self.mock_data.get("securityDefaults", {})
        
        return {}
    
    def get_all_pages(self, endpoint: str) -> List[Dict]:
        """Get all pages of a paginated response."""
        self._log_call("get_all_pages", {"endpoint": endpoint})
        
        if "/users" in endpoint:
            return self.mock_data.get("users", [])
        elif "/domains" in endpoint:
            return self.mock_data.get("domains", [])
        elif "/conditionalAccess" in endpoint:
            return self.mock_data.get("conditionalAccessPolicies", [])
        
        return []
    
    def _log_call(self, method: str, args: Dict):
        """Log API call for verification."""
        self._call_log.append({
            "method": method,
            "args": args,
            "timestamp": datetime.now().isoformat()
        })
    
    def get_call_log(self) -> List[Dict]:
        """Get the call log for verification."""
        return self._call_log
    
    def clear_call_log(self):
        """Clear the call log."""
        self._call_log = []


@pytest.fixture
def mock_graph_client():
    """Provide a mock graph client for testing."""
    return MockGraphClient()


@pytest.fixture
def mock_graph_client_no_mfa():
    """Provide a mock client where no users have MFA."""
    data = MockGraphClient()._default_mock_data()
    for user in data["users"]:
        user["isMfaRegistered"] = False
        user["authenticationMethods"] = []
    return MockGraphClient(data)


@pytest.fixture
def mock_graph_client_all_mfa():
    """Provide a mock client where all users have MFA."""
    data = MockGraphClient()._default_mock_data()
    for user in data["users"]:
        user["isMfaRegistered"] = True
        user["authenticationMethods"] = [{"type": "microsoftAuthenticator"}]
    return MockGraphClient(data)


@pytest.fixture
def mock_graph_client_security_defaults_enabled():
    """Provide a mock client with security defaults enabled."""
    data = MockGraphClient()._default_mock_data()
    data["securityDefaults"]["isEnabled"] = True
    return MockGraphClient(data)


@pytest.fixture
def sample_config():
    """Provide sample configuration for checks."""
    return {
        "tenant_id": "test-tenant-id",
        "initiated_by": "test@example.com",
        "scan_id": "test-scan-123",
        "require_strong_mfa": False,
        "exempt_users": [],
        "break_glass_accounts": ["emergency@test.com"],
        "include_guests": False
    }
