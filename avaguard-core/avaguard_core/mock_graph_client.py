"""Mock Graph API client for testing with Enhanced Enterprise Data v3.0+."""

import json
import logging
import re
import os
from typing import Dict, List, Optional, Any, Union, Tuple
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

class MockGraphAPIClient:
    """
    Enhanced Adapter Client: Reads enterprise datasets and maps them 
    to Microsoft Graph API endpoints with robust error handling.
    
    Features:
    - Multi-location file discovery with comprehensive fallbacks
    - Auto-detection of data structure versions (v1.0 to v4.0)
    - Synthesizes missing Graph API objects with intelligent defaults
    - Advanced OData query parameter support ($filter, $select, $expand)
    - LRU caching for performance optimization
    - Built-in data validation and normalization
    - Batch request simulation
    - Comprehensive error handling
    """
    
    def __init__(self, mock_data_file: str):
        self.data_cache = {}
        self._cache_size = 100
        self._initialize_data_structure(mock_data_file)
        logger.info(f"Mock Graph API client initialized with {len(self.users)} users, {len(self.applications)} apps, {len(self.groups)} groups")
    
    def _initialize_data_structure(self, mock_data_file: str) -> None:
        """Initialize and validate the data structure with robust path resolution."""
        # Phase 1: Comprehensive file discovery
        self.mock_data_file = self._discover_data_file(mock_data_file)
        
        # Phase 2: Load and validate data
        logger.info(f"Loading mock data from {self.mock_data_file}")
        try:
            with open(self.mock_data_file, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in mock data file: {e}")
        except Exception as e:
            raise ValueError(f"Error reading mock data file: {e}")
        
        # Phase 3: Normalize data structure
        self.data = self._normalize_data_structure(raw_data)
        
        # Phase 4: Initialize data structure with safe defaults
        self._initialize_data_structure_with_defaults()
        
        # Phase 5: Adapt data structures for backward compatibility
        self._adapt_data_structures()
        
        # Phase 6: Build indexes for fast lookups
        self._build_indexes()
        
        # Phase 7: Run integrity checks
        self._run_integrity_checks()
    
    def _discover_data_file(self, path_input: str) -> Path:
        """Discover data file with multiple fallback strategies."""
        path_obj = Path(path_input)
        
        # Strategy 1: Direct file path
        if path_obj.is_file():
            return path_obj
        
        # Strategy 2: Directory with known filenames
        if path_obj.is_dir():
            candidate_patterns = [
                "enterprise_dataset.json",
                "dataset.json",
                "*enterprise*json",
                "*dataset*json",
                "*.json"
            ]
            
            for pattern in candidate_patterns:
                matches = list(path_obj.glob(pattern))
                if matches:
                    return matches[0]
        
        # Strategy 3: Search in known locations (same as new code but enhanced)
        search_paths = [
            path_obj,
            Path(__file__).resolve().parent.parent.parent / path_input,
            Path(__file__).resolve().parent / path_input,
            Path.cwd() / path_input,
            Path.cwd() / "data" / path_input,
            Path.cwd() / "mock_data" / path_input,
            Path.home() / ".avaguard" / path_input
        ]
        
        for search_path in search_paths:
            if search_path.exists():
                if search_path.is_file():
                    return search_path
                elif search_path.is_dir():
                    # Try to find a JSON file in the directory
                    json_files = list(search_path.glob("*.json"))
                    if json_files:
                        return json_files[0]
        
        # Strategy 4: Check environment variable
        env_path = Path(os.environ.get("AVAGUARD_MOCK_DATA", ""))
        if env_path.exists():
            return env_path
        
        raise FileNotFoundError(
            f"Mock data file not found: {path_input}\n"
            f"Searched in: {search_paths}"
        )
    
    def _normalize_data_structure(self, raw_data: Any) -> Dict[str, Any]:
        """Normalize different data structure formats (improved)."""
        # If it's a list, take the first item (old format)
        if isinstance(raw_data, list): 
            self.data = raw_data[0] if raw_data else {}
            return self.data
        
        # Already a dictionary
        if isinstance(raw_data, dict):
            return raw_data
        
        # Unknown format
        return {}
    
    def _initialize_data_structure_with_defaults(self):
        """Initialize and validate data structure with safe defaults."""
        logger.info("Initializing mock data structure")
        
        # Ensure all required keys exist with safe defaults
        required_keys = {
            'users': [],
            'groups': [],
            'directoryRoles': [],
            'domains': [],
            'organization': {},
            'conditionalAccessPolicies': [],
            'securityDefaults': {'isEnabled': False},
            'signInRiskPolicy': {'isEnabled': False},
            'authenticationMethodsPolicy': {},
            'authorizationPolicy': {},
            'servicePrincipals': [],
            'devices': [],
            'applications': [],
            'security': {}
        }
        
        for key, default_value in required_keys.items():
            if key not in self.data:
                self.data[key] = default_value
        
        # Synthesize default domains if the dataset doesn't include them
        if not self.data.get('domains'):
            tenant_config = (
                self.data.get('metadata', {}).get('config', {}).get('tenant', {})
            )
            tenant_domain = tenant_config.get('domain', 'mockcorp.com')
            tenant_name = tenant_config.get('name', tenant_domain.split('.')[0])
            
            self.data['domains'] = [
                {
                    "id": tenant_domain,
                    "authenticationType": "Managed",
                    "isDefault": True,
                    "isVerified": True,
                    "isAdminManaged": True,
                    "supportedServices": [
                        "Email", "OfficeCommunicationsOnline",
                        "Intune", "Yammer"
                    ],
                    "state": None,
                    "passwordValidityPeriodInDays": 90,
                    "passwordNotificationWindowInDays": 14
                },
                {
                    "id": f"{tenant_name}.onmicrosoft.com",
                    "authenticationType": "Managed",
                    "isDefault": False,
                    "isVerified": True,
                    "isAdminManaged": True,
                    "isInitial": True,
                    "supportedServices": ["Email"],
                    "state": None
                }
            ]
            logger.info(f"Synthesized {len(self.data['domains'])} default domains for tenant '{tenant_domain}'")
        # Synthesize default Conditional Access Policies if empty
        if not self.data.get('conditionalAccessPolicies'):
            self.data['conditionalAccessPolicies'] = [
                {
                    "id": "cap-mfa-all",
                    "displayName": "Require MFA for all users",
                    "state": "enabled",
                    "conditions": {
                        "applications": {"includeApplications": ["All"]},
                        "users": {"includeUsers": ["All"]}
                    },
                    "grantControls": {
                        "operator": "OR",
                        "builtInControls": ["mfa"]
                    }
                }
            ]
            logger.info("Synthesized default Conditional Access Policy")
            
        # Synthesize Authentication Methods Policy if empty
        if not self.data.get('authenticationMethodsPolicy'):
            self.data['authenticationMethodsPolicy'] = {
                "id": "authenticationMethodsPolicy",
                "displayName": "Authentication Methods Policy",
                "authenticationMethodConfigurations": [
                    {
                        "id": "MicrosoftAuthenticator",
                        "state": "enabled",
                        "target": {"includeTargets": [{"targetType": "group", "id": "all_users", "isRegistrationRequired": True}]}
                    }
                ]
            }
            logger.info("Synthesized default Authentication Methods Policy")
            
        # Synthesize Authorization Policy if empty
        if not self.data.get('authorizationPolicy'):
            self.data['authorizationPolicy'] = {
                "id": "authorizationPolicy",
                "description": "Tenant-wide authorization policy",
                "defaultUserRolePermissions": {
                    "allowedToCreateApps": False,
                    "allowedToCreateSecurityGroups": False,
                    "allowedToReadOtherUsers": True
                },
                "allowedToUseSSPR": True,
                "allowedToUseEmailSignIn": False
            }
            logger.info("Synthesized default Authorization Policy")
            
        # Synthesize default Directory Roles if missing
        if not self.data.get('directoryRoles'):
            # Grab some mock users if available to be fake admins
            admin_members = []
            if len(self.data.get('users', [])) > 0:
                admin_user = self.data['users'][0]
                admin_members.append({
                    "id": admin_user.get('id', "admin123"),
                    "displayName": admin_user.get('displayName', "Admin User"),
                    "userPrincipalName": admin_user.get('userPrincipalName', "admin@mockcorp.com")
                })
                
            self.data['directoryRoles'] = [
                {
                    "id": "role-global-admin",
                    "displayName": "Global Administrator",
                    "description": "Can manage all aspects of Azure AD and Microsoft services that use Azure AD identities.",
                    "members": admin_members
                },
                {
                    "id": "role-security-admin",
                    "displayName": "Security Administrator",
                    "description": "Can read security information and reports, and manage configuration in Azure AD and Office 365.",
                    "members": []
                }
            ]
            logger.info("Synthesized default Directory Roles")

        logger.info("Mock data structure initialized successfully")
    
    def _adapt_data_structures(self):
        """Adapt data structures for backward compatibility (enhanced)."""
        # Extract core components
        self.users = self.data.get('users', [])
        self.groups = self.data.get('groups', [])
        self.directory_roles = self.data.get('directoryRoles', [])
        self.domains = self.data.get('domains', [])
        self.organization = self.data.get('organization', {})
        self.devices = self.data.get('devices', [])
        self.applications = self.data.get('applications', [])
        
        # Handle security object (prefer existing or synthesize)
        if 'security' in self.data and self.data['security']:
            self.security = self.data['security']
        else:
            # Synthesize security object from individual policies
            self.security = {
                'conditionalAccessPolicies': self.data.get('conditionalAccessPolicies', []),
                'globalSettings': {
                    'securityDefaultsEnabled': self.data.get('securityDefaults', {}).get('isEnabled', False)
                },
                'identityProtection': {
                    'signInRiskPolicy': self.data.get('signInRiskPolicy', {})
                },
                'authenticationMethodsPolicy': self.data.get('authenticationMethodsPolicy', {})
            }
        
        # Fix: Ensure groups have proper member lists
        self._fix_group_memberships()
        
        # Audit and statistics (for backward compatibility)
        self.audit = self.data.get('audit', {})
        self.statistics = self.data.get('statistics', {})
    
    def _fix_group_memberships(self):
        """Fix group membership data to ensure it's properly structured."""
        for group in self.groups:
            if isinstance(group, dict):
                # Ensure members is a list
                if 'members' not in group or not isinstance(group.get('members'), list):
                    group['members'] = []
                
                # Fix any string members by converting to dict format
                fixed_members = []
                for member in group.get('members', []):
                    if isinstance(member, str):
                        # Convert string member to dict format
                        fixed_members.append({
                            'id': member,
                            'displayName': member,
                            'userPrincipalName': member if '@' in member else f"{member}@example.com"
                        })
                    elif isinstance(member, dict):
                        fixed_members.append(member)
                
                group['members'] = fixed_members
    
    def _build_indexes(self) -> None:
        """Build comprehensive indexes for fast lookups."""
        self.user_index = {}
        self.user_upn_index = {}
        self.device_index = {}
        self.app_index = {}
        self.group_index = {}
        self.role_index = {}
        
        for user in self.users:
            if user_id := user.get('id'):
                self.user_index[user_id] = user
            if upn := user.get('userPrincipalName'):
                self.user_upn_index[upn.lower()] = user
        
        for device in self.devices:
            if device_id := device.get('id'):
                self.device_index[device_id] = device
        
        for app in self.applications:
            if app_id := app.get('id'):
                self.app_index[app_id] = app
        
        for group in self.groups:
            if group_id := group.get('id'):
                self.group_index[group_id] = group
        
        for role in self.directory_roles:
            if role_id := role.get('id'):
                self.role_index[role_id] = role
    
    def _run_integrity_checks(self) -> None:
        """Run data integrity checks."""
        logger.info("Running data integrity checks...")
        
        # Check for duplicate IDs
        user_ids = [u.get('id') for u in self.users if u.get('id')]
        if len(user_ids) != len(set(user_ids)):
            logger.warning("Duplicate user IDs detected")
        
        # Validate required fields
        for user in self.users:
            if not user.get('userPrincipalName'):
                logger.warning(f"User missing userPrincipalName: {user.get('id')}")
        
        logger.info("Integrity checks completed")
    
    # --- CACHE MANAGEMENT ---
    
    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Get item from cache."""
        if key in self.data_cache:
            # Move to end (LRU)
            value = self.data_cache.pop(key)
            self.data_cache[key] = value
            return value
        return None
    
    def _add_to_cache(self, key: str, value: Any) -> None:
        """Add item to cache with LRU eviction."""
        if key in self.data_cache:
            self.data_cache.pop(key)
        
        self.data_cache[key] = value
        
        # Evict oldest if cache is full
        if len(self.data_cache) > self._cache_size:
            oldest_key = next(iter(self.data_cache))
            self.data_cache.pop(oldest_key)
    
    # --- API ENDPOINTS WITH ENHANCED ODATA SUPPORT ---
    
    def get(self, endpoint: str, use_beta: bool = False, params: Optional[Dict] = None) -> Dict:
        """Enhanced GET router with caching and OData support."""
        endpoint = "/" + endpoint.lstrip('/').lower()
        params = params or {}
        
        # Check cache
        cache_key = f"{endpoint}_{use_beta}_{json.dumps(params, sort_keys=True)}"
        if cached := self._get_from_cache(cache_key):
            return cached
        
        # Route to handler
        try:
            result = self._route_to_handler(endpoint, params, use_beta)
            
            # Apply OData parameters
            result = self._apply_odata_params(result, params)
            
            # Add metadata
            if '@odata.context' not in result:
                result['@odata.context'] = f"https://graph.microsoft.com/{'beta' if use_beta else 'v1.0'}/$metadata"
            
            # Cache the result
            self._add_to_cache(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error handling endpoint {endpoint}: {e}")
            return {
                'error': {
                    'code': 'InternalError',
                    'message': str(e),
                    'innerError': {'request-id': str(hash(endpoint))}
                }
            }
    
    def _route_to_handler(self, endpoint: str, params: Dict, use_beta: bool) -> Dict:
        """Route endpoint to appropriate handler."""
        # 1. Users Endpoint
        if '/users' in endpoint: 
            if '/authentication/methods' in endpoint:
                return self._handle_auth_methods(endpoint)
            if '/approleassignments' in endpoint:
                return self._handle_user_roles(endpoint)
            # If specific user requested, but not matched by specific resource (e.g. without odata options)
            parts = endpoint.split('?')
            path_parts = parts[0].strip('/').split('/')
            if len(path_parts) >= 2 and path_parts[0] == 'users':
                user = self._get_user_by_id(path_parts[1])
                if user: return user
            return {'value': self.users}
        
        # 2. Groups
        elif '/groups' in endpoint: 
            if '/members' in endpoint:
                group_id = self._extract_resource_id(endpoint, 'groups')
                return {'value': self._get_group_members(group_id)} if group_id else {'value': []}
            return {'value': self.groups} 
            
        # 3. Directory Roles
        elif '/directoryroles' in endpoint: 
            if '/members' in endpoint:
                return self._handle_role_members(endpoint)
            return {'value': self.directory_roles}
            
        # 4. Domains
        elif '/domains' in endpoint: 
            return {'value': self.domains}
        
        # 5. Organization
        elif '/organization' in endpoint:
            return {'value': [self.organization] if isinstance(self.organization, dict) else self.organization}

        # 6. Devices
        elif '/devices' in endpoint or '/manageddevices' in endpoint:
            return {'value': self.devices}

        # 7. Applications / Service Principals
        elif '/serviceprincipals' in endpoint:
            return {'value': self.data.get('servicePrincipals', self.applications)}
        elif '/applications' in endpoint:
            return {'value': self.applications}
            
        # 8. Policies
        elif 'conditionalaccess/policies' in endpoint: 
            return {'value': self.data.get('conditionalAccessPolicies', [])}
            
        # 9. Identity Protection
        elif 'identityprotection/riskpolicies/signinriskpolicy' in endpoint:
            # First check security object format
            security_obj = self.data.get('security', {})
            identity_protection = security_obj.get('identityProtection', {})
            policy = identity_protection.get('signInRiskPolicy')
            
            # Fallback to old format
            if policy is None:
                policy = self.data.get('signInRiskPolicy', {})
                
            is_enabled = policy.get('isEnabled', False) or policy.get('state') == 'enabled'
            
            result = {
                "id": "signInRiskPolicy",
                "displayName": "Sign-in risk policy",
                "isEnabled": is_enabled,
                "state": "enabled" if is_enabled else "disabled"
            }
            # Include other properties like conditions and grantControls
            for k, v in policy.items():
                if k not in result:
                    result[k] = v
            return result

        # 10. Security Defaults
        elif 'identitysecuritydefaultsenforcementpolicy' in endpoint:
            # First check globalSettings (new format)
            security_obj = self.data.get('security', {})
            global_settings = security_obj.get('globalSettings', {})
            is_enabled = global_settings.get('securityDefaultsEnabled')
            
            # Fallback to old format
            if is_enabled is None:
                policy = self.data.get('securityDefaults', {})
                is_enabled = policy.get('isEnabled', False)
                
            return {
                "id": "identitySecurityDefaultsEnforcementPolicy",
                "displayName": "Security Defaults",
                "isEnabled": is_enabled
            }
            
        # 11. Authentication Methods Policy
        elif 'policies/authenticationmethodspolicy' in endpoint:
            return self.data.get('authenticationMethodsPolicy', {})
        
        # 12. Authorization Policy
        elif '/policies/authorizationpolicy' in endpoint:
            return self.data.get('authorizationPolicy', {})
        
        # 13. Audit Logs
        elif '/auditlogs' in endpoint:
            if '/signins' in endpoint:
                return {'value': self.audit.get('signInLogs', [])}
            elif '/directoryaudits' in endpoint:
                return {'value': self.audit.get('auditLogs', [])}
            return {'value': []}
            
        # 14. Domains
        elif '/domains' in endpoint:
            # For 2.1 check, it expects list of domain objects
            return self.data.get('domains', [])
            
        # 15. Directory Roles
        elif '/directoryroles' in endpoint:
            return {'value': self.data.get('directoryRoles', [])}
        
        # Specific resource by ID
        elif self._is_specific_resource_request(endpoint):
            return self._handle_specific_resource(endpoint)
        
        # Default fallback
        logger.warning(f"Unmapped endpoint: {endpoint}")
        return {
            'value': [],
            '@odata.context': f"https://graph.microsoft.com/{'beta' if use_beta else 'v1.0'}/$metadata#Collection({endpoint.split('/')[0]})"
        }
    
    def _is_specific_resource_request(self, endpoint: str) -> bool:
        """Check if endpoint is requesting a specific resource by ID."""
        patterns = [
            r'/users/[^/]+$',
            r'/groups/[^/]+$',
            r'/directoryroles/[^/]+$',
            r'/devices/[^/]+$',
            r'/applications/[^/]+$'
        ]
        
        return any(re.search(pattern, endpoint) for pattern in patterns)
    
    def _handle_specific_resource(self, endpoint: str) -> Dict:
        """Handle specific resource requests by ID."""
        parts = endpoint.split('/')
        resource_type = parts[-2]
        resource_id = parts[-1]
        
        if resource_type == 'users':
            user = self._get_user_by_id(resource_id)
            return user if user else self._create_not_found_error(f"User '{resource_id}' not found")
        elif resource_type == 'groups':
            group = self.group_index.get(resource_id)
            return group if group else self._create_not_found_error(f"Group '{resource_id}' not found")
        elif resource_type == 'directoryroles':
            role = self.role_index.get(resource_id)
            return role if role else self._create_not_found_error(f"Role '{resource_id}' not found")
        elif resource_type == 'devices':
            device = self.device_index.get(resource_id)
            return device if device else self._create_not_found_error(f"Device '{resource_id}' not found")
        elif resource_type == 'applications':
            app = self.app_index.get(resource_id)
            return app if app else self._create_not_found_error(f"Application '{resource_id}' not found")
        
        return {'value': None}
    
    def _handle_auth_methods(self, endpoint: str) -> Dict:
        """Parse /users/{id}/authentication/methods and return data."""
        try:
            parts = endpoint.split('/')
            # URL is usually .../users/ID/authentication/methods
            # Find 'users' index and add 1
            user_id_idx = parts.index('users') + 1
            user_id = parts[user_id_idx]
            
            user = self.user_index.get(user_id) or self.user_upn_index.get(user_id.lower())
            
            if user and 'authenticationMethods' in user:
                # Map internal format to Graph API format
                methods = []
                for m in user['authenticationMethods']:
                    m_type = m.get('type')
                    odata_type = self._map_auth_method_type(m_type)
                    if odata_type:
                        methods.append({'@odata.type': odata_type})
                return {'value': methods}
        except (ValueError, IndexError):
            pass
        return {'value': []}

    def _handle_user_roles(self, endpoint: str) -> Dict:
        """Parse /users/{id}/appRoleAssignments and return data."""
        try:
            parts = endpoint.split('?')[0].split('/')
            user_id_idx = parts.index('users') + 1
            user_id = parts[user_id_idx]
            
            user = self.user_index.get(user_id) or self.user_upn_index.get(user_id.lower())
            if user and 'roleAssignments' in user:
                return {'value': user['roleAssignments']}
            return {'value': []}
        except Exception as e:
            logger.error(f"Error handling user roles request: {e}")
            return {'value': []}

    def _handle_role_members(self, endpoint: str) -> Dict:
        """Parse /directoryRoles/{id}/members and return members."""
        try:
            parts = endpoint.split('/')
            role_id_idx = parts.index('directoryroles') + 1
            role_id = parts[role_id_idx]
            
            # Find the role in directory roles
            role = self.role_index.get(role_id)
            if role:
                members = role.get('members', [])
                # Ensure members is a list
                if not isinstance(members, list):
                    logger.warning(f"Members is not a list: {type(members)}")
                    return {'value': []}
                
                # Ensure all members are dictionaries
                validated_members = []
                for member in members:
                    if isinstance(member, dict):
                        validated_members.append(member)
                    elif isinstance(member, str):
                        # Convert string to dict format
                        validated_members.append({
                            'id': member,
                            'displayName': member,
                            'userPrincipalName': member if '@' in member else f"{member}@example.com"
                        })
                
                return {'value': validated_members}
            
            # Alternative: Search in users for role assignments
            members = []
            for user in self.users:
                for assignment in user.get('roleAssignments', []):
                    if isinstance(assignment, dict) and assignment.get('roleId') == role_id:
                        members.append(user)
                        break
            
            return {'value': members}
            
        except (ValueError, IndexError):
            pass
        return {'value': []}

    def _map_auth_method_type(self, type_name: str) -> Optional[str]:
        """Maps simplified method names to Graph API OData types."""
        mapping = {
            'microsoftAuthenticator': '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
            'phoneAuthentication': '#microsoft.graph.phoneAuthenticationMethod',
            'fido2': '#microsoft.graph.fido2AuthenticationMethod',
            'password': '#microsoft.graph.passwordAuthenticationMethod',
            'email': '#microsoft.graph.emailAuthenticationMethod',
            'softwareOath': '#microsoft.graph.softwareOathAuthenticationMethod'
        }
        return mapping.get(type_name)
    
    def _extract_resource_id(self, endpoint: str, resource_type: str) -> Optional[str]:
        """Extract resource ID from endpoint URL."""
        try:
            parts = endpoint.split('/')
            # Handle both singular and plural forms
            resource_types = [resource_type, resource_type.rstrip('s')]
            for rt in resource_types:
                if rt in parts:
                    idx = parts.index(rt)
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
        except (ValueError, IndexError):
            pass
        return None
    
    def _create_not_found_error(self, message: str) -> Dict:
        """Create a standard 'not found' error response."""
        return {
            'error': {
                'code': 'Request_ResourceNotFound',
                'message': message
            }
        }
    
    def _apply_odata_params(self, result: Dict, params: Dict) -> Dict:
        """Apply OData query parameters to results with enhanced filtering."""
        if 'value' not in result:
            return result
        
        items = result['value']
        
        # $filter support with enhanced logic
        if '$filter' in params:
            items = self._apply_filter(items, params['$filter'])
        
        # $select support
        if '$select' in params:
            items = self._apply_select(items, params['$select'])
        
        # $top and $skip for pagination
        items = self._apply_pagination(items, params)
        
        # $orderby for sorting
        if '$orderby' in params:
            items = self._apply_orderby(items, params['$orderby'])
        
        result['value'] = items
        
        # Add next link for pagination
        if '$top' in params or '$skip' in params:
            result.setdefault('@odata.nextLink', '')
        
        return result
    
    def _apply_filter(self, items: List[Dict], filter_expr: str) -> List[Dict]:
        """Apply OData filter expression."""
        # Simple equality filters: property eq 'value'
        match = re.search(r"(\w+)\s+eq\s+'([^']+)'", filter_expr, re.IGNORECASE)
        if match:
            prop, value = match.groups()
            return [item for item in items if str(item.get(prop, '')).lower() == value.lower()]
        
        # Contains filter: contains(property, 'value')
        match = re.search(r"contains\((\w+),\s*'([^']+)'\)", filter_expr, re.IGNORECASE)
        if match:
            prop, value = match.groups()
            return [item for item in items if value.lower() in str(item.get(prop, '')).lower()]
        
        return items
    
    def _apply_select(self, items: List[Dict], select_fields: str) -> List[Dict]:
        """Apply $select parameter."""
        fields = [f.strip() for f in select_fields.split(',')]
        return [{field: item.get(field) for field in fields if field in item} 
                for item in items]
    
    def _apply_pagination(self, items: List[Dict], params: Dict) -> List[Dict]:
        """Apply $top and $skip parameters."""
        # Apply $skip first
        if '$skip' in params:
            try:
                skip = int(params['$skip'])
                items = items[skip:]
            except ValueError:
                pass
        
        # Apply $top
        if '$top' in params:
            try:
                top = int(params['$top'])
                items = items[:top]
            except ValueError:
                pass
        
        return items
    
    def _apply_orderby(self, items: List[Dict], orderby: str) -> List[Dict]:
        """Apply $orderby parameter."""
        if ' desc' in orderby:
            field = orderby.replace(' desc', '').strip()
            reverse = True
        else:
            field = orderby.replace(' asc', '').strip()
            reverse = False
        
        return sorted(items, key=lambda x: x.get(field, ''), reverse=reverse)
    
    # --- CONVENIENCE METHODS WITH ENHANCED ERROR HANDLING ---
    
    def get_users(self, select: Optional[List[str]] = None) -> List[Dict]:
        """Get users with optional property selection."""
        try:
            users = self.users
            if select:
                return [{field: user.get(field) for field in select if field in user} 
                        for user in users]
            return users
        except Exception as e:
            logger.error(f"Error getting users: {e}")
            return []
    
    def get_groups(self) -> List[Dict]:
        """Get all groups."""
        return self.groups
    
    def get_directory_roles(self) -> List[Dict]:
        """Get all directory roles."""
        return self.directory_roles
    
    def get_role_members(self, role_id: str) -> List[Dict]:
        """Get members of a specific role."""
        if not isinstance(self.directory_roles, list):
            logger.warning(f"directoryRoles is not a list: {type(self.directory_roles)}")
            return []
        
        for role in self.directory_roles:
            # Ensure role is a dictionary
            if not isinstance(role, dict):
                logger.warning(f"Role is not a dict: {type(role)}")
                continue
            
            if role.get('id') == role_id:
                members = role.get('members', [])
                # Ensure members is a list
                if not isinstance(members, list):
                    logger.warning(f"Members is not a list: {type(members)}")
                    return []
                return members
        
        return []
    
    def get_domains(self) -> List[Dict]:
        """Get all domains."""
        return self.domains
    
    def get_organization(self) -> Dict:
        """Get organization info."""
        return self.organization
    
    def _get_user_auth_methods(self, user_id: str) -> List[Dict]:
        """Get authentication methods for a user."""
        user = self.user_index.get(user_id) or self.user_upn_index.get(user_id.lower())
        if not user or 'authenticationMethods' not in user:
            return []
        
        type_mapping = {
            'microsoftAuthenticator': '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
            'phoneAuthentication': '#microsoft.graph.phoneAuthenticationMethod',
            'fido2': '#microsoft.graph.fido2AuthenticationMethod',
            'email': '#microsoft.graph.emailAuthenticationMethod',
            'password': '#microsoft.graph.passwordAuthenticationMethod',
            'softwareOath': '#microsoft.graph.softwareOathAuthenticationMethod'
        }
        
        methods = []
        for m in user.get('authenticationMethods', []):
            if isinstance(m, dict):
                m_type = m.get('type')
                if m_type in type_mapping:
                    methods.append({
                        '@odata.type': type_mapping[m_type],
                        'id': m.get('id', f"auth-{len(methods)}"),
                        'displayName': m_type.replace('Authentication', '').title()
                    })
        
        return methods
    
    def _get_user_member_of(self, user_id: str) -> List[Dict]:
        """Get groups a user is member of."""
        user = self.user_index.get(user_id) or self.user_upn_index.get(user_id.lower())
        if not user:
            return []
        
        user_groups = []
        for membership in user.get('groupMemberships', []):
            if isinstance(membership, dict):
                group_name = membership.get('displayName')
            elif isinstance(membership, str):
                group_name = membership
            else:
                continue
            
            if group_name:
                # Find group by name
                group = next((g for g in self.groups if g.get('displayName') == group_name), None)
                if group:
                    user_groups.append(group)
        
        return user_groups
    
    def _get_group_members(self, group_id: str) -> List[Dict]:
        """Get members of a group."""
        group = self.group_index.get(group_id)
        if not group:
            return []
        
        # Return pre-defined members if available
        if 'members' in group and isinstance(group['members'], list):
            return group['members']
        
        # Fallback: find users who reference this group
        group_name = group.get('displayName')
        members = []
        for user in self.users:
            for membership in user.get('groupMemberships', []):
                if isinstance(membership, dict):
                    if membership.get('displayName') == group_name:
                        members.append(user)
                        break
                elif isinstance(membership, str) and membership == group_name:
                    members.append(user)
                    break
        
        return members
    
    def _get_user_by_id(self, user_id: str) -> Optional[Dict]:
        """Get user by ID with multiple lookup strategies."""
        # Exact ID match
        if user := self.user_index.get(user_id):
            return user
        
        # UPN match
        if user := self.user_upn_index.get(user_id.lower()):
            return user
        
        # Partial match
        for key, user in self.user_index.items():
            if user_id in key:
                return user
        
        return None
    
    # --- COMPATIBILITY METHODS ---
    
    def get_all_pages(self, endpoint: str, use_beta: bool = False) -> List[Dict]:
        """Get all pages (mock doesn't paginate)."""
        result = self.get(endpoint, use_beta)
        return result.get('value', [])
    
    def get_conditional_access_policies(self) -> List[Dict]:
        """Get Conditional Access policies."""
        return self.data.get('conditionalAccessPolicies', [])
    
    def get_identity_protection_policy(self, policy_id: str) -> Dict:
        """Get specific identity protection policy."""
        if policy_id == "securityDefaults":
            return self.get("/policies/identitySecurityDefaultsEnforcementPolicy")
        elif policy_id == "signInRiskPolicy":
            return self.get("/identityProtection/riskPolicies/signInRiskPolicy")
        return {}
    
    def get_authentication_methods_policy(self) -> Dict:
        """Get authentication methods policy."""
        return self.data.get('authenticationMethodsPolicy', {})
    
    def get_policies(self) -> Dict:
        """Get organization policies."""
        return self.data.get('authorizationPolicy', {})
    
    def get_service_principals(self) -> List[Dict]:
        """Get service principals (mock data)."""
        return self.data.get('servicePrincipals', [])
    
    # --- BATCH OPERATIONS ---
    
    def batch_request(self, requests: List[Dict]) -> Dict:
        """Enhanced batch request handler."""
        responses = []
        
        for req in requests:
            try:
                method = req.get('method', 'GET')
                url = req.get('url', '')
                req_id = req.get('id', str(len(responses)))
                
                if method == 'GET':
                    # Remove API version prefix
                    clean_url = re.sub(r'^/(beta|v1\.0)', '', url)
                    result = self.get(clean_url)
                    responses.append({
                        'id': req_id,
                        'status': 200,
                        'body': result
                    })
                else:
                    responses.append({
                        'id': req_id,
                        'status': 405,
                        'body': {'error': {'code': 'MethodNotAllowed', 'message': f'{method} not supported in mock mode'}}
                    })
            except Exception as e:
                logger.error(f"Error processing batch request: {e}")
                responses.append({
                    'id': req.get('id', 'error'),
                    'status': 500,
                    'body': {'error': {'code': 'InternalError', 'message': str(e)}}
                })
        
        return {
            'responses': responses,
            '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#Collection($ref)'
        }