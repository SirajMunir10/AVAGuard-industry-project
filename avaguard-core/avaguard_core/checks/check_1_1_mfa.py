"""CIS 1.1: Ensure MFA is enabled for all privileged users."""

import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus
from datetime import datetime

logger = logging.getLogger(__name__)

class Check_1_1_MFA(BaseCheck):
    """Check if MFA is enabled for privileged users."""
    
    CHECK_ID = "1.1"
    TITLE = "Ensure multi-factor authentication is enabled for all privileged users"
    DESCRIPTION = "Privileged accounts should require MFA to reduce risk of compromise"
    REQUIRES_PREMIUM = True
    
    # Standard Microsoft Graph MFA method types
    MFA_METHOD_TYPES = {
        # Phone methods
        'phoneAuthenticationMethod': '#microsoft.graph.phoneAuthenticationMethod',
        'microsoftAuthenticator': '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
        'windowsHelloForBusiness': '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
        'fido2': '#microsoft.graph.fido2AuthenticationMethod',
        'email': '#microsoft.graph.emailAuthenticationMethod',
        'softwareOath': '#microsoft.graph.softwareOathAuthenticationMethod',
        'temporaryAccessPass': '#microsoft.graph.temporaryAccessPassAuthenticationMethod'
    }
    
    # Strong MFA methods (more secure)
    STRONG_MFA_METHODS = {
        'fido2',
        'windowsHelloForBusiness',
        'microsoftAuthenticator'  # With number matching
    }
    
    # Privileged role identifiers (template IDs for built-in roles)
    PRIVILEGED_ROLES = {
        # Global Admin
        '62e90394-69f5-4237-9190-012177145e10': {
            'name': 'Global Administrator',
            'risk_level': 'critical'
        },
        # Privileged Role Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814': {
            'name': 'Privileged Role Administrator',
            'risk_level': 'critical'
        },
        # Security Administrator
        '194ae4cb-b126-40b2-bc5e-47205b6c23b2': {
            'name': 'Security Administrator',
            'risk_level': 'high'
        },
        # Exchange Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de': {
            'name': 'Exchange Administrator',
            'risk_level': 'high'
        },
        # SharePoint Administrator
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': {
            'name': 'SharePoint Administrator',
            'risk_level': 'high'
        },
        # User Administrator
        'fe930be7-5e62-47db-91af-98c3a49a38b1': {
            'name': 'User Administrator',
            'risk_level': 'high'
        },
        # Application Administrator
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': {
            'name': 'Application Administrator',
            'risk_level': 'high'
        },
        # Azure AD Joined Device Local Administrator
        '9f06204d-73c1-4d4c-880a-6edb90606fd8': {
            'name': 'Azure AD Joined Device Local Administrator',
            'risk_level': 'medium'
        }
    }
    
    def __init__(self, graph_client, config: Optional[Dict] = None):
        super().__init__(graph_client, config)
        self.config = config or {}
        self.require_strong_mfa = self.config.get('require_strong_mfa', False)
        self.exempt_users = set(self.config.get('exempt_users', []))
        self.exempt_patterns = self.config.get('exempt_patterns', [])
        self.include_guests = self.config.get('include_guests', False)
        self.break_glass_accounts = self.config.get('break_glass_accounts', [])
        
    def execute(self) -> CheckResult:
        """Execute MFA check for privileged users."""
        try:
            logger.info(f"Executing check {self.CHECK_ID}: {self.TITLE}")
            
            # Get privileged users based on API type
            privileged_users = self._get_privileged_users()
            
            if not privileged_users:
                return self.create_result(
                    status=CheckStatus.PASS,
                    details="No privileged users found in the directory",
                    compliant_count=0,
                    total_count=0
                )
            
            # Check MFA status for each privileged user
            analysis = self._analyze_mfa_status(privileged_users)
            
            # Generate result
            return self._create_check_result(analysis)
            
        except Exception as e:
            logger.error(f"Error executing check {self.CHECK_ID}: {e}", exc_info=True)
            return self.create_result(
                status=CheckStatus.ERROR,
                details=f"Error checking MFA status: {str(e)}",
                total_count=0
            )
    
    def _get_privileged_users(self) -> List[Dict[str, Any]]:
        """Get list of privileged users based on API connection type."""
        if self._is_real_api_connection():
            return self._get_privileged_users_from_real_api()
        else:
            return self._get_privileged_users_from_mock_data()
    
    def _is_real_api_connection(self) -> bool:
        """Determine if we're connected to real Azure API or mock data."""
        # Check if graph client has real API attributes
        if hasattr(self.graph_client, 'is_mock_client'):
            return not self.graph_client.is_mock_client
        
        # Check for authentication token
        if hasattr(self.graph_client, 'token'):
            return bool(self.graph_client.token)
            
        # Default assumption - treat as mock
        return False
    
    def _get_privileged_users_from_real_api(self) -> List[Dict[str, Any]]:
        """Get privileged users from real Azure Graph API."""
        privileged_users = []
        
        try:
            # Method 1: Get users with privileged roles
            for role_template_id, role_info in self.PRIVILEGED_ROLES.items():
                try:
                    # Get role object by template ID
                    role_response = self.graph_client.get(
                        f"/directoryRoles?$filter=roleTemplateId eq '{role_template_id}'"
                    )
                    
                    roles = role_response.get('value', [])
                    if not roles:
                        continue
                    
                    role = roles[0]
                    
                    # Get members of this role
                    members_response = self.graph_client.get(
                        f"/directoryRoles/{role['id']}/members"
                    )
                    
                    members = members_response.get('value', [])
                    
                    for member in members:
                        if member.get('@odata.type') == '#microsoft.graph.user':
                            user_info = self._enrich_user_info(member, role_info)
                            privileged_users.append(user_info)
                            
                except Exception as e:
                    logger.warning(f"Error fetching members for role {role_info['name']}: {e}")
            
            # Method 2: Get users with isPrivileged attribute (if available in custom attributes)
            try:
                # Try to get users with privileged indicators
                privileged_query = (
                    "$select=id,userPrincipalName,displayName,accountEnabled,"
                    "userType,jobTitle,department,createdDateTime"
                )
                users_response = self.graph_client.get(f"/users?{privileged_query}")
                
                for user in users_response.get('value', []):
                    if self._is_privileged_by_attributes(user):
                        user_info = self._enrich_user_info(user, {'name': 'Custom Privileged', 'risk_level': 'medium'})
                        privileged_users.append(user_info)
                        
            except Exception as e:
                logger.debug(f"Could not fetch users by attributes: {e}")
            
            # Remove duplicates (users might be in multiple roles)
            unique_users = self._deduplicate_users(privileged_users)
            
            return unique_users
            
        except Exception as e:
            logger.error(f"Error fetching privileged users from real API: {e}")
            return []
    
    def _get_privileged_users_from_mock_data(self) -> List[Dict[str, Any]]:
        """Get privileged users from mock data."""
        try:
            users = self.graph_client.get_users()
            
            privileged_users = []
            for user in users:
                if user.get('isPrivileged') or self._is_privileged_by_attributes(user):
                    # Enrich with role information if available
                    role_name = "Unknown Privileged Role"
                    risk_level = "medium"
                    
                    # Try to get role from assignments
                    role_assignments = user.get('roleAssignments', [])
                    if role_assignments:
                        role_name = role_assignments[0].get('roleName', role_name)
                    
                    user_info = self._enrich_user_info(user, {'name': role_name, 'risk_level': risk_level})
                    privileged_users.append(user_info)
            
            return privileged_users
            
        except Exception as e:
            logger.error(f"Error fetching privileged users from mock data: {e}")
            return []
    
    def _is_privileged_by_attributes(self, user: Dict) -> bool:
        """Determine if user is privileged based on attributes."""
        # Check user type (exclude guests unless configured)
        user_type = user.get('userType', 'Member')
        if user_type == 'Guest' and not self.include_guests:
            return False
        
        # Check job title for privileged indicators
        job_title = user.get('jobTitle', '').lower()
        privileged_titles = ['admin', 'administrator', 'director', 'manager', 'lead', 
                           'security', 'ciso', 'cio', 'cto', 'ceo', 'vp', 'head']
        
        if any(title in job_title for title in privileged_titles):
            return True
        
        # Check department
        department = user.get('department', '').lower()
        privileged_depts = ['it', 'security', 'infrastructure', 'cloud', 'devops', 
                          'network', 'system', 'platform']
        
        if any(dept in department for dept in privileged_depts):
            return True
        
        return False
    
    def _enrich_user_info(self, user: Dict, role_info: Dict) -> Dict[str, Any]:
        """Enrich user information with role data."""
        return {
            'id': user.get('id'),
            'userPrincipalName': user.get('userPrincipalName'),
            'displayName': user.get('displayName'),
            'accountEnabled': user.get('accountEnabled', True),
            'userType': user.get('userType', 'Member'),
            'jobTitle': user.get('jobTitle', ''),
            'department': user.get('department', ''),
            'role': role_info.get('name', 'Unknown Role'),
            'role_risk_level': role_info.get('risk_level', 'medium'),
            'createdDateTime': user.get('createdDateTime'),
            'is_exempt': self._is_user_exempt(user.get('userPrincipalName', '')),
            # Preserve MFA fields for mock data
            'isMfaRegistered': user.get('isMfaRegistered', False),
            'authenticationMethods': user.get('authenticationMethods', []),
        }
    
    def _is_user_exempt(self, upn: str) -> bool:
        """Check if user is exempt from MFA requirement."""
        upn_lower = upn.lower()
        
        # Check break glass accounts
        if upn_lower in [acc.lower() for acc in self.break_glass_accounts]:
            return True
        
        # Check exempt list
        if upn_lower in self.exempt_users:
            return True
        
        # Check exempt patterns
        for pattern in self.exempt_patterns:
            import re
            if re.match(pattern, upn_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _deduplicate_users(self, users: List[Dict]) -> List[Dict]:
        """Remove duplicate users from list."""
        seen_ids = set()
        unique_users = []
        
        for user in users:
            user_id = user.get('id')
            if user_id and user_id not in seen_ids:
                seen_ids.add(user_id)
                unique_users.append(user)
        
        return unique_users
    
    def _analyze_mfa_status(self, privileged_users: List[Dict]) -> Dict[str, Any]:
        """Analyze MFA status for privileged users."""
        analysis = {
            'total': len(privileged_users),
            'compliant': 0,
            'non_compliant': [],
            'exempt': 0,
            'disabled': 0,
            'strong_mfa': 0,
            'weak_mfa': 0,
            'findings': []
        }
        
        for user in privileged_users:
            try:
                user_id = user['id']
                upn = user['userPrincipalName']
                
                # Check if user is exempt
                if user.get('is_exempt'):
                    analysis['exempt'] += 1
                    continue
                
                # Check if account is disabled
                if not user.get('accountEnabled', True):
                    analysis['disabled'] += 1
                    continue
                
                # Get MFA status
                mfa_status = self._get_user_mfa_status(user_id, user)
                
                if mfa_status['has_mfa']:
                    analysis['compliant'] += 1
                    
                    # Check MFA strength
                    if mfa_status['strong_mfa']:
                        analysis['strong_mfa'] += 1
                    else:
                        analysis['weak_mfa'] += 1
                        
                    # Add to findings with details
                    finding = {
                        'userPrincipalName': upn,
                        'role': user.get('role'),
                        'status': 'compliant',
                        'mfa_methods': mfa_status.get('methods', []),
                        'has_strong_mfa': mfa_status.get('strong_mfa', False),
                        'last_mfa_registration': mfa_status.get('last_registration')
                    }
                    analysis['findings'].append(finding)
                    
                else:
                    # Non-compliant
                    finding = {
                        'userPrincipalName': upn,
                        'role': user.get('role'),
                        'role_risk_level': user.get('role_risk_level'),
                        'status': 'non_compliant',
                        'reason': 'No MFA methods registered',
                        'account_age_days': self._get_account_age_days(user.get('createdDateTime'))
                    }
                    analysis['non_compliant'].append(finding)
                    analysis['findings'].append(finding)
                    
            except Exception as e:
                logger.error(f"Error analyzing MFA for user {user.get('userPrincipalName')}: {e}")
        
        return analysis
    
    def _get_user_mfa_status(self, user_id: str, user_info: Dict) -> Dict[str, Any]:
        """Get MFA status for a specific user."""
        if self._is_real_api_connection():
            return self._get_mfa_status_from_real_api(user_id)
        else:
            return self._get_mfa_status_from_mock_data(user_info)
    
    def _get_mfa_status_from_real_api(self, user_id: str) -> Dict[str, Any]:
        """Get MFA status from real Azure Graph API."""
        try:
            # Get authentication methods
            auth_response = self.graph_client.get(f"/users/{user_id}/authentication/methods")
            methods = auth_response.get('value', [])
            
            mfa_methods = []
            has_mfa = False
            strong_mfa = False
            
            for method in methods:
                method_type = method.get('@odata.type', '')
                
                # Check if it's an MFA-capable method
                if method_type in self.MFA_METHOD_TYPES.values():
                    has_mfa = True
                    
                    # Extract method name
                    method_name = next(
                        (k for k, v in self.MFA_METHOD_TYPES.items() if v == method_type),
                        'unknown'
                    )
                    mfa_methods.append(method_name)
                    
                    # Check if it's a strong method
                    if method_name in self.STRONG_MFA_METHODS:
                        strong_mfa = True
            
            return {
                'has_mfa': has_mfa,
                'strong_mfa': strong_mfa,
                'methods': mfa_methods,
                'total_methods': len(methods)
            }
            
        except Exception as e:
            logger.warning(f"Could not fetch MFA methods for user {user_id}: {e}")
            
            # Fallback: Check MFA registration status via user properties
            try:
                user_response = self.graph_client.get(f"/users/{user_id}?$select=id,userPrincipalName")
                user_data = user_response
                
                # Some APIs might have isMfaRegistered field
                has_mfa = user_data.get('isMfaRegistered', False)
                
                return {
                    'has_mfa': has_mfa,
                    'strong_mfa': False,
                    'methods': [],
                    'total_methods': 0
                }
                
            except Exception as inner_e:
                logger.error(f"Fallback MFA check also failed for {user_id}: {inner_e}")
                return {
                    'has_mfa': False,
                    'strong_mfa': False,
                    'methods': [],
                    'total_methods': 0
                }
    
    def _get_mfa_status_from_mock_data(self, user_info: Dict) -> Dict[str, Any]:
        """Get MFA status from mock data."""
        has_mfa = user_info.get('isMfaRegistered', False)
        methods = user_info.get('authenticationMethods', [])
        
        mfa_methods = []
        strong_mfa = False
        
        for method in methods:
            method_type = method.get('type', '')
            if method_type in self.MFA_METHOD_TYPES:
                mfa_methods.append(method_type)
                if method_type in self.STRONG_MFA_METHODS:
                    strong_mfa = True
        
        return {
            'has_mfa': has_mfa,
            'strong_mfa': strong_mfa,
            'methods': mfa_methods,
            'total_methods': len(methods),
            'last_registration': user_info.get('mfaRegistrationDateTime')
        }
    
    def _get_account_age_days(self, created_date: Optional[str]) -> Optional[int]:
        """Calculate account age in days."""
        if not created_date:
            return None
        
        try:
            from datetime import datetime
            # Clean date string
            date_str = created_date.replace('Z', '').split('.')[0]
            created = datetime.fromisoformat(date_str)
            now = datetime.now()
            
            return (now - created).days
        except Exception:
            return None
    
    def _create_check_result(self, analysis: Dict) -> CheckResult:
        """Create the final check result from analysis."""
        total = analysis['total']
        compliant = analysis['compliant']
        non_compliant = analysis['non_compliant']
        exempt = analysis['exempt']
        disabled = analysis['disabled']
        strong_mfa = analysis['strong_mfa']
        weak_mfa = analysis['weak_mfa']
        
        if len(non_compliant) == 0:
            details = [
                f"All {total} privileged users have MFA enabled",
                f"• Total privileged users analyzed: {total}",
                f"• Users with MFA: {compliant}",
                f"• Users with strong MFA: {strong_mfa}",
                f"• Exempt users: {exempt}",
                f"• Disabled accounts: {disabled}"
            ]
            
            if weak_mfa > 0 and self.require_strong_mfa:
                details.append(f"⚠️ Warning: {weak_mfa} users have weak MFA methods")
            
            return self.create_result(
                status=CheckStatus.PASS,
                details="\n".join(details),
                compliant_count=compliant,
                total_count=total
            )
        
        # Non-compliant users found
        details = [
            f"Found {len(non_compliant)} privileged user(s) without MFA",
            f"• Total privileged users analyzed: {total}",
            f"• Users with MFA: {compliant}",
            f"• Users without MFA: {len(non_compliant)}",
            f"• Users with strong MFA: {strong_mfa}",
            f"• Exempt users: {exempt}",
            f"• Disabled accounts: {disabled}",
            ""
        ]
        
        # Add risk breakdown
        critical_risk = sum(1 for user in non_compliant if user.get('role_risk_level') == 'critical')
        high_risk = sum(1 for user in non_compliant if user.get('role_risk_level') == 'high')
        
        if critical_risk > 0 or high_risk > 0:
            details.append("RISK BREAKDOWN:")
            if critical_risk > 0:
                details.append(f"  • Critical risk roles without MFA: {critical_risk}")
            if high_risk > 0:
                details.append(f"  • High risk roles without MFA: {high_risk}")
            details.append("")
        
        # Add top findings
        details.append("USERS WITHOUT MFA:")
        for i, user in enumerate(non_compliant[:10], 1):
            role = user.get('role', 'Unknown')
            risk_marker = " ⚠️" if user.get('role_risk_level') in ['critical', 'high'] else ""
            details.append(f"  {i}. {user['userPrincipalName']} - {role}{risk_marker}")
        
        if len(non_compliant) > 10:
            details.append(f"  ... and {len(non_compliant) - 10} more")
        
        # Add recommendations
        details.extend([
            "",
            "RECOMMENDATIONS:",
            "1. Enable MFA for all privileged users immediately",
            "2. Consider using Conditional Access to enforce MFA (requires Azure AD P1/P2)",
            "3. Implement Privileged Identity Management (PIM) for just-in-time access",
            "4. Use strong authentication methods (FIDO2, Windows Hello)",
            "5. Monitor MFA registration through Azure AD reporting"
        ])
        
        if self.require_strong_mfa and weak_mfa > 0:
            details.extend([
                "",
                "STRONG MFA REQUIRED:",
                f"{weak_mfa} users have weak MFA methods. Consider upgrading to:",
                "• FIDO2 security keys",
                "• Windows Hello for Business",
                "• Microsoft Authenticator with number matching"
            ])
        
        return self.create_result(
            status=CheckStatus.FAIL,
            details="\n".join(details),
            non_compliant_resources=non_compliant,
            non_compliant_count=len(non_compliant),
            compliant_count=compliant,
            total_count=total,
            metadata={
                'strong_mfa_users': strong_mfa,
                'weak_mfa_users': weak_mfa,
                'exempt_users': exempt,
                'disabled_accounts': disabled,
                'critical_risk_without_mfa': critical_risk,
                'high_risk_without_mfa': high_risk,
                'require_strong_mfa': self.require_strong_mfa,
                'analysis_timestamp': datetime.now().isoformat()
            }
        )
    
    def get_configuration_help(self) -> Dict[str, Any]:
        """Provide configuration guidance for this check."""
        return {
            'description': 'Configure MFA enforcement for privileged users',
            'fields': [
                {
                    'name': 'require_strong_mfa',
                    'type': 'boolean',
                    'default': False,
                    'description': 'Require strong MFA methods (FIDO2, Windows Hello)',
                    'help': 'When enabled, weak MFA methods like SMS will be flagged'
                },
                {
                    'name': 'exempt_users',
                    'type': 'array',
                    'default': [],
                    'description': 'List of user principal names exempt from MFA',
                    'help': 'e.g., ["emergency@domain.com"] - Use sparingly!'
                },
                {
                    'name': 'break_glass_accounts',
                    'type': 'array',
                    'default': [],
                    'description': 'Break glass accounts (always exempt)',
                    'help': 'Emergency access accounts that bypass MFA'
                },
                {
                    'name': 'include_guests',
                    'type': 'boolean',
                    'default': False,
                    'description': 'Include guest users in privileged check',
                    'help': 'Guest users with privileged roles should also have MFA'
                }
            ],
            'recommendations': [
                'Implement Conditional Access policies for privileged users',
                'Use Azure AD PIM for just-in-time privileged access',
                'Enable MFA registration campaign for users',
                'Monitor MFA registration and usage with Azure AD reports',
                'Consider passwordless authentication for highest security'
            ],
            'strong_mfa_methods': list(self.STRONG_MFA_METHODS),
            'privileged_roles': {rid: info['name'] for rid, info in self.PRIVILEGED_ROLES.items()}
        }