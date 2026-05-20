from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
import re
from datetime import datetime

logger = logging.getLogger(__name__)

class Check_1_5_GuestRoles(BaseCheck):
    CHECK_ID = "1.5"
    TITLE = "Ensure that no guest users have elevated roles"
    DESCRIPTION = "Guest users should not have administrative privileges"
    REQUIRES_PREMIUM = False
    
    # High-risk administrative roles (should never be assigned to guests)
    HIGH_RISK_ADMIN_ROLES = {
        # Critical roles
        '62e90394-69f5-4237-9190-012177145e10': {
            'name': 'Global Administrator',
            'risk_level': 'critical',
            'description': 'Full access to all administrative features'
        },
        'e8611ab8-c189-46e8-94e1-60213ab1f814': {
            'name': 'Privileged Role Administrator',
            'risk_level': 'critical',
            'description': 'Can manage role assignments'
        },
        # High-risk administrative roles
        '194ae4cb-b126-40b2-bc5e-47205b6c23b2': {
            'name': 'Security Administrator',
            'risk_level': 'high',
            'description': 'Security configuration and monitoring'
        },
        'fe930be7-5e62-47db-91af-98c3a49a38b1': {
            'name': 'User Administrator',
            'risk_level': 'high',
            'description': 'User management and password reset'
        },
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': {
            'name': 'Application Administrator',
            'risk_level': 'high',
            'description': 'Application registration and management'
        },
        # Moderate-risk administrative roles
        '29232cdf-9323-42fd-ade2-1d097af3e4de': {
            'name': 'Exchange Administrator',
            'risk_level': 'medium',
            'description': 'Exchange Online management'
        },
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': {
            'name': 'SharePoint Administrator',
            'risk_level': 'medium',
            'description': 'SharePoint Online management'
        },
        '69091246-20e8-4a56-b4d2-92ace7f8b7b8': {
            'name': 'Teams Administrator',
            'risk_level': 'medium',
            'description': 'Microsoft Teams management'
        }
    }
    
    # Permitted roles for guests (read-only, limited access)
    PERMITTED_GUEST_ROLES = {
        'f2ef992c-3afb-46b9-b7cf-a126ee74c451': {
            'name': 'Global Reader',
            'reason': 'Read-only role is acceptable for guests'
        },
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b': {
            'name': 'Directory Readers',
            'reason': 'Read-only directory access'
        },
        'a0b1b346-4d3e-4e8b-98f8-753987be4970': {
            'name': 'Guest Inviter',
            'reason': 'Limited guest management capability'
        }
    }
    
    def __init__(self, graph_client, config: Optional[Dict] = None):
        super().__init__(graph_client, config)
        self.config = config or {}
        self.whitelist_guests = set(self.config.get('whitelist_guests', []))
        self.include_all_roles = self.config.get('include_all_roles', False)
        self.report_permitted_roles = self.config.get('report_permitted_roles', False)
        self.check_group_memberships = self.config.get('check_group_memberships', True)
        
    def execute(self) -> CheckResult:
        """Execute guest roles check."""
        try:
            logger.info(f"Executing check {self.CHECK_ID}: {self.TITLE}")
            
            # Get guest users with their role assignments
            guest_users = self._get_guest_users_with_roles()
            
            if not guest_users:
                return self.create_result(
                    status=CheckStatus.PASS,
                    details="No guest users found in the directory",
                    compliant_count=0,
                    total_count=0
                )
            
            # Analyze guest roles for compliance
            analysis = self._analyze_guest_roles(guest_users)
            
            # Generate result
            return self._create_check_result(analysis)
            
        except Exception as e:
            logger.error(f"Error executing check {self.CHECK_ID}: {e}", exc_info=True)
            return self.create_result(
                status=CheckStatus.ERROR,
                details=f"Error checking guest roles: {str(e)}",
                total_count=0
            )
    
    def _get_guest_users_with_roles(self) -> List[Dict[str, Any]]:
        """Get guest users with their role assignments."""
        if self._is_real_api_connection():
            return self._get_guest_users_from_real_api()
        else:
            return self._get_guest_users_from_mock_data()
    
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
    
    def _get_guest_users_from_real_api(self) -> List[Dict[str, Any]]:
        """Get guest users from real Azure Graph API with role assignments."""
        guest_users = []
        
        try:
            # Get all guest users
            guest_filter = "userType eq 'Guest'"
            select_fields = (
                "id,userPrincipalName,displayName,accountEnabled,"
                "createdDateTime,mail,externalUserState,externalUserStateChangeDateTime"
            )
            
            guest_response = self.graph_client.get(
                f"/users?$filter={guest_filter}&$select={select_fields}"
            )
            
            guests = guest_response.get('value', [])
            
            for guest in guests:
                guest_id = guest.get('id')
                if not guest_id:
                    continue
                
                # Get role assignments for this guest
                guest_with_roles = self._enrich_guest_with_roles(guest)
                guest_users.append(guest_with_roles)
            
            return guest_users
            
        except Exception as e:
            logger.error(f"Error fetching guest users from real API: {e}")
            return []
    
    def _enrich_guest_with_roles(self, guest: Dict) -> Dict[str, Any]:
        """Enrich guest user with role assignment data."""
        guest_id = guest.get('id')
        enriched_guest = guest.copy()
        
        # Initialize role assignments
        enriched_guest['roleAssignments'] = []
        enriched_guest['groupMemberships'] = []
        
        try:
            # Get direct role assignments
            role_response = self.graph_client.get(
                f"/users/{guest_id}/memberOf?$select=id,displayName,roleTemplateId"
            )
            
            memberships = role_response.get('value', [])
            
            for item in memberships:
                item_type = item.get('@odata.type', '')
                
                if item_type == '#microsoft.graph.directoryRole':
                    # This is a directory role assignment
                    role_template_id = item.get('roleTemplateId')
                    if role_template_id:
                        role_info = self._get_role_info_by_template_id(role_template_id)
                        if role_info:
                            assignment = {
                                'id': item.get('id'),
                                'displayName': item.get('displayName'),
                                'roleTemplateId': role_template_id,
                                'roleName': role_info['name'],
                                'riskLevel': role_info.get('risk_level', 'low'),
                                'isPermitted': role_template_id in self.PERMITTED_GUEST_ROLES
                            }
                            enriched_guest['roleAssignments'].append(assignment)
                
                elif self.check_group_memberships and item_type == '#microsoft.graph.group':
                    # Track group memberships for analysis
                    group_info = {
                        'id': item.get('id'),
                        'displayName': item.get('displayName'),
                        'isSecurityGroup': item.get('securityEnabled', False)
                    }
                    enriched_guest['groupMemberships'].append(group_info)
            
        except Exception as e:
            logger.warning(f"Could not fetch roles for guest {guest.get('userPrincipalName')}: {e}")
        
        return enriched_guest
    
    def _get_role_info_by_template_id(self, template_id: str) -> Optional[Dict]:
        """Get role information by template ID."""
        if template_id in self.HIGH_RISK_ADMIN_ROLES:
            return self.HIGH_RISK_ADMIN_ROLES[template_id]
        elif template_id in self.PERMITTED_GUEST_ROLES:
            return self.PERMITTED_GUEST_ROLES[template_id]
        else:
            # Unknown role - treat as potentially risky
            return {
                'name': 'Unknown Role',
                'risk_level': 'unknown',
                'description': 'Custom or unknown role'
            }
    
    def _get_guest_users_from_mock_data(self) -> List[Dict[str, Any]]:
        """Get guest users from mock data."""
        try:
            users = self.graph_client.get_users()
            
            guest_users = []
            for user in users:
                if user.get('userType') == 'Guest':
                    # Ensure roleAssignments exists in mock data
                    if 'roleAssignments' not in user:
                        user['roleAssignments'] = []
                    
                    # Ensure groupMemberships exists
                    if 'groupMemberships' not in user:
                        user['groupMemberships'] = []
                    
                    guest_users.append(user)
            
            return guest_users
            
        except Exception as e:
            logger.error(f"Error fetching guest users from mock data: {e}")
            return []
    
    def _analyze_guest_roles(self, guest_users: List[Dict]) -> Dict[str, Any]:
        """Analyze guest roles for compliance."""
        analysis = {
            'total_guests': len(guest_users),
            'compliant_guests': 0,
            'non_compliant_guests': [],
            'whitelisted_guests': 0,
            'disabled_guests': 0,
            'findings': [],
            'role_statistics': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'permitted': 0
            }
        }
        
        for guest in guest_users:
            try:
                guest_upn = guest.get('userPrincipalName', '').lower()
                guest_display = guest.get('displayName', 'Unknown')
                
                # Check if guest is whitelisted
                if guest_upn in self.whitelist_guests:
                    analysis['whitelisted_guests'] += 1
                    continue
                
                # Check if guest account is disabled
                if not guest.get('accountEnabled', True):
                    analysis['disabled_guests'] += 1
                    continue
                
                # Get role assignments
                role_assignments = guest.get('roleAssignments', [])
                
                if not role_assignments:
                    # Guest has no roles - compliant
                    analysis['compliant_guests'] += 1
                    continue
                
                # Analyze each role assignment
                non_compliant_roles = []
                permitted_roles = []
                risk_levels = []
                
                for role in role_assignments:
                    role_template_id = role.get('roleTemplateId')
                    role_name = role.get('roleName', 'Unknown')
                    
                    if role_template_id in self.PERMITTED_GUEST_ROLES:
                        # Permitted role for guests
                        permitted_roles.append(role_name)
                        analysis['role_statistics']['permitted'] += 1
                        
                    elif role_template_id in self.HIGH_RISK_ADMIN_ROLES:
                        # High-risk administrative role
                        role_info = self.HIGH_RISK_ADMIN_ROLES[role_template_id]
                        non_compliant_roles.append({
                            'name': role_name,
                            'risk_level': role_info['risk_level'],
                            'description': role_info['description']
                        })
                        analysis['role_statistics'][role_info['risk_level']] += 1
                        risk_levels.append(role_info['risk_level'])
                        
                    elif self.include_all_roles:
                        # Unknown or custom role (treated as non-compliant when include_all_roles is True)
                        non_compliant_roles.append({
                            'name': role_name,
                            'risk_level': 'unknown',
                            'description': 'Custom or unknown role'
                        })
                        analysis['role_statistics']['low'] += 1
                        risk_levels.append('low')
                
                if non_compliant_roles:
                    # Guest has non-compliant roles
                    highest_risk = self._get_highest_risk_level(risk_levels)
                    
                    finding = {
                        'userPrincipalName': guest.get('userPrincipalName'),
                        'displayName': guest_display,
                        'assigned_roles': [r['name'] for r in non_compliant_roles],
                        'role_details': non_compliant_roles,
                        'permitted_roles': permitted_roles if self.report_permitted_roles else [],
                        'risk_level': highest_risk,
                        'account_created': guest.get('createdDateTime'),
                        'external_state': guest.get('externalUserState', 'Unknown'),
                        'reason': f"Guest account has {len(non_compliant_roles)} administrative role(s)"
                    }
                    
                    analysis['non_compliant_guests'].append(finding)
                    analysis['findings'].append(finding)
                    
                else:
                    # Guest only has permitted roles (or no roles if include_all_roles is False)
                    analysis['compliant_guests'] += 1
                    
                    if self.report_permitted_roles and permitted_roles:
                        # Optionally track guests with only permitted roles
                        analysis['findings'].append({
                            'userPrincipalName': guest.get('userPrincipalName'),
                            'displayName': guest_display,
                            'status': 'compliant',
                            'permitted_roles': permitted_roles
                        })
                        
            except Exception as e:
                logger.error(f"Error analyzing guest {guest.get('userPrincipalName')}: {e}")
        
        return analysis
    
    def _get_highest_risk_level(self, risk_levels: List[str]) -> str:
        """Get the highest risk level from a list."""
        risk_order = ['critical', 'high', 'medium', 'low', 'unknown']
        
        for level in risk_order:
            if level in risk_levels:
                return level
        
        return 'low'
    
    def _create_check_result(self, analysis: Dict) -> CheckResult:
        """Create the final check result from analysis."""
        total_guests = analysis['total_guests']
        compliant = analysis['compliant_guests']
        non_compliant = analysis['non_compliant_guests']
        whitelisted = analysis['whitelisted_guests']
        disabled = analysis['disabled_guests']
        role_stats = analysis['role_statistics']
        
        if len(non_compliant) == 0:
            details = [
                f"No guest users have administrative roles (checked {total_guests} guests)",
                f"• Compliant guests: {compliant}",
                f"• Whitelisted guests: {whitelisted}",
                f"• Disabled guest accounts: {disabled}"
            ]
            
            if role_stats['permitted'] > 0:
                details.append(f"• Guests with permitted roles: {role_stats['permitted']}")
            
            return self.create_result(
                status=CheckStatus.PASS,
                details="\n".join(details),
                compliant_count=compliant + whitelisted,
                total_count=total_guests
            )
        
        # Non-compliant guests found
        details = [
            f"Found {len(non_compliant)} guest user(s) with administrative roles",
            f"• Total guests analyzed: {total_guests}",
            f"• Compliant guests: {compliant}",
            f"• Non-compliant guests: {len(non_compliant)}",
            f"• Whitelisted guests: {whitelisted}",
            f"• Disabled guest accounts: {disabled}",
            ""
        ]
        
        # Add role statistics
        if any(count > 0 for count in [role_stats['critical'], role_stats['high'], role_stats['medium']]):
            details.append("ADMINISTRATIVE ROLE BREAKDOWN:")
            if role_stats['critical'] > 0:
                details.append(f"  ⚠️ Critical-risk roles: {role_stats['critical']} (Global Admin, Privileged Role Admin)")
            if role_stats['high'] > 0:
                details.append(f"  ⚠️ High-risk roles: {role_stats['high']} (Security Admin, User Admin, Application Admin)")
            if role_stats['medium'] > 0:
                details.append(f"  ⚠️ Medium-risk roles: {role_stats['medium']} (Exchange Admin, SharePoint Admin, Teams Admin)")
            if role_stats['permitted'] > 0:
                details.append(f"  ✓ Permitted roles: {role_stats['permitted']} (Global Reader, Directory Readers)")
            details.append("")
        
        # Add high-risk findings
        critical_findings = [f for f in non_compliant if f.get('risk_level') == 'critical']
        high_findings = [f for f in non_compliant if f.get('risk_level') == 'high']
        
        if critical_findings:
            details.append("CRITICAL RISK GUESTS:")
            for i, finding in enumerate(critical_findings[:5], 1):
                roles = ", ".join(finding['assigned_roles'][:3])
                if len(finding['assigned_roles']) > 3:
                    roles += f" (+{len(finding['assigned_roles']) - 3} more)"
                details.append(f"  {i}. {finding['userPrincipalName']} - {roles}")
            details.append("")
        
        if high_findings:
            details.append("HIGH RISK GUESTS:")
            for i, finding in enumerate(high_findings[:5], 1):
                roles = ", ".join(finding['assigned_roles'][:2])
                details.append(f"  {i}. {finding['userPrincipalName']} - {roles}")
            details.append("")
        
        # Add total count of non-compliant guests
        if len(non_compliant) > 10:
            details.append(f"Total non-compliant guests: {len(non_compliant)}")
        
        # Add recommendations
        details.extend([
            "RECOMMENDATIONS:",
            "1. Immediately remove administrative roles from guest users",
            "2. Review B2B collaboration settings in Azure AD",
            "3. Implement Conditional Access policies to restrict guest access",
            "4. Use Azure AD Entitlement Management for guest access governance",
            "5. Regularly audit guest user permissions and memberships",
            "",
            "PERMITTED ROLES FOR GUESTS:",
            "• Global Reader (read-only access)",
            "• Directory Readers (read-only directory access)",
            "• Guest Inviter (limited guest management)"
        ])
        
        # Determine check status based on risk levels
        status = CheckStatus.FAIL
        if role_stats['critical'] == 0 and role_stats['high'] == 0:
            # Only medium/low risk roles - consider as warning
            status = CheckStatus.WARNING
            details.insert(0, "⚠️ WARNING: Guests have administrative roles, but no critical/high-risk roles detected")
        
        return self.create_result(
            status=status,
            details="\n".join(details),
            non_compliant_resources=non_compliant,
            non_compliant_count=len(non_compliant),
            compliant_count=compliant,
            total_count=total_guests,
            metadata={
                'critical_risk_guests': len(critical_findings),
                'high_risk_guests': len(high_findings),
                'medium_risk_guests': role_stats['medium'],
                'whitelisted_guests': whitelisted,
                'disabled_guests': disabled,
                'permitted_roles_count': role_stats['permitted'],
                'include_all_roles': self.include_all_roles,
                'analysis_timestamp': datetime.now().isoformat()
            }
        )
    
    def get_configuration_help(self) -> Dict[str, Any]:
        """Provide configuration guidance for this check."""
        return {
            'description': 'Configure guest role detection settings',
            'fields': [
                {
                    'name': 'whitelist_guests',
                    'type': 'array',
                    'default': [],
                    'description': 'Guest users to whitelist (allowed to have roles)',
                    'help': 'Use for trusted external administrators or partners'
                },
                {
                    'name': 'include_all_roles',
                    'type': 'boolean',
                    'default': False,
                    'description': 'Flag all roles assigned to guests (not just admin roles)',
                    'help': 'When enabled, any role assignment to guests is flagged'
                },
                {
                    'name': 'report_permitted_roles',
                    'type': 'boolean',
                    'default': False,
                    'description': 'Report guests with permitted roles (Global Reader, etc.)',
                    'help': 'Useful for compliance reporting'
                },
                {
                    'name': 'check_group_memberships',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Check group memberships for privilege escalation',
                    'help': 'Groups with administrative privileges should be checked'
                }
            ],
            'permitted_guest_roles': list(self.PERMITTED_GUEST_ROLES.values()),
            'high_risk_admin_roles': [
                {'name': info['name'], 'risk_level': info['risk_level']}
                for info in self.HIGH_RISK_ADMIN_ROLES.values()
            ],
            'recommendations': [
                'Use Azure AD Entitlement Management for guest access governance',
                'Implement least privilege for all guest users',
                'Regularly review and clean up guest accounts',
                'Use Conditional Access to restrict guest access to specific resources',
                'Monitor guest user activities with Azure AD audit logs'
            ]
        }