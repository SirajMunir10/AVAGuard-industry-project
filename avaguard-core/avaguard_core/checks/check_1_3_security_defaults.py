from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class Check_1_3_SecurityDefaults(BaseCheck):
    CHECK_ID = "1.3"
    TITLE = "Ensure that Security Defaults is enabled"
    DESCRIPTION = "Security defaults provide basic identity security posture"
    REQUIRES_PREMIUM = False
    
    # Security Defaults capabilities (what it enables when turned on)
    SECURITY_DEFAULTS_CAPABILITIES = {
        'require_mfa_admins': {
            'description': 'Require MFA for all administrators',
            'risk_reduction': 'high'
        },
        'require_mfa_users': {
            'description': 'Require MFA for all users when necessary',
            'risk_reduction': 'medium'
        },
        'block_legacy_auth': {
            'description': 'Block legacy authentication protocols',
            'risk_reduction': 'high'
        },
        'protect_privileged_actions': {
            'description': 'Require MFA for privileged Azure AD tasks',
            'risk_reduction': 'high'
        },
        'registration_campaign': {
            'description': 'Register users for MFA',
            'risk_reduction': 'medium'
        }
    }
    
    # Equivalent Conditional Access policies (if Security Defaults is disabled)
    EQUIVALENT_CA_POLICIES = [
        {
            'name': 'Block legacy authentication',
            'priority': 1,
            'state': 'enabled',
            'description': 'Blocks older auth protocols like IMAP, POP3, SMTP'
        },
        {
            'name': 'Require MFA for admins',
            'priority': 2,
            'state': 'enabled',
            'description': 'Requires MFA for all admin roles'
        },
        {
            'name': 'Require MFA for all users',
            'priority': 3,
            'state': 'enabled',
            'description': 'Requires MFA when sign-in risk is detected'
        }
    ]
    
    def __init__(self, graph_client, config: Optional[Dict] = None):
        super().__init__(graph_client, config)
        self.config = config or {}
        self.check_equivalent_policies = self.config.get('check_equivalent_policies', True)
        self.allow_custom_policies = self.config.get('allow_custom_policies', False)
        self.require_mfa_for_all = self.config.get('require_mfa_for_all', False)
        
    def execute(self) -> CheckResult:
        """Execute Security Defaults check."""
        try:
            logger.info(f"Executing check {self.CHECK_ID}: {self.TITLE}")
            
            # Get Security Defaults status
            security_defaults_status = self._get_security_defaults_status()
            
            if security_defaults_status['is_enabled']:
                return self._create_pass_result(security_defaults_status)
            
            # Security Defaults is disabled - check for equivalent policies
            analysis = self._analyze_security_posture(security_defaults_status)
            
            return self._create_fail_or_warning_result(analysis)
            
        except Exception as e:
            logger.error(f"Error executing check {self.CHECK_ID}: {e}", exc_info=True)
            return self.create_result(
                status=CheckStatus.ERROR,
                details=f"Error checking Security Defaults: {str(e)}",
                total_count=1
            )
    
    def _get_security_defaults_status(self) -> Dict[str, Any]:
        """Get Security Defaults status from Graph API."""
        if self._is_real_api_connection():
            return self._get_security_defaults_from_real_api()
        else:
            return self._get_security_defaults_from_mock_data()
    
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
    
    def _get_security_defaults_from_real_api(self) -> Dict[str, Any]:
        """Get Security Defaults status from real Azure Graph API."""
        try:
            # Get Identity Security Defaults Enforcement Policy
            policy_response = self.graph_client.get(
                "/policies/identitySecurityDefaultsEnforcementPolicy"
            )
            
            is_enabled = policy_response.get('isEnabled', False)
            description = policy_response.get('description', 'Security Defaults policy')
            
            # Get additional context about the tenant
            try:
                # Check if tenant has Azure AD Premium licenses (which might justify disabling Security Defaults)
                tenant_details = self._get_tenant_context()
            except Exception as e:
                logger.debug(f"Could not get tenant context: {e}")
                tenant_details = {}
            
            return {
                'is_enabled': is_enabled,
                'policy_name': 'Security Defaults',
                'description': description,
                'last_modified': policy_response.get('modifiedDateTime'),
                'tenant_context': tenant_details,
                'source': 'real_api'
            }
            
        except Exception as e:
            logger.error(f"Error fetching Security Defaults from real API: {e}")
            # Fallback to checking via mock method
            return self._get_security_defaults_from_mock_data()
    
    def _get_tenant_context(self) -> Dict[str, Any]:
        """Get tenant context for better recommendations."""
        context = {
            'has_premium_licenses': False,
            'has_conditional_access': False,
            'mfa_enabled_users': 0
        }
        
        try:
            # Check organization details for premium features
            org_response = self.graph_client.get("/organization")
            if org_response.get('value'):
                org = org_response['value'][0]
                context['tenant_name'] = org.get('displayName')
                context['tenant_id'] = org.get('id')
            
            # Check for Conditional Access policies (requires P1/P2)
            ca_policies_response = self.graph_client.get("/identity/conditionalAccess/policies")
            ca_policies = ca_policies_response.get('value', [])
            
            if ca_policies:
                context['has_conditional_access'] = True
                context['ca_policy_count'] = len(ca_policies)
                enabled_ca_policies = [p for p in ca_policies if p.get('state') == 'enabled']
                context['enabled_ca_policy_count'] = len(enabled_ca_policies)
            
        except Exception as e:
            logger.debug(f"Could not gather full tenant context: {e}")
        
        return context
    
    def _get_security_defaults_from_mock_data(self) -> Dict[str, Any]:
        """Get Security Defaults status from mock data."""
        try:
            policy = self.graph_client.get_identity_protection_policy("securityDefaults")
            
            return {
                'is_enabled': policy.get('isEnabled', False),
                'policy_name': policy.get('displayName', 'Security Defaults'),
                'description': policy.get('description', 'Basic security settings'),
                'source': 'mock_data'
            }
            
        except Exception as e:
            logger.error(f"Error fetching Security Defaults from mock data: {e}")
            return {
                'is_enabled': False,
                'policy_name': 'Security Defaults',
                'description': 'Error fetching policy',
                'source': 'error'
            }
    
    def _analyze_security_posture(self, security_defaults_status: Dict) -> Dict[str, Any]:
        """Analyze overall security posture when Security Defaults is disabled."""
        analysis = {
            'security_defaults_enabled': False,
            'equivalent_policies_found': False,
            'ca_policy_details': [],
            'security_gaps': [],
            'recommendations': [],
            'risk_level': 'high'
        }
        
        # Check for equivalent Conditional Access policies
        if self.check_equivalent_policies:
            ca_coverage = self._check_conditional_access_coverage()
            analysis['ca_policy_details'] = ca_coverage.get('policies', [])
            analysis['equivalent_policies_found'] = ca_coverage.get('has_coverage', False)
            
            if analysis['equivalent_policies_found']:
                analysis['risk_level'] = 'medium'
                analysis['recommendations'].append(
                    "Consider enabling Security Defaults for simpler management, " +
                    "or ensure all equivalent policies are properly configured."
                )
            else:
                analysis['security_gaps'].extend([
                    "No MFA enforcement for administrators",
                    "Legacy authentication protocols not blocked",
                    "No baseline MFA registration campaign"
                ])
                analysis['recommendations'].append(
                    "Immediately enable Security Defaults or configure equivalent " +
                    "Conditional Access policies."
                )
        
        # Check MFA adoption if possible
        try:
            mfa_stats = self._get_mfa_adoption_stats()
            analysis['mfa_adoption'] = mfa_stats
            
            if mfa_stats.get('admin_mfa_rate', 0) < 90:
                analysis['security_gaps'].append(f"Low MFA adoption for admins: {mfa_stats.get('admin_mfa_rate', 0)}%")
            
            if mfa_stats.get('overall_mfa_rate', 0) < 50:
                analysis['security_gaps'].append(f"Low overall MFA adoption: {mfa_stats.get('overall_mfa_rate', 0)}%")
                
        except Exception as e:
            logger.debug(f"Could not get MFA adoption stats: {e}")
        
        return analysis
    
    def _check_conditional_access_coverage(self) -> Dict[str, Any]:
        """Check if equivalent Conditional Access policies exist."""
        coverage = {
            'has_coverage': False,
            'policies': [],
            'coverage_score': 0
        }
        
        try:
            # Get Conditional Access policies
            ca_policies_response = self.graph_client.get("/identity/conditionalAccess/policies")
            ca_policies = ca_policies_response.get('value', [])
            
            if not ca_policies:
                return coverage
            
            # Define what we're looking for
            required_coverage = {
                'block_legacy_auth': False,
                'mfa_for_admins': False,
                'mfa_risk_based': False
            }
            
            for policy in ca_policies:
                if policy.get('state') != 'enabled':
                    continue
                
                policy_name = policy.get('displayName', 'Unnamed Policy')
                policy_details = {
                    'name': policy_name,
                    'state': policy.get('state'),
                    'conditions': policy.get('conditions', {}),
                    'grantControls': policy.get('grantControls', {})
                }
                
                # Check for legacy auth blocking
                if self._policy_blocks_legacy_auth(policy):
                    required_coverage['block_legacy_auth'] = True
                    policy_details['covers'] = 'Blocks legacy authentication'
                
                # Check for MFA for admins
                if self._policy_requires_mfa_for_admins(policy):
                    required_coverage['mfa_for_admins'] = True
                    policy_details['covers'] = 'Requires MFA for administrators'
                
                # Check for risk-based MFA
                if self._policy_requires_risk_based_mfa(policy):
                    required_coverage['mfa_risk_based'] = True
                    policy_details['covers'] = 'Requires MFA based on risk'
                
                coverage['policies'].append(policy_details)
            
            # Calculate coverage score
            coverage_items = list(required_coverage.values())
            coverage_score = sum(1 for item in coverage_items if item) / len(coverage_items) * 100
            coverage['coverage_score'] = coverage_score
            coverage['has_coverage'] = coverage_score >= 80  # 80% coverage threshold
            
            return coverage
            
        except Exception as e:
            logger.error(f"Error checking Conditional Access coverage: {e}")
            return coverage
    
    def _policy_blocks_legacy_auth(self, policy: Dict) -> bool:
        """Check if policy blocks legacy authentication."""
        conditions = policy.get('conditions', {})
        client_app_types = conditions.get('clientAppTypes', [])
        
        # Check for legacy auth client types
        legacy_types = ['exchangeActiveSync', 'other']
        return any(client_type in legacy_types for client_type in client_app_types)
    
    def _policy_requires_mfa_for_admins(self, policy: Dict) -> bool:
        """Check if policy requires MFA for administrators."""
        conditions = policy.get('conditions', {})
        users = conditions.get('users', {})
        include_roles = users.get('includeRoles', [])
        
        # Check if includes admin roles
        admin_roles = ['Global Administrator', 'Privileged Role Administrator', 
                      'Security Administrator', 'User Administrator']
        
        if any(role in include_roles for role in admin_roles):
            grant_controls = policy.get('grantControls', {})
            built_in_controls = grant_controls.get('builtInControls', [])
            return 'mfa' in built_in_controls
        
        return False
    
    def _policy_requires_risk_based_mfa(self, policy: Dict) -> bool:
        """Check if policy requires MFA based on risk."""
        conditions = policy.get('conditions', {})
        sign_in_risk = conditions.get('signInRiskLevels', [])
        
        if sign_in_risk:
            grant_controls = policy.get('grantControls', {})
            built_in_controls = grant_controls.get('builtInControls', [])
            return 'mfa' in built_in_controls
        
        return False
    
    def _get_mfa_adoption_stats(self) -> Dict[str, Any]:
        """Get MFA adoption statistics if possible."""
        stats = {
            'overall_mfa_rate': 0,
            'admin_mfa_rate': 0,
            'user_count': 0,
            'mfa_registered_count': 0
        }
        
        try:
            # This is a simplified version - real implementation would need
            # to query MFA registration data
            if self._is_real_api_connection():
                # Real API would use /reports/authenticationMethods/userRegistrationDetails
                pass
            
            # For mock data, check user properties
            users = self.graph_client.get_users()
            if users:
                total_users = len(users)
                mfa_users = sum(1 for u in users if u.get('isMfaRegistered', False))
                admin_users = [u for u in users if u.get('isPrivileged', False)]
                admin_mfa_users = sum(1 for u in admin_users if u.get('isMfaRegistered', False))
                
                stats['user_count'] = total_users
                stats['mfa_registered_count'] = mfa_users
                stats['overall_mfa_rate'] = (mfa_users / total_users * 100) if total_users > 0 else 0
                stats['admin_mfa_rate'] = (admin_mfa_users / len(admin_users) * 100) if admin_users else 0
        
        except Exception as e:
            logger.debug(f"Could not calculate MFA adoption: {e}")
        
        return stats
    
    def _create_pass_result(self, security_defaults_status: Dict) -> CheckResult:
        """Create result when Security Defaults is enabled."""
        details = [
            "✅ Security Defaults are ENABLED",
            "",
            "SECURITY BENEFITS PROVIDED:"
        ]
        
        # List security benefits
        for key, capability in self.SECURITY_DEFAULTS_CAPABILITIES.items():
            details.append(f"• {capability['description']} (Risk reduction: {capability['risk_reduction'].title()})")
        
        details.extend([
            "",
            "RECOMMENDATIONS:",
            "1. Review Security Defaults settings periodically",
            "2. Monitor MFA registration and adoption rates",
            "3. Consider upgrading to Azure AD P1/P2 for more granular controls",
            "4. Review Conditional Access reports for any blocked sign-ins"
        ])
        
        # Add additional context if available
        if security_defaults_status.get('tenant_context', {}).get('has_conditional_access'):
            details.append("")
            details.append("⚠️ NOTE: Tenant has Conditional Access policies. " +
                         "Consider whether Security Defaults or custom policies better fit your needs.")
        
        return self.create_result(
            status=CheckStatus.PASS,
            details="\n".join(details),
            compliant_count=1,
            total_count=1,
            metadata={
                'policy_name': security_defaults_status.get('policy_name'),
                'last_modified': security_defaults_status.get('last_modified'),
                'source': security_defaults_status.get('source'),
                'check_timestamp': datetime.now().isoformat()
            }
        )
    
    def _create_fail_or_warning_result(self, analysis: Dict) -> CheckResult:
        """Create result when Security Defaults is disabled."""
        # Determine if this should be a warning or failure
        if analysis.get('equivalent_policies_found') and self.allow_custom_policies:
            status = CheckStatus.WARNING
            status_prefix = "⚠️ WARNING:"
        else:
            status = CheckStatus.FAIL
            status_prefix = "❌ FAILURE:"
        
        details = [
            f"{status_prefix} Security Defaults are DISABLED",
            f"Risk Level: {analysis.get('risk_level', 'high').upper()}",
            ""
        ]
        
        # Add security gap analysis
        if analysis.get('security_gaps'):
            details.append("SECURITY GAPS IDENTIFIED:")
            for gap in analysis['security_gaps']:
                details.append(f"• {gap}")
            details.append("")
        
        # Add Conditional Access coverage if checked
        if self.check_equivalent_policies and analysis.get('ca_policy_details'):
            details.append("CONDITIONAL ACCESS POLICIES FOUND:")
            for policy in analysis['ca_policy_details'][:5]:  # Show top 5
                covers = policy.get('covers', 'Unknown coverage')
                details.append(f"• {policy['name']} - {covers}")
            
            coverage_score = analysis.get('ca_policy_details', [{}])[0].get('coverage_score', 0)
            if coverage_score > 0:
                details.append(f"  Coverage Score: {coverage_score:.1f}%")
            details.append("")
        
        # Add MFA adoption if available
        if analysis.get('mfa_adoption'):
            mfa_stats = analysis['mfa_adoption']
            details.append("MFA ADOPTION STATISTICS:")
            details.append(f"• Overall MFA adoption: {mfa_stats.get('overall_mfa_rate', 0):.1f}%")
            details.append(f"• Admin MFA adoption: {mfa_stats.get('admin_mfa_rate', 0):.1f}%")
            details.append("")
        
        # Add recommendations
        details.append("RECOMMENDATIONS:")
        
        if analysis.get('equivalent_policies_found') and self.allow_custom_policies:
            details.extend([
                "1. Review existing Conditional Access policies for completeness",
                "2. Ensure all critical security controls are covered:",
                "   • Block legacy authentication protocols",
                "   • Require MFA for all administrators",
                "   • Require MFA based on sign-in risk",
                "3. Document the business justification for custom policies",
                "4. Regularly audit policy effectiveness"
            ])
        else:
            details.extend([
                "1. ENABLE SECURITY DEFAULTS IMMEDIATELY:",
                "   • Azure Portal → Azure Active Directory → Properties",
                "   • Click 'Manage Security defaults'",
                "   • Set to 'Enabled'",
                "",
                "2. If Security Defaults cannot be enabled, configure equivalent policies:",
                "   • Create Conditional Access policy to block legacy auth",
                "   • Create policy requiring MFA for all admin roles",
                "   • Implement risk-based MFA policies",
                "",
                "3. Monitor implementation with Azure AD security reports"
            ])
        
        # Add Azure AD Premium consideration
        details.extend([
            "",
            "AZURE AD PREMIUM CONSIDERATION:",
            "• Security Defaults is free for all tenants",
            "• Azure AD P1/P2 provides more granular Conditional Access controls",
            "• Consider upgrading if you need more flexible policy management"
        ])
        
        return self.create_result(
            status=status,
            details="\n".join(details),
            non_compliant_resources=[{
                'policy': 'Security Defaults',
                'status': 'Disabled',
                'risk_level': analysis.get('risk_level', 'high'),
                'equivalent_coverage': analysis.get('equivalent_policies_found', False)
            }],
            non_compliant_count=1,
            total_count=1,
            metadata={
                'risk_level': analysis.get('risk_level', 'high'),
                'equivalent_policies_found': analysis.get('equivalent_policies_found', False),
                'security_gaps_count': len(analysis.get('security_gaps', [])),
                'mfa_adoption_rate': analysis.get('mfa_adoption', {}).get('overall_mfa_rate', 0),
                'check_timestamp': datetime.now().isoformat()
            }
        )
    
    def get_configuration_help(self) -> Dict[str, Any]:
        """Provide configuration guidance for this check."""
        return {
            'description': 'Configure Security Defaults check settings',
            'fields': [
                {
                    'name': 'check_equivalent_policies',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Check for equivalent Conditional Access policies',
                    'help': 'When enabled, checks if custom policies provide equivalent security'
                },
                {
                    'name': 'allow_custom_policies',
                    'type': 'boolean',
                    'default': False,
                    'description': 'Allow custom Conditional Access as equivalent to Security Defaults',
                    'help': 'When enabled, custom policies may result in WARNING instead of FAIL'
                },
                {
                    'name': 'require_mfa_for_all',
                    'type': 'boolean',
                    'default': False,
                    'description': 'Require MFA for all users (not just risk-based)',
                    'help': 'Stricter requirement than Security Defaults'
                }
            ],
            'security_defaults_capabilities': self.SECURITY_DEFAULTS_CAPABILITIES,
            'recommendations': [
                'Enable Security Defaults for all tenants without Azure AD Premium',
                'If using custom Conditional Access, ensure all Security Defaults capabilities are covered',
                'Regularly review and test security policies',
                'Monitor Azure AD security reports for policy effectiveness'
            ]
        }