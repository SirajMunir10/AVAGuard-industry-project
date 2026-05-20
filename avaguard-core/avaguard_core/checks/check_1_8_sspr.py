from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import re

logger = logging.getLogger(__name__)

class Check_1_8_SSPR(BaseCheck):
    CHECK_ID = "1.8"
    TITLE = "Ensure that self-service password reset is enabled"
    DESCRIPTION = "SSPR allows users to reset their own passwords"
    REQUIRES_PREMIUM = True  # Azure AD P1 required for full SSPR features
    
    # SSPR authentication methods and their security levels
    SSPR_AUTH_METHODS = {
        'mobilePhone': {
            'name': 'Mobile phone',
            'security_level': 'medium',
            'description': 'SMS or voice call to mobile phone'
        },
        'email': {
            'name': 'Alternate email',
            'security_level': 'low',
            'description': 'Email to alternate email address'
        },
        'officePhone': {
            'name': 'Office phone',
            'security_level': 'medium',
            'description': 'Voice call to office phone'
        },
        'securityQuestions': {
            'name': 'Security questions',
            'security_level': 'low',
            'description': 'Pre-defined security questions'
        },
        'appPassword': {
            'name': 'App password',
            'security_level': 'high',
            'description': 'Authenticator app notification or code'
        }
    }
    
    # Minimum recommended SSPR configuration
    MINIMUM_SSPR_CONFIG = {
        'required_methods': 2,  # Number of authentication methods required
        'min_strong_methods': 1,  # At least one medium/high security method
        'recommended_methods': ['mobilePhone', 'email', 'appPassword'],
        'exclude_security_questions': True  # Security questions are less secure
    }
    
    def __init__(self, graph_client, config: Optional[Dict] = None):
        super().__init__(graph_client, config)
        self.config = config or {}
        self.require_strong_auth = self.config.get('require_strong_auth', True)
        self.min_auth_methods = self.config.get('min_auth_methods', 2)
        self.exclude_questions = self.config.get('exclude_questions', True)
        self.check_registration = self.config.get('check_registration', True)
        self.allowed_domains = self.config.get('allowed_domains', [])
        
    def execute(self) -> CheckResult:
        """Execute SSPR configuration check."""
        try:
            logger.info(f"Executing check {self.CHECK_ID}: {self.TITLE}")
            
            # Get SSPR configuration status
            sspr_config = self._get_sspr_configuration()
            
            if not sspr_config.get('enabled'):
                return self._create_fail_result(sspr_config)
            
            # SSPR is enabled - check configuration quality
            analysis = self._analyze_sspr_configuration(sspr_config)
            
            if analysis['is_compliant']:
                return self._create_pass_result(sspr_config, analysis)
            else:
                return self._create_warning_or_fail_result(sspr_config, analysis)
            
        except Exception as e:
            logger.error(f"Error executing check {self.CHECK_ID}: {e}", exc_info=True)
            return self.create_result(
                status=CheckStatus.ERROR,
                details=f"Error checking SSPR configuration: {str(e)}",
                total_count=1
            )
    
    def _get_sspr_configuration(self) -> Dict[str, Any]:
        """Get SSPR configuration from Graph API."""
        if self._is_real_api_connection():
            return self._get_sspr_from_real_api()
        else:
            return self._get_sspr_from_mock_data()
    
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
    
    def _get_sspr_from_real_api(self) -> Dict[str, Any]:
        """Get SSPR configuration from real Azure Graph API."""
        config = {
            'enabled': False,
            'enabled_for_users': False,
            'enabled_for_admins': False,
            'authentication_methods': [],
            'number_of_methods_required': 1,
            'registration_required': False,
            'source': 'real_api',
            'errors': []
        }
        
        try:
            # Note: SSPR configuration is not directly available in Microsoft Graph v1.0
            # We need to use Azure AD Graph API or check via other indicators
            
            # Method 1: Check via organization policies (if available)
            try:
                # Try to get authentication methods policy
                auth_methods_policy = self.graph_client.get(
                    "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations"
                )
                
                methods_config = auth_methods_policy.get('value', [])
                for method in methods_config:
                    if method.get('id') == 'passwordReset':
                        config['enabled'] = method.get('state') == 'enabled'
                        break
                        
            except Exception as e:
                logger.debug(f"Could not get authentication methods policy: {e}")
                config['errors'].append('Could not retrieve authentication methods policy')
            
            # Method 2: Check user properties for SSPR indicators
            try:
                # Get a sample user to check SSPR properties
                users_response = self.graph_client.get("/users?$top=1")
                if users_response.get('value'):
                    sample_user = users_response['value'][0]
                    
                    # Check if user has password reset methods registered
                    user_id = sample_user.get('id')
                    auth_methods_response = self.graph_client.get(
                        f"/users/{user_id}/authentication/methods"
                    )
                    
                    methods = auth_methods_response.get('value', [])
                    if methods:
                        config['authentication_methods'] = [
                            method.get('@odata.type', '').replace('#microsoft.graph.', '')
                            for method in methods
                        ]
                        
            except Exception as e:
                logger.debug(f"Could not check user authentication methods: {e}")
            
            # Method 3: Check directory settings for SSPR
            try:
                # Try to get password reset policies
                directory_settings = self._get_directory_settings()
                if directory_settings:
                    config.update(directory_settings)
                    
            except Exception as e:
                logger.debug(f"Could not get directory settings: {e}")
            
            # Fallback: Check if Azure AD P1/P2 is licensed (SSPR requires P1)
            try:
                has_premium = self._check_premium_licensing()
                config['has_premium_license'] = has_premium
                if not has_premium:
                    config['errors'].append('Azure AD Premium license may be required for SSPR')
                    
            except Exception as e:
                logger.debug(f"Could not check licensing: {e}")
            
            return config
            
        except Exception as e:
            logger.error(f"Error fetching SSPR configuration from real API: {e}")
            # Return basic configuration indicating not enabled
            return {
                'enabled': False,
                'source': 'real_api_error',
                'errors': [f'API Error: {str(e)}']
            }
    
    def _get_directory_settings(self) -> Dict[str, Any]:
        """Get directory settings related to SSPR."""
        # Note: This would require specific directory settings API calls
        # For now, return empty dict
        return {}
    
    def _check_premium_licensing(self) -> bool:
        """Check if tenant has Azure AD Premium licenses."""
        try:
            # Get subscribed SKUs
            skus_response = self.graph_client.get("/subscribedSkus")
            skus = skus_response.get('value', [])
            
            # Check for Azure AD Premium P1 or P2 SKUs
            premium_skus = ['AAD_PREMIUM', 'AAD_PREMIUM_P2', 'EMSPREMIUM']
            for sku in skus:
                sku_part = sku.get('skuPartNumber', '').upper()
                if any(premium in sku_part for premium in premium_skus):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _get_sspr_from_mock_data(self) -> Dict[str, Any]:
        """Get SSPR configuration from mock data."""
        try:
            # Try to get from security settings in mock data
            if hasattr(self.graph_client, 'security'):
                security_data = self.graph_client.security
                global_settings = security_data.get('globalSettings', {})
                
                return {
                    'enabled': global_settings.get('selfServicePasswordReset', False),
                    'enabled_for_users': global_settings.get('selfServicePasswordReset', False),
                    'enabled_for_admins': True,  # Typically enabled for admins by default
                    'authentication_methods': ['mobilePhone', 'email'],  # Default methods
                    'number_of_methods_required': 2,
                    'registration_required': True,
                    'source': 'mock_data'
                }
            
            # Fallback: Check user properties
            users = self.graph_client.get_users()
            if users:
                # Check if any users have SSPR methods configured
                sspr_methods = set()
                for user in users:
                    auth_methods = user.get('authenticationMethods', [])
                    for method in auth_methods:
                        method_type = method.get('type', '')
                        if method_type in self.SSPR_AUTH_METHODS:
                            sspr_methods.add(method_type)
                
                return {
                    'enabled': len(sspr_methods) > 0,
                    'authentication_methods': list(sspr_methods),
                    'number_of_methods_required': 1,
                    'source': 'mock_data_inferred'
                }
            
            return {
                'enabled': False,
                'source': 'mock_data_no_info'
            }
            
        except Exception as e:
            logger.error(f"Error fetching SSPR configuration from mock data: {e}")
            return {
                'enabled': False,
                'source': 'mock_data_error',
                'errors': [str(e)]
            }
    
    def _analyze_sspr_configuration(self, sspr_config: Dict) -> Dict[str, Any]:
        """Analyze SSPR configuration for compliance and security."""
        analysis = {
            'is_compliant': False,
            'security_score': 0,
            'issues': [],
            'warnings': [],
            'recommendations': [],
            'method_analysis': {}
        }
        
        # Check if SSPR is enabled
        if not sspr_config.get('enabled'):
            analysis['issues'].append('SSPR is not enabled')
            return analysis
        
        # Analyze authentication methods
        auth_methods = sspr_config.get('authentication_methods', [])
        required_methods = sspr_config.get('number_of_methods_required', 1)
        
        # Method count analysis
        method_count = len(auth_methods)
        if method_count < required_methods:
            analysis['issues'].append(
                f'Only {method_count} authentication method(s) configured, '
                f'but {required_methods} required'
            )
        
        # Method security analysis
        strong_methods = 0
        weak_methods = 0
        
        for method in auth_methods:
            method_info = self.SSPR_AUTH_METHODS.get(method, {})
            security_level = method_info.get('security_level', 'unknown')
            
            analysis['method_analysis'][method] = {
                'name': method_info.get('name', method),
                'security_level': security_level,
                'description': method_info.get('description', '')
            }
            
            if security_level in ['high', 'medium']:
                strong_methods += 1
            else:
                weak_methods += 1
        
        # Check for security questions (less secure)
        if 'securityQuestions' in auth_methods and self.exclude_questions:
            analysis['warnings'].append(
                'Security questions are enabled (less secure). '
                'Consider using stronger authentication methods.'
            )
        
        # Check minimum strong methods requirement
        if self.require_strong_auth and strong_methods < self.MINIMUM_SSPR_CONFIG['min_strong_methods']:
            analysis['issues'].append(
                f'Only {strong_methods} strong authentication method(s) configured. '
                f'Minimum recommended: {self.MINIMUM_SSPR_CONFIG["min_strong_methods"]}'
            )
        
        # Calculate security score (0-100)
        max_score = 100
        score = max_score
        
        # Deductions for issues
        if method_count < required_methods:
            score -= 30
        
        if strong_methods < self.MINIMUM_SSPR_CONFIG['min_strong_methods']:
            score -= 20
        
        if 'securityQuestions' in auth_methods and self.exclude_questions:
            score -= 10
        
        analysis['security_score'] = max(0, score)
        
        # Determine if configuration is compliant
        if not analysis['issues'] and score >= 70:
            analysis['is_compliant'] = True
        
        # Generate recommendations
        if method_count < 2:
            analysis['recommendations'].append(
                'Configure at least 2 authentication methods for SSPR'
            )
        
        if strong_methods < 1:
            analysis['recommendations'].append(
                'Add at least one strong authentication method (mobile phone or authenticator app)'
            )
        
        if 'securityQuestions' in auth_methods:
            analysis['recommendations'].append(
                'Consider disabling security questions in favor of more secure methods'
            )
        
        # Add general recommendations
        analysis['recommendations'].extend([
            'Ensure all users are registered for SSPR',
            'Regularly audit SSPR usage and registration',
            'Consider implementing passwordless authentication'
        ])
        
        return analysis
    
    def _create_pass_result(self, sspr_config: Dict, analysis: Dict) -> CheckResult:
        """Create result when SSPR is properly configured."""
        auth_methods = sspr_config.get('authentication_methods', [])
        method_count = len(auth_methods)
        
        details = [
            "✅ Self-Service Password Reset is ENABLED and properly configured",
            f"Security Score: {analysis['security_score']}/100",
            "",
            "CONFIGURATION DETAILS:"
        ]
        
        # List authentication methods
        if auth_methods:
            details.append(f"Authentication methods configured ({method_count}):")
            for method in auth_methods:
                method_info = self.SSPR_AUTH_METHODS.get(method, {})
                security_level = method_info.get('security_level', 'unknown')
                security_icon = '🔒' if security_level in ['high', 'medium'] else '⚠️'
                details.append(f"  • {security_icon} {method_info.get('name', method)} "
                              f"({security_level.title()} security)")
        else:
            details.append("Authentication methods: Not specified in configuration")
        
        # Add SSPR benefits
        details.extend([
            "",
            "BENEFITS OF SSPR:",
            "• Reduced helpdesk workload for password resets",
            "• Improved user productivity (no waiting for IT support)",
            "• Enhanced security through multi-factor authentication",
            "• Available 24/7 for users in different time zones"
        ])
        
        # Add recommendations for improvement
        if analysis['security_score'] < 90:
            details.append("")
            details.append("RECOMMENDATIONS FOR IMPROVEMENT:")
            for rec in analysis.get('recommendations', [])[:3]:
                details.append(f"• {rec}")
        
        # Add best practices
        details.extend([
            "",
            "BEST PRACTICES:",
            "1. Require users to register for SSPR during initial sign-in",
            "2. Regularly review SSPR usage reports",
            "3. Consider combining with Conditional Access for risk-based policies",
            "4. Train users on SSPR process and benefits"
        ])
        
        return self.create_result(
            status=CheckStatus.PASS,
            details="\n".join(details),
            compliant_count=1,
            total_count=1,
            metadata={
                'enabled': True,
                'authentication_method_count': method_count,
                'security_score': analysis['security_score'],
                'authentication_methods': auth_methods,
                'source': sspr_config.get('source', 'unknown'),
                'check_timestamp': datetime.now().isoformat()
            }
        )
    
    def _create_warning_or_fail_result(self, sspr_config: Dict, analysis: Dict) -> CheckResult:
        """Create result when SSPR has configuration issues."""
        auth_methods = sspr_config.get('authentication_methods', [])
        method_count = len(auth_methods)
        
        # Determine severity
        has_critical_issues = len(analysis.get('issues', [])) > 0
        security_score = analysis.get('security_score', 0)
        
        if has_critical_issues or security_score < 50:
            status = CheckStatus.FAIL
            status_prefix = "❌ FAILURE:"
        else:
            status = CheckStatus.WARNING
            status_prefix = "⚠️ WARNING:"
        
        details = [
            f"{status_prefix} Self-Service Password Reset configuration needs improvement",
            f"Security Score: {security_score}/100",
            ""
        ]
        
        # Add issues
        if analysis.get('issues'):
            details.append("ISSUES FOUND:")
            for issue in analysis['issues']:
                details.append(f"• {issue}")
            details.append("")
        
        # Add warnings
        if analysis.get('warnings'):
            details.append("SECURITY WARNINGS:")
            for warning in analysis['warnings']:
                details.append(f"• ⚠️ {warning}")
            details.append("")
        
        # Add current configuration
        details.append("CURRENT CONFIGURATION:")
        details.append(f"• SSPR Enabled: {'Yes' if sspr_config.get('enabled') else 'No'}")
        details.append(f"• Authentication methods: {method_count}")
        
        if auth_methods:
            details.append("  Configured methods:")
            for method in auth_methods:
                method_info = self.SSPR_AUTH_METHODS.get(method, {})
                details.append(f"    - {method_info.get('name', method)}")
        
        # Add recommendations
        details.append("")
        details.append("RECOMMENDATIONS:")
        
        for i, rec in enumerate(analysis.get('recommendations', []), 1):
            details.append(f"{i}. {rec}")
        
        # Add Azure AD requirements
        details.extend([
            "",
            "AZURE AD REQUIREMENTS:",
            "• Azure AD Premium P1 or higher required for SSPR",
            "• Users must register authentication methods before using SSPR",
            "• Consider hybrid deployment for on-premises password writeback"
        ])
        
        # Add configuration steps
        details.extend([
            "",
            "CONFIGURATION STEPS:",
            "1. Azure Portal → Azure Active Directory → Password reset",
            "2. Set 'Self service password reset enabled' to 'All' or 'Selected'",
            "3. Configure authentication methods (minimum 2 recommended)",
            "4. Configure registration policy (require users to register)",
            "5. Configure notifications (notify users and admins of password resets)",
            "6. Test SSPR with a pilot group before enabling for all users"
        ])
        
        return self.create_result(
            status=status,
            details="\n".join(details),
            non_compliant_resources=[{
                'policy': 'Self-Service Password Reset',
                'status': 'Enabled but misconfigured',
                'security_score': security_score,
                'authentication_methods': auth_methods,
                'issues': analysis.get('issues', []),
                'warnings': analysis.get('warnings', [])
            }],
            non_compliant_count=1,
            total_count=1,
            metadata={
                'enabled': sspr_config.get('enabled', False),
                'security_score': security_score,
                'issue_count': len(analysis.get('issues', [])),
                'warning_count': len(analysis.get('warnings', [])),
                'authentication_method_count': method_count,
                'source': sspr_config.get('source', 'unknown'),
                'check_timestamp': datetime.now().isoformat()
            }
        )
    
    def _create_fail_result(self, sspr_config: Dict) -> CheckResult:
        """Create result when SSPR is not enabled."""
        details = [
            "❌ FAILURE: Self-Service Password Reset is DISABLED",
            "",
            "IMPACT OF DISABLED SSPR:",
            "• Increased helpdesk workload for password resets",
            "• Reduced user productivity during password issues",
            "• Potential security risks from password sharing",
            "• Limited user self-service capabilities"
        ]
        
        # Add errors from configuration retrieval if any
        errors = sspr_config.get('errors', [])
        if errors:
            details.append("")
            details.append("CONFIGURATION ERRORS:")
            for error in errors:
                details.append(f"• {error}")
        
        # Add licensing check
        if sspr_config.get('has_premium_license') is False:
            details.append("")
            details.append("⚠️ LICENSING NOTE: Azure AD Premium P1 or higher is required for SSPR")
        
        # Add recommendations
        details.extend([
            "",
            "RECOMMENDATIONS:",
            "1. ENABLE SSPR IMMEDIATELY:",
            "   • Azure Portal → Azure Active Directory → Password reset",
            "   • Set 'Self service password reset enabled' to 'All'",
            "",
            "2. CONFIGURE AUTHENTICATION METHODS:",
            "   • Require at least 2 methods for security",
            "   • Include at least one strong method (mobile phone or authenticator app)",
            "   • Consider excluding security questions (less secure)",
            "",
            "3. IMPLEMENT REGISTRATION POLICY:",
            "   • Require users to register methods on next sign-in",
            "   • Use Conditional Access to require registration",
            "   • Send reminders for unregistered users",
            "",
            "4. TEST AND ROLLOUT:",
            "   • Start with a pilot group of IT staff",
            "   • Gradually expand to all users",
            "   • Monitor usage and adjust as needed"
        ])
        
        return self.create_result(
            status=CheckStatus.FAIL,
            details="\n".join(details),
            non_compliant_resources=[{
                'policy': 'Self-Service Password Reset',
                'status': 'Disabled',
                'errors': errors
            }],
            non_compliant_count=1,
            total_count=1,
            metadata={
                'enabled': False,
                'errors': errors,
                'has_premium_license': sspr_config.get('has_premium_license'),
                'source': sspr_config.get('source', 'unknown'),
                'check_timestamp': datetime.now().isoformat()
            }
        )
    
    def get_configuration_help(self) -> Dict[str, Any]:
        """Provide configuration guidance for this check."""
        return {
            'description': 'Configure SSPR check settings',
            'fields': [
                {
                    'name': 'require_strong_auth',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Require strong authentication methods',
                    'help': 'Require at least one medium/high security method (mobile phone, authenticator app)'
                },
                {
                    'name': 'min_auth_methods',
                    'type': 'number',
                    'default': 2,
                    'description': 'Minimum number of authentication methods required',
                    'help': 'Microsoft recommends at least 2 methods for SSPR'
                },
                {
                    'name': 'exclude_questions',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Flag security questions as insecure',
                    'help': 'Security questions are considered less secure than other methods'
                },
                {
                    'name': 'check_registration',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Check user registration status',
                    'help': 'Verify users have registered SSPR methods (may require additional API permissions)'
                }
            ],
            'authentication_methods': self.SSPR_AUTH_METHODS,
            'minimum_configuration': self.MINIMUM_SSPR_CONFIG,
            'recommendations': [
                'Enable SSPR for all users to reduce helpdesk workload',
                'Require at least 2 authentication methods for security',
                'Include strong methods like mobile phone or authenticator app',
                'Consider implementing password writeback for hybrid environments',
                'Regularly review SSPR usage and registration reports'
            ]
        }