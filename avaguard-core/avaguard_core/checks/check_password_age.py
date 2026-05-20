from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set
import re
from enum import Enum

logger = logging.getLogger(__name__)

class PasswordAgeStatus(Enum):
    """Enum for password age status categories."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    EXEMPT = "exempt"
    EXTERNAL = "external"
    UNKNOWN = "unknown"
    ERROR = "error"

class Check_PasswordAge(BaseCheck):
    CHECK_ID = "password_age"
    TITLE = "Check for user accounts with passwords older than 90 days"
    DESCRIPTION = "Regular password rotation reduces the risk of compromised credentials"
    REQUIRES_PREMIUM = False
    
    # Configuration constants
    DEFAULT_PASSWORD_AGE_LIMIT_DAYS = 90
    PRIVILEGED_PASSWORD_AGE_LIMIT_DAYS = 60  # Stricter for privileged users
    SERVICE_ACCOUNT_AGE_LIMIT_DAYS = 365  # Longer for service accounts
    
    # NIST 800-63B recommendations
    NIST_PASSWORD_AGE_LIMIT_DAYS = 365  # NIST recommends longer or no rotation
    NIST_COMPLIANCE_MODE = False  # Set to True for NIST compliance
    
    def __init__(self, graph_client, config: Optional[Dict] = None):
        super().__init__(graph_client, config)
        self.config = config or {}
        self.password_age_limit = self.config.get('password_age_limit', 
                                                   self.NIST_PASSWORD_AGE_LIMIT_DAYS 
                                                   if self.NIST_COMPLIANCE_MODE 
                                                   else self.DEFAULT_PASSWORD_AGE_LIMIT_DAYS)
        self.strict_privileged = self.config.get('strict_privileged', True)
        self.exempt_users = set(self.config.get('exempt_users', []))
        self.exempt_patterns = self.config.get('exempt_patterns', [])
        self.service_account_patterns = self.config.get('service_account_patterns', [
            r'^svc_', r'^service_', r'_svc@', r'_service@', 
            r'serviceaccount', r'bot@', r'api@', r'automation@'
        ])
        
    def execute(self) -> CheckResult:
        """Execute the password age check."""
        logger.info(f"Executing check {self.CHECK_ID} with {self.password_age_limit} day limit")
        
        try:
            # Get users with authentication details
            users_data = self._fetch_users_with_auth_details()
            
            # Analyze password age
            analysis = self._analyze_password_age(users_data)
            
            # Generate result
            return self._create_check_result(analysis)
            
        except Exception as e:
            logger.error(f"Error executing {self.CHECK_ID}: {str(e)}", exc_info=True)
            return self.create_result(
                status=CheckStatus.ERROR,
                details=f"Error checking password age: {str(e)}",
                total_count=0
            )
    
    def _fetch_users_with_auth_details(self) -> List[Dict[str, Any]]:
        """Fetch users with authentication details from Graph API."""
        logger.info("Fetching users with authentication details...")
        
        try:
            if self._is_real_api_connection():
                # Real Azure API - use beta endpoint for signInActivity
                users = self._fetch_users_from_real_api()
            else:
                # Mock data - use standard endpoint
                users = self.graph_client.get_users()
            
            # Enrich with additional authentication data if available
            enriched_users = self._enrich_users_with_auth_data(users)
            return enriched_users
            
        except Exception as e:
            logger.error(f"Error fetching users: {e}")
            return []
    
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
    
    def _fetch_users_from_real_api(self) -> List[Dict[str, Any]]:
        """Fetch users from real Azure Graph API with authentication details."""
        users = []
        
        try:
            # Use beta endpoint for signInActivity (requires AuditLog.Read.All permission)
            beta_users_response = self.graph_client.get("/users", use_beta=True, 
                                                       params={'$select': 'id,userPrincipalName,displayName,accountEnabled,userType,'
                                                                          'lastPasswordChangeDateTime,signInActivity'})
            beta_users = beta_users_response.get('value', [])
            
            if beta_users:
                users = beta_users
            else:
                # Fallback to v1.0 endpoint
                v1_users_response = self.graph_client.get("/users", 
                                                         params={'$select': 'id,userPrincipalName,displayName,accountEnabled,userType,'
                                                                             'lastPasswordChangeDateTime'})
                users = v1_users_response.get('value', [])
            
            return users
            
        except Exception as e:
            logger.warning(f"Could not fetch from beta endpoint: {e}. Using standard endpoint.")
            # Fallback to standard endpoint
            return self.graph_client.get_users()
    
    def _enrich_users_with_auth_data(self, users: List[Dict]) -> List[Dict]:
        """Enrich users with additional authentication data."""
        enriched_users = []
        
        for user in users:
            enriched_user = user.copy()
            
            # Add privilege detection
            enriched_user['is_privileged'] = self._is_privileged_user(user)
            
            # Add service account detection
            enriched_user['is_service_account'] = self._is_service_account(user)
            
            # Add exemption status
            enriched_user['is_exempt'] = self._is_user_exempt(user)
            
            # Add external user detection
            enriched_user['is_external'] = self._is_external_user(user)
            
            # Determine password change date from multiple sources
            enriched_user['password_change_date'] = self._get_password_change_date(user)
            
            enriched_users.append(enriched_user)
        
        return enriched_users
    
    def _is_privileged_user(self, user: Dict) -> bool:
        """Determine if user is privileged."""
        # Check role assignments
        roles = user.get('roleAssignments', [])
        if roles:
            privileged_roles = ['Global Administrator', 'Privileged Role Administrator', 
                               'Security Administrator', 'User Administrator']
            for role in roles:
                if role.get('roleName') in privileged_roles:
                    return True
        
        # Check job title patterns
        job_title = user.get('jobTitle', '').lower()
        privileged_titles = ['admin', 'administrator', 'security', 'ciso', 'director', 'manager']
        if any(title in job_title for title in privileged_titles):
            return True
        
        return False
    
    def _is_service_account(self, user: Dict) -> bool:
        """Identify service accounts."""
        upn = user.get('userPrincipalName', '').lower()
        
        # Check naming patterns
        for pattern in self.service_account_patterns:
            if re.search(pattern, upn, re.IGNORECASE):
                return True
        
        # Check description for service account indicators
        description = user.get('description', '').lower()
        service_indicators = ['service account', 'automation', 'bot', 'integration', 
                             'non-interactive', 'system account']
        if any(indicator in description for indicator in service_indicators):
            return True
        
        return False
    
    def _is_user_exempt(self, user: Dict) -> bool:
        """Check if user should be exempt from password age check."""
        upn = user.get('userPrincipalName', '').lower()
        
        # Check exact UPN match
        if upn in self.exempt_users:
            return True
        
        # Check pattern matches
        for pattern in self.exempt_patterns:
            if re.match(pattern, upn, re.IGNORECASE):
                return True
        
        return False
    
    def _is_external_user(self, user: Dict) -> bool:
        """Identify external users (guests, federated, etc.)."""
        user_type = user.get('userType', '')
        
        # Guest users
        if user_type == 'Guest':
            return True
        
        # Check for external domains
        upn = user.get('userPrincipalName', '')
        if '@' in upn:
            domain = upn.split('@')[1].lower()
            # Common external domains
            external_domains = ['gmail.com', 'outlook.com', 'hotmail.com', 
                               'partner.com', 'external.com', 'vendor.com']
            if any(ext_domain in domain for ext_domain in external_domains):
                return True
        
        # Check authentication methods
        auth_methods = user.get('authenticationMethods', [])
        if auth_methods and any(method.get('type') in ['federated', 'external'] 
                                for method in auth_methods):
            return True
        
        return False
    
    def _get_password_change_date(self, user: Dict) -> Optional[datetime]:
        """Extract password change date from multiple possible fields."""
        # Try multiple date fields in order of preference
        date_fields = [
            user.get('lastPasswordChangeDateTime'),
            user.get('passwordLastChangedDateTime'),
            user.get('signInActivity', {}).get('lastPasswordChangeDateTime'),
            user.get('createdDateTime')  # Last resort - account creation date
        ]
        
        for date_str in date_fields:
            if date_str:
                try:
                    return self._parse_date_string(date_str)
                except (ValueError, TypeError):
                    continue
        
        return None
    
    def _parse_date_string(self, date_str: str) -> Optional[datetime]:
        """Parse date string from various formats."""
        try:
            if isinstance(date_str, str):
                # Remove timezone and microseconds
                date_clean = date_str.replace('Z', '').replace('z', '')
                if '.' in date_clean:
                    date_clean = date_clean.split('.')[0]
                if '+' in date_clean:
                    date_clean = date_clean.split('+')[0]
                
                return datetime.fromisoformat(date_clean)
            elif isinstance(date_str, datetime):
                return date_str
        except Exception:
            pass
        
        return None
    
    def _analyze_password_age(self, users: List[Dict]) -> Dict[str, Any]:
        """Analyze password age for all users."""
        now = datetime.now()
        
        # Initialize counters
        stats = {
            'compliant': 0,
            'non_compliant': 0,
            'exempt': 0,
            'external': 0,
            'unknown': 0,
            'error': 0,
            'total_analyzed': 0,
            'findings': []
        }
        
        for user in users:
            try:
                user_id = user.get('id', 'unknown')
                upn = user.get('userPrincipalName', 'unknown')
                
                # Skip disabled accounts
                if not user.get('accountEnabled', True):
                    stats['unknown'] += 1
                    continue
                
                # Check exemptions
                if user.get('is_exempt'):
                    stats['exempt'] += 1
                    continue
                
                # Check external users (may have different policies)
                if user.get('is_external'):
                    stats['external'] += 1
                    continue
                
                stats['total_analyzed'] += 1
                
                # Get password change date
                pwd_change_date = user.get('password_change_date')
                
                if not pwd_change_date:
                    # No password date available
                    finding = {
                        'userPrincipalName': upn,
                        'id': user_id,
                        'status': PasswordAgeStatus.UNKNOWN.value,
                        'reason': "No password change date available",
                        'days_old': None,
                        'last_change': None,
                        'user_type': user.get('userType', 'Member'),
                        'is_privileged': user.get('is_privileged', False)
                    }
                    stats['unknown'] += 1
                    stats['findings'].append(finding)
                    continue
                
                # Calculate password age
                days_old = (now - pwd_change_date).days
                
                # Determine age limit for this user
                age_limit = self._get_age_limit_for_user(user)
                
                # Check compliance
                if days_old <= age_limit:
                    stats['compliant'] += 1
                else:
                    # Non-compliant
                    finding = {
                        'userPrincipalName': upn,
                        'id': user_id,
                        'status': PasswordAgeStatus.NON_COMPLIANT.value,
                        'reason': f"Password {days_old} days old (limit: {age_limit} days)",
                        'days_old': days_old,
                        'age_limit': age_limit,
                        'last_change': pwd_change_date.strftime('%Y-%m-%d'),
                        'user_type': user.get('userType', 'Member'),
                        'is_privileged': user.get('is_privileged', False),
                        'is_service_account': user.get('is_service_account', False)
                    }
                    stats['non_compliant'] += 1
                    stats['findings'].append(finding)
                    
            except Exception as e:
                logger.error(f"Error analyzing user {user.get('id')}: {e}")
                stats['error'] += 1
        
        return stats
    
    def _get_age_limit_for_user(self, user: Dict) -> int:
        """Get password age limit for specific user type."""
        if self.NIST_COMPLIANCE_MODE:
            return self.NIST_PASSWORD_AGE_LIMIT_DAYS
        
        if user.get('is_service_account'):
            return self.SERVICE_ACCOUNT_AGE_LIMIT_DAYS
        
        if self.strict_privileged and user.get('is_privileged'):
            return self.PRIVILEGED_PASSWORD_AGE_LIMIT_DAYS
        
        return self.password_age_limit
    
    def _create_check_result(self, analysis: Dict) -> CheckResult:
        """Create the final check result from analysis."""
        compliant = analysis['compliant']
        non_compliant = analysis['non_compliant']
        exempt = analysis['exempt']
        external = analysis['external']
        unknown = analysis['unknown']
        error = analysis['error']
        total_analyzed = analysis['total_analyzed']
        findings = analysis['findings']
        
        if non_compliant == 0:
            details = [
                f"All {total_analyzed} analyzed users have compliant passwords",
                f"Compliance threshold: {self.password_age_limit} days",
                f"• Compliant users: {compliant}",
                f"• Exempt users: {exempt}",
                f"• External users: {external}",
                f"• Unknown status: {unknown}",
                f"• Analysis errors: {error}"
            ]
            
            if self.NIST_COMPLIANCE_MODE:
                details.append(f"⚠️ NIST 800-63B compliance mode enabled ({self.NIST_PASSWORD_AGE_LIMIT_DAYS} days)")
            
            return self.create_result(
                status=CheckStatus.PASS,
                details="\n".join(details),
                compliant_count=compliant,
                total_count=total_analyzed
            )
        
        # Sort findings by days old (descending)
        sorted_findings = sorted(findings, key=lambda x: x.get('days_old', 0), reverse=True)
        
        # Create detailed report
        details = [
            f"Found {non_compliant} user(s) with non-compliant passwords (> {self.password_age_limit} days)",
            f"• Total analyzed: {total_analyzed}",
            f"• Compliant users: {compliant}",
            f"• Non-compliant users: {non_compliant}",
            f"• Exempt users: {exempt}",
            f"• External users: {external}",
            f"• Unknown status: {unknown}",
            f"• Analysis errors: {error}",
            ""
        ]
        
        # Add age limit info
        if self.strict_privileged:
            details.append(f"Privileged users limit: {self.PRIVILEGED_PASSWORD_AGE_LIMIT_DAYS} days")
        details.append(f"Service accounts limit: {self.SERVICE_ACCOUNT_AGE_LIMIT_DAYS} days")
        
        if self.NIST_COMPLIANCE_MODE:
            details.append(f"⚠️ NIST 800-63B compliance mode enabled ({self.NIST_PASSWORD_AGE_LIMIT_DAYS} days)")
        
        # Add top findings
        if sorted_findings:
            details.append("\nTOP 10 OLDEST PASSWORDS:")
            for i, finding in enumerate(sorted_findings[:10], 1):
                days_old = finding.get('days_old', 0)
                is_privileged = finding.get('is_privileged', False)
                privileged_marker = " ⚠️" if is_privileged else ""
                details.append(f"  {i}. {finding['userPrincipalName']}: {days_old} days old{privileged_marker}")
        
        # Add statistics by user type
        privileged_count = sum(1 for f in sorted_findings if f.get('is_privileged'))
        service_account_count = sum(1 for f in sorted_findings if f.get('is_service_account'))
        
        if privileged_count > 0 or service_account_count > 0:
            details.append(f"\nRISK BREAKDOWN:")
            if privileged_count > 0:
                details.append(f"  • Privileged users with old passwords: {privileged_count}")
            if service_account_count > 0:
                details.append(f"  • Service accounts with old passwords: {service_account_count}")
        
        # Add recommendations
        details.extend([
            "\nRECOMMENDATIONS:",
            "1. Implement password expiration policies in Azure AD",
            "2. Consider passwordless authentication (FIDO2, Windows Hello)",
            "3. Use Conditional Access to require password reset",
            "4. Enable self-service password reset",
            "5. Monitor password age with Azure AD reporting"
        ])
        
        if self.NIST_COMPLIANCE_MODE:
            details.extend([
                "\nNIST 800-63B GUIDANCE:",
                "• Prioritize password length and complexity over frequent rotation",
                "• Implement breached password detection",
                "• Consider removing password expiration requirements"
            ])
        
        return self.create_result(
            status=CheckStatus.FAIL,
            details="\n".join(details),
            non_compliant_resources=sorted_findings,
            non_compliant_count=non_compliant,
            compliant_count=compliant,
            total_count=total_analyzed,
            metadata={
                'password_age_limit': self.password_age_limit,
                'privileged_limit': self.PRIVILEGED_PASSWORD_AGE_LIMIT_DAYS if self.strict_privileged else None,
                'exempt_users': exempt,
                'external_users': external,
                'unknown_status': unknown,
                'nist_compliance_mode': self.NIST_COMPLIANCE_MODE,
                'analysis_timestamp': datetime.now().isoformat()
            }
        )
    
    def get_configuration_help(self) -> Dict[str, Any]:
        """Provide configuration guidance for this check."""
        return {
            'description': 'Configure password age detection settings',
            'fields': [
                {
                    'name': 'password_age_limit',
                    'type': 'number',
                    'default': self.DEFAULT_PASSWORD_AGE_LIMIT_DAYS,
                    'description': 'Maximum password age in days',
                    'help': 'Standard: 90 days, NIST: 365 days or none'
                },
                {
                    'name': 'strict_privileged',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Apply stricter limit to privileged users',
                    'help': 'Privileged users get 60-day limit when enabled'
                },
                {
                    'name': 'exempt_users',
                    'type': 'array',
                    'default': [],
                    'description': 'List of user principal names to exempt',
                    'help': 'e.g., ["emergency@domain.com", "service@domain.com"]'
                },
                {
                    'name': 'exempt_patterns',
                    'type': 'array',
                    'default': [],
                    'description': 'Regex patterns for exempt users',
                    'help': 'e.g., ["^svc_.*@", ".*_bot@domain.com"]'
                },
                {
                    'name': 'service_account_patterns',
                    'type': 'array',
                    'default': self.service_account_patterns,
                    'description': 'Patterns to identify service accounts',
                    'help': 'Service accounts get 365-day limit'
                }
            ],
            'recommendations': [
                'Consider NIST 800-63B guidelines (longer or no password expiration)',
                'Implement passwordless authentication where possible',
                'Use Azure AD Password Protection with banned password lists',
                'Enable self-service password reset',
                'Monitor for password spray attacks'
            ],
            'compliance_standards': {
                'CIS': '90 days for regular users, 60 days for privileged users',
                'NIST 800-63B': 'No mandatory rotation, focus on length/complexity',
                'ISO 27001': 'Regular password changes based on risk assessment'
            }
        }
    
    def get_password_statistics(self) -> Dict[str, Any]:
        """Get password age statistics for reporting."""
        return {
            'default_limit_days': self.DEFAULT_PASSWORD_AGE_LIMIT_DAYS,
            'privileged_limit_days': self.PRIVILEGED_PASSWORD_AGE_LIMIT_DAYS,
            'service_account_limit_days': self.SERVICE_ACCOUNT_AGE_LIMIT_DAYS,
            'nist_limit_days': self.NIST_PASSWORD_AGE_LIMIT_DAYS,
            'nist_mode': self.NIST_COMPLIANCE_MODE
        }