from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import re

logger = logging.getLogger(__name__)

class Check_InactiveUsers(BaseCheck):
    CHECK_ID = "inactive_users"
    TITLE = "Check for user accounts inactive for 90+ days"
    DESCRIPTION = "Identify enabled accounts that haven't signed in recently"
    REQUIRES_PREMIUM = True
    
    # Configuration constants
    INACTIVITY_THRESHOLD_DAYS = 90
    SIGNIN_ACTIVITY_URL = "/reports/getCredentialUserRegistrationDetails"
    
    def __init__(self, graph_client, config: Optional[Dict] = None):
        super().__init__(graph_client, config)
        self.config = config or {}
        self.inactivity_days = self.config.get('inactivity_days', self.INACTIVITY_THRESHOLD_DAYS)
        
    def execute(self) -> CheckResult:
        """Execute the inactive users check."""
        logger.info(f"Executing check {self.CHECK_ID} with {self.inactivity_days} day threshold")
        
        try:
            # Get users from Graph API
            users = self._fetch_users_with_signin_activity()
            
            # Analyze inactivity
            analysis = self._analyze_user_inactivity(users)
            
            # Generate result
            return self._create_check_result(analysis)
            
        except Exception as e:
            logger.error(f"Error executing {self.CHECK_ID}: {str(e)}", exc_info=True)
            return self.create_result(
                status=CheckStatus.ERROR,
                details=f"Error checking inactive users: {str(e)}",
                total_count=0
            )
    
    def _fetch_users_with_signin_activity(self) -> List[Dict[str, Any]]:
        """Fetch users with their sign-in activity data."""
        logger.info("Fetching users with sign-in activity...")
        
        # Try to get comprehensive sign-in data from reports API
        users_with_activity = []
        
        try:
            # For real Azure API, use the reports endpoint
            if self._is_real_api_connection():
                users_with_activity = self._fetch_users_from_reports_api()
            else:
                # For mock data, use regular users endpoint
                users_with_activity = self.graph_client.get_users()
                
        except Exception as e:
            logger.warning(f"Could not fetch from reports API: {e}. Falling back to basic user data.")
            users_with_activity = self.graph_client.get_users()
        
        return users_with_activity
    
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
    
    def _fetch_users_from_reports_api(self) -> List[Dict[str, Any]]:
        """Fetch users with sign-in activity from Microsoft Graph Reports API."""
        users_data = []
        
        try:
            # Get credential user registration details (includes last sign-in)
            registration_details = self.graph_client.get(self.SIGNIN_ACTIVITY_URL)
            
            if registration_details and 'value' in registration_details:
                for user_detail in registration_details['value']:
                    user_data = {
                        'id': user_detail.get('id'),
                        'userPrincipalName': user_detail.get('userPrincipalName'),
                        'accountEnabled': True,  # Reports API doesn't include this, assume enabled
                        'signInActivity': {
                            'lastSignInDateTime': user_detail.get('lastSignInDateTime'),
                            'isMfaRegistered': user_detail.get('isMfaRegistered', False)
                        }
                    }
                    users_data.append(user_data)
            
            # Also get basic user info to merge
            basic_users = self.graph_client.get_users()
            
            # Merge data
            merged_users = self._merge_user_data(basic_users, users_data)
            return merged_users
            
        except Exception as e:
            logger.warning(f"Reports API failed: {e}. Using basic user data.")
            return self.graph_client.get_users()
    
    def _merge_user_data(self, basic_users: List[Dict], detailed_users: List[Dict]) -> List[Dict]:
        """Merge basic user data with detailed sign-in activity."""
        user_map = {u.get('userPrincipalName', '').lower(): u for u in basic_users}
        
        merged = []
        for detail in detailed_users:
            upn = detail.get('userPrincipalName', '').lower()
            if upn in user_map:
                # Merge sign-in activity into basic user data
                user = user_map[upn].copy()
                user['signInActivity'] = detail.get('signInActivity', {})
                merged.append(user)
            else:
                # Use detailed data as is
                merged.append(detail)
        
        # Add any basic users not in detailed data
        for upn, user in user_map.items():
            if not any(u.get('userPrincipalName', '').lower() == upn for u in merged):
                merged.append(user)
        
        return merged
    
    def _analyze_user_inactivity(self, users: List[Dict]) -> Dict[str, Any]:
        """Analyze users for inactivity."""
        limit_date = datetime.now() - timedelta(days=self.inactivity_days)
        
        inactive_users = []
        active_count = 0
        disabled_count = 0
        service_accounts = 0
        exempt_users = 0
        skipped_count = 0
        
        # Get exemption list from config
        exempt_upns = set(self.config.get('exempt_users', []))
        exempt_patterns = self.config.get('exempt_patterns', [])
        
        for user in users:
            # Skip if user object is invalid
            if not isinstance(user, dict):
                skipped_count += 1
                continue
            
            user_id = user.get('id', 'unknown')
            upn = user.get('userPrincipalName', 'unknown').lower()
            
            # Check if user is exempt
            if self._is_user_exempt(upn, exempt_upns, exempt_patterns, user):
                exempt_users += 1
                continue
            
            # Check if account is disabled
            if not user.get('accountEnabled', True):
                disabled_count += 1
                continue
            
            # Check if service account (based on naming convention or attributes)
            if self._is_service_account(upn, user):
                service_accounts += 1
                continue
            
            # Get last sign-in date
            last_signin = self._get_last_signin_date(user)
            
            if last_signin is None:
                # No sign-in data available
                user_info = {
                    'userPrincipalName': upn,
                    'id': user_id,
                    'reason': "No sign-in data available",
                    'lastSignIn': None,
                    'daysInactive': None
                }
                inactive_users.append(user_info)
                
            elif last_signin < limit_date:
                # User is inactive
                days_inactive = (datetime.now() - last_signin).days
                user_info = {
                    'userPrincipalName': upn,
                    'id': user_id,
                    'reason': f"Inactive for {days_inactive} days (Last: {last_signin.strftime('%Y-%m-%d')})",
                    'lastSignIn': last_signin.strftime('%Y-%m-%d'),
                    'daysInactive': days_inactive
                }
                inactive_users.append(user_info)
                
            else:
                # User is active
                active_count += 1
        
        return {
            'inactive_users': inactive_users,
            'active_count': active_count,
            'disabled_count': disabled_count,
            'service_accounts': service_accounts,
            'exempt_users': exempt_users,
            'skipped_count': skipped_count,
            'total_checked': len(users)
        }
    
    def _is_user_exempt(self, upn: str, exempt_upns: set, 
                        exempt_patterns: List[str], user: Dict) -> bool:
        """Check if user should be exempt from inactivity check."""
        # Check exact UPN match
        if upn in exempt_upns:
            return True
        
        # Check pattern matches
        for pattern in exempt_patterns:
            if re.match(pattern, upn, re.IGNORECASE):
                return True
        
        # Check user attributes for exemption
        user_type = user.get('userType', '')
        job_title = user.get('jobTitle', '').lower()
        
        # Exempt external/guest users
        if user_type in ['Guest', 'External']:
            return True
        
        # Exempt based on job title (e.g., service accounts, break-glass)
        exempt_titles = ['break-glass', 'emergency', 'service account', 'bot', 'api']
        if any(exempt in job_title for exempt in exempt_titles):
            return True
        
        return False
    
    def _is_service_account(self, upn: str, user: Dict) -> bool:
        """Identify service accounts based on naming conventions and attributes."""
        # Common service account naming patterns
        service_patterns = [
            r'^svc_',
            r'^service_',
            r'_svc@',
            r'_service@',
            r'serviceaccount',
            r'bot@',
            r'api@',
            r'integration@',
            r'automation@'
        ]
        
        # Check naming patterns
        for pattern in service_patterns:
            if re.search(pattern, upn, re.IGNORECASE):
                return True
        
        # Check user attributes
        if user.get('userType') == 'Service':
            return True
        
        # Check description for service account indicators
        description = user.get('description', '').lower()
        service_indicators = ['service account', 'automation', 'bot', 'integration', 'non-interactive']
        if any(indicator in description for indicator in service_indicators):
            return True
        
        return False
    
    def _get_last_signin_date(self, user: Dict) -> Optional[datetime]:
        """Extract and parse last sign-in date from user data."""
        # Try multiple possible date fields
        date_sources = [
            user.get('signInActivity', {}).get('lastSignInDateTime'),
            user.get('lastSignInDateTime'),
            user.get('lastSuccessfulSignInDateTime'),
            user.get('createdDateTime')  # Fallback to account creation
        ]
        
        for date_str in date_sources:
            if date_str:
                try:
                    # Clean and parse ISO date string
                    if isinstance(date_str, str):
                        # Remove timezone info and microseconds
                        date_clean = date_str.replace('Z', '').replace('z', '')
                        if '.' in date_clean:
                            date_clean = date_clean.split('.')[0]
                        
                        # Handle different ISO formats
                        return datetime.fromisoformat(date_clean)
                    elif isinstance(date_str, datetime):
                        return date_str
                        
                except (ValueError, AttributeError) as e:
                    logger.debug(f"Could not parse date '{date_str}' for user {user.get('id')}: {e}")
                    continue
        
        return None
    
    def _create_check_result(self, analysis: Dict) -> CheckResult:
        """Create the final check result from analysis."""
        inactive_users = analysis['inactive_users']
        active_count = analysis['active_count']
        disabled_count = analysis['disabled_count']
        service_accounts = analysis['service_accounts']
        exempt_users = analysis['exempt_users']
        skipped_count = analysis['skipped_count']
        total_checked = analysis['total_checked']
        
        # Calculate effective total (excluding exempt and disabled)
        effective_total = total_checked - exempt_users - disabled_count - service_accounts - skipped_count
        
        if not inactive_users:
            details = [
                f"No inactive accounts found (checked {effective_total} enabled, non-exempt users)",
                f"Active users: {active_count}",
                f"Disabled accounts: {disabled_count}",
                f"Service accounts: {service_accounts}",
                f"Exempt users: {exempt_users}"
            ]
            
            return self.create_result(
                status=CheckStatus.PASS,
                details="\n".join(details),
                compliant_count=active_count,
                total_count=effective_total
            )
        
        # Create detailed breakdown
        details = [
            f"Found {len(inactive_users)} inactive user(s) (> {self.inactivity_days} days):",
            f"• Active users: {active_count}",
            f"• Inactive users: {len(inactive_users)}",
            f"• Disabled accounts: {disabled_count}",
            f"• Service accounts: {service_accounts}",
            f"• Exempt users: {exempt_users}",
            f"• Total scanned: {total_checked}",
            "",
            "Top inactive users:"
        ]
        
        # Add top 10 most inactive users
        sorted_inactive = sorted(inactive_users, 
                                key=lambda x: x.get('daysInactive', 0) or 0, 
                                reverse=True)
        
        for i, user in enumerate(sorted_inactive[:10]):
            days = user.get('daysInactive', 'unknown')
            details.append(f"  {i+1}. {user['userPrincipalName']} - {days} days inactive")
        
        if len(inactive_users) > 10:
            details.append(f"  ... and {len(inactive_users) - 10} more")
        
        # Add recommendations
        details.extend([
            "",
            "RECOMMENDATIONS:",
            "1. Review and disable inactive user accounts",
            "2. Consider implementing automated account lifecycle management",
            "3. Create service accounts with proper monitoring",
            "4. Document exemption criteria"
        ])
        
        return self.create_result(
            status=CheckStatus.FAIL,
            details="\n".join(details),
            non_compliant_resources=sorted_inactive,
            non_compliant_count=len(inactive_users),
            compliant_count=active_count,
            total_count=effective_total,
            metadata={
                'inactivity_threshold_days': self.inactivity_days,
                'disabled_accounts': disabled_count,
                'service_accounts': service_accounts,
                'exempt_users': exempt_users,
                'analysis_timestamp': datetime.now().isoformat()
            }
        )
    
    def get_configuration_help(self) -> Dict[str, Any]:
        """Provide configuration guidance for this check."""
        return {
            'description': 'Configure inactive user detection settings',
            'fields': [
                {
                    'name': 'inactivity_days',
                    'type': 'number',
                    'default': self.INACTIVITY_THRESHOLD_DAYS,
                    'description': 'Number of days before considering a user inactive',
                    'help': 'Recommended: 90 days for regular users, 30-60 days for privileged users'
                },
                {
                    'name': 'exempt_users',
                    'type': 'array',
                    'default': [],
                    'description': 'List of user principal names to exempt from check',
                    'help': 'e.g., ["emergency@domain.com", "service-account@domain.com"]'
                },
                {
                    'name': 'exempt_patterns',
                    'type': 'array',
                    'default': [],
                    'description': 'Regex patterns for exempt users',
                    'help': 'e.g., ["^svc_.*@", ".*_bot@domain.com"]'
                }
            ],
            'recommendations': [
                'Use Microsoft Entra ID Governance for automated user lifecycle management',
                'Implement Privileged Identity Management for privileged accounts',
                'Create separate service accounts with proper monitoring',
                'Document all exemptions and review quarterly'
            ]
        }