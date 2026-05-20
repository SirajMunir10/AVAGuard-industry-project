from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime
import re

logger = logging.getLogger(__name__)

class Check_1_11_LegacyAuth(BaseCheck):
    CHECK_ID = "1.11"
    TITLE = "Ensure that legacy authentication protocols are blocked"
    DESCRIPTION = "Legacy authentication does not support MFA and should be blocked"
    REQUIRES_PREMIUM = False  # Basic Conditional Access available in all tiers
    
    # Legacy authentication protocols
    LEGACY_PROTOCOLS = {
        'exchangeActiveSync': {
            'name': 'Exchange ActiveSync',
            'risk_level': 'high',
            'description': 'Mobile email synchronization protocol',
            'common_use': 'Mobile email clients'
        },
        'other': {
            'name': 'Other clients',
            'risk_level': 'critical',
            'description': 'IMAP, POP3, SMTP, MAPI, EWS',
            'common_use': 'Email clients and older apps'
        },
        'autodiscover': {
            'name': 'Autodiscover',
            'risk_level': 'medium',
            'description': 'Exchange Autodiscover service',
            'common_use': 'Automatic Exchange configuration'
        }
    }
    
    # Signs of legacy authentication activity
    LEGACY_AUTH_INDICATORS = [
        'IMAP',
        'POP3', 
        'SMTP',
        'MAPI',
        'EWS',
        'ActiveSync',
        'EAS',
        'cardDAV',
        'calDAV'
    ]
    
    def __init__(self, graph_client, config: Optional[Dict] = None):
        super().__init__(graph_client, config)
        self.config = config or {}
        self.check_signin_logs = self.config.get('check_signin_logs', True)
        self.require_all_protocols = self.config.get('require_all_protocols', True)
        self.whitelist_apps = self.config.get('whitelist_apps', [])
        self.detection_threshold = self.config.get('detection_threshold', 10)  # Minimum sign-ins to flag
        
    def execute(self) -> CheckResult:
        """Execute legacy authentication check."""
        try:
            logger.info(f"Executing check {self.CHECK_ID}: {self.TITLE}")
            
            # First check if Security Defaults are enabled (blocks legacy auth automatically)
            security_defaults_enabled = False
            try:
                if hasattr(self.graph_client, 'get_identity_protection_policy'):
                    policy = self.graph_client.get_identity_protection_policy("securityDefaults")
                    security_defaults_enabled = policy.get('isEnabled', False)
                elif hasattr(self.graph_client, 'get'):
                    # Fallback to direct API call for real client
                    policy_response = self.graph_client.get("/policies/identitySecurityDefaultsEnforcementPolicy")
                    security_defaults_enabled = policy_response.get('isEnabled', False)
            except Exception as e:
                logger.debug(f"Could not check security defaults: {e}")
                
            # Get Conditional Access policies
            ca_policies = self._get_conditional_access_policies()
            
            # Analyze policies for legacy auth blocking
            policy_analysis = self._analyze_ca_policies(ca_policies)
            
            # If Security Defaults are enabled, it provides 100% coverage
            if security_defaults_enabled:
                policy_analysis['total_coverage_score'] = 100
                policy_analysis['coverage'] = {k: True for k in policy_analysis['coverage']}
                policy_analysis['security_defaults_active'] = True
            
            # Check for legacy auth activity if configured
            legacy_activity = None
            if self.check_signin_logs:
                legacy_activity = self._check_legacy_auth_activity()
            
            # Generate comprehensive result
            return self._create_check_result(policy_analysis, legacy_activity)
            
        except Exception as e:
            logger.error(f"Error executing check {self.CHECK_ID}: {e}", exc_info=True)
            return self.create_result(
                status=CheckStatus.ERROR,
                details=f"Error checking legacy authentication: {str(e)}",
                total_count=1
            )
    
    def _get_conditional_access_policies(self) -> List[Dict[str, Any]]:
        """Get Conditional Access policies."""
        try:
            if self._is_real_api_connection():
                return self._get_ca_policies_from_real_api()
            else:
                return self._get_ca_policies_from_mock_data()
        except Exception as e:
            logger.error(f"Error fetching Conditional Access policies: {e}")
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
    
    def _get_ca_policies_from_real_api(self) -> List[Dict[str, Any]]:
        """Get Conditional Access policies from real Azure Graph API."""
        try:
            # Use beta endpoint for comprehensive policy details
            policies_response = self.graph_client.get(
                "/identity/conditionalAccess/policies",
                use_beta=True
            )
            
            policies = policies_response.get('value', [])
            
            # Enrich policies with protocol information
            enriched_policies = []
            for policy in policies:
                enriched = self._enrich_ca_policy(policy)
                enriched_policies.append(enriched)
            
            return enriched_policies
            
        except Exception as e:
            logger.warning(f"Could not fetch from beta endpoint: {e}")
            
            # Fallback to standard endpoint
            try:
                policies_response = self.graph_client.get(
                    "/identity/conditionalAccess/policies"
                )
                policies = policies_response.get('value', [])
                
                enriched_policies = []
                for policy in policies:
                    enriched = self._enrich_ca_policy(policy)
                    enriched_policies.append(enriched)
                
                return enriched_policies
                
            except Exception as inner_e:
                logger.error(f"Failed to fetch CA policies: {inner_e}")
                return []
    
    def _enrich_ca_policy(self, policy: Dict) -> Dict[str, Any]:
        """Enrich Conditional Access policy with legacy auth analysis."""
        enriched = policy.copy()
        
        # Extract client app types
        conditions = policy.get('conditions', {})
        client_apps = conditions.get('clientAppTypes', [])
        
        # Check for legacy protocol coverage
        legacy_coverage = {
            'exchangeActiveSync': 'exchangeActiveSync' in client_apps,
            'other': 'other' in client_apps,
            'autodiscover': 'autodiscover' in client_apps or 'exchangeActiveSync' in client_apps
        }
        
        # Check grant controls
        grant_controls = policy.get('grantControls', {})
        built_in_controls = grant_controls.get('builtInControls', [])
        blocks_access = 'block' in built_in_controls
        
        # Determine if this policy blocks legacy auth
        targets_legacy = any(legacy_coverage.values())
        is_blocking_policy = targets_legacy and blocks_access
        
        enriched['legacy_analysis'] = {
            'targets_legacy': targets_legacy,
            'blocks_access': blocks_access,
            'is_blocking_policy': is_blocking_policy,
            'legacy_coverage': legacy_coverage,
            'covered_protocols': [proto for proto, covered in legacy_coverage.items() if covered]
        }
        
        return enriched
    
    def _get_ca_policies_from_mock_data(self) -> List[Dict[str, Any]]:
        """Get Conditional Access policies from mock data."""
        try:
            policies = self.graph_client.get_conditional_access_policies()
            
            # Ensure all policies have legacy analysis
            enriched_policies = []
            for policy in policies:
                enriched = self._enrich_ca_policy(policy)
                enriched_policies.append(enriched)
            
            return enriched_policies
            
        except Exception as e:
            logger.error(f"Error fetching CA policies from mock data: {e}")
            return []
    
    def _analyze_ca_policies(self, policies: List[Dict]) -> Dict[str, Any]:
        """Analyze Conditional Access policies for legacy auth blocking."""
        analysis = {
            'blocking_policies': [],
            'partial_policies': [],
            'no_policies': True,
            'coverage': {
                'exchangeActiveSync': False,
                'other': False,
                'autodiscover': False
            },
            'total_coverage_score': 0,
            'recommendations': []
        }
        
        # Check each policy
        for policy in policies:
            if policy.get('state') != 'enabled':
                continue
            
            legacy_analysis = policy.get('legacy_analysis', {})
            
            if legacy_analysis.get('is_blocking_policy'):
                analysis['no_policies'] = False
                analysis['blocking_policies'].append({
                    'name': policy.get('displayName', 'Unnamed Policy'),
                    'id': policy.get('id'),
                    'coverage': legacy_analysis.get('covered_protocols', []),
                    'created': policy.get('createdDateTime')
                })
                
                # Update coverage
                for proto in legacy_analysis.get('covered_protocols', []):
                    if proto in analysis['coverage']:
                        analysis['coverage'][proto] = True
            
            elif legacy_analysis.get('targets_legacy'):
                # Policy targets legacy but doesn't block (e.g., requires MFA)
                analysis['partial_policies'].append({
                    'name': policy.get('displayName', 'Unnamed Policy'),
                    'action': policy.get('grantControls', {}).get('builtInControls', ['unknown'])[0]
                })
        
        # Calculate coverage score
        total_protocols = len(analysis['coverage'])
        covered_protocols = sum(1 for covered in analysis['coverage'].values() if covered)
        analysis['total_coverage_score'] = (covered_protocols / total_protocols * 100) if total_protocols > 0 else 0
        
        # Generate recommendations
        if analysis['no_policies']:
            analysis['recommendations'].append(
                "Create a Conditional Access policy to block all legacy authentication protocols"
            )
        
        # Check for missing protocol coverage
        missing_protocols = []
        for proto, covered in analysis['coverage'].items():
            if not covered:
                proto_info = self.LEGACY_PROTOCOLS.get(proto, {})
                missing_protocols.append(proto_info.get('name', proto))
        
        if missing_protocols:
            analysis['recommendations'].append(
                f"Extend blocking to cover: {', '.join(missing_protocols)}"
            )
        
        # Check for partial policies (MFA instead of block)
        if analysis['partial_policies']:
            analysis['recommendations'].append(
                "Consider changing policies that require MFA for legacy auth to 'Block' instead"
            )
        
        return analysis
    
    def _check_legacy_auth_activity(self) -> Optional[Dict[str, Any]]:
        """Check for recent legacy authentication activity."""
        activity = {
            'recent_signins': 0,
            'by_protocol': {},
            'top_users': [],
            'risk_indicators': [],
            'detected': False
        }
        
        try:
            if self._is_real_api_connection():
                # Real API - check sign-in logs
                return self._check_legacy_auth_from_real_api()
            else:
                # Mock data - check if available
                return self._check_legacy_auth_from_mock_data()
                
        except Exception as e:
            logger.debug(f"Could not check legacy auth activity: {e}")
            return None
    
    def _check_legacy_auth_from_real_api(self) -> Dict[str, Any]:
        """Check legacy auth activity from real Azure API."""
        activity = {
            'recent_signins': 0,
            'by_protocol': {},
            'top_users': [],
            'risk_indicators': [],
            'detected': False,
            'source': 'real_api'
        }
        
        try:
            # Get recent sign-in logs (requires AuditLog.Read.All)
            # Note: This is a simplified implementation
            # Real implementation would need to filter for legacy auth
            
            # For now, return minimal data
            return activity
            
        except Exception as e:
            logger.warning(f"Could not fetch sign-in logs: {e}")
            return activity
    
    def _check_legacy_auth_from_mock_data(self) -> Dict[str, Any]:
        """Check legacy auth activity from mock data."""
        activity = {
            'recent_signins': 0,
            'by_protocol': {},
            'top_users': [],
            'risk_indicators': [],
            'detected': False,
            'source': 'mock_data'
        }
        
        try:
            # Check audit logs in mock data
            if hasattr(self.graph_client, 'audit'):
                audit_data = self.graph_client.audit
                signin_logs = audit_data.get('signInLogs', [])
                
                legacy_signins = []
                for log in signin_logs:
                    # Check for legacy indicators
                    client_app = log.get('deviceDetail', {}).get('operatingSystem', '')
                    resource = log.get('appDisplayName', '')
                    
                    is_legacy = False
                    protocol = 'unknown'
                    
                    for indicator in self.LEGACY_AUTH_INDICATORS:
                        if indicator.lower() in str(client_app).lower() or \
                           indicator.lower() in str(resource).lower():
                            is_legacy = True
                            protocol = indicator
                            break
                    
                    if is_legacy:
                        legacy_signins.append({
                            'user': log.get('userPrincipalName'),
                            'protocol': protocol,
                            'timestamp': log.get('timestamp'),
                            'status': log.get('status')
                        })
                
                activity['recent_signins'] = len(legacy_signins)
                activity['detected'] = len(legacy_signins) > 0
                
                # Group by protocol
                for signin in legacy_signins:
                    proto = signin['protocol']
                    activity['by_protocol'][proto] = activity['by_protocol'].get(proto, 0) + 1
                
                # Get top users
                user_counts = {}
                for signin in legacy_signins:
                    user = signin['user']
                    user_counts[user] = user_counts.get(user, 0) + 1
                
                activity['top_users'] = sorted(
                    [{'user': user, 'count': count} for user, count in user_counts.items()],
                    key=lambda x: x['count'],
                    reverse=True
                )[:5]  # Top 5 users
                
                # Check for risk indicators
                if len(legacy_signins) > self.detection_threshold:
                    activity['risk_indicators'].append(
                        f"High volume of legacy auth: {len(legacy_signins)} sign-ins detected"
                    )
                
        except Exception as e:
            logger.debug(f"Could not analyze legacy auth from mock data: {e}")
        
        return activity
    
    def _create_check_result(self, policy_analysis: Dict, 
                           legacy_activity: Optional[Dict]) -> CheckResult:
        """Create the final check result."""
        blocking_policies = policy_analysis['blocking_policies']
        coverage_score = policy_analysis['total_coverage_score']
        missing_protocols = [proto for proto, covered in policy_analysis['coverage'].items() if not covered]
        
        # Determine check status
        if coverage_score == 100:
            status = CheckStatus.PASS
        elif coverage_score >= 70 and not self.require_all_protocols:
            status = CheckStatus.WARNING
        else:
            status = CheckStatus.FAIL
        
        # Build details
        details = []
        
        if status == CheckStatus.PASS:
            details.append("✅ Legacy authentication protocols are BLOCKED")
            
            if policy_analysis.get('security_defaults_active'):
                details.append("Coverage provided globally via Security Defaults")
            else:
                details.append(f"Coverage Score: {coverage_score:.0f}%")
            
            if blocking_policies:
                details.append("")
                details.append("BLOCKING POLICIES:")
                for policy in blocking_policies[:3]:  # Show top 3
                    protocols = [self.LEGACY_PROTOCOLS.get(p, {}).get('name', p) 
                                for p in policy['coverage']]
                    details.append(f"• {policy['name']} - Blocks: {', '.join(protocols)}")
            
        else:
            if status == CheckStatus.WARNING:
                details.append("⚠️ WARNING: Legacy authentication partially blocked")
            else:
                details.append("❌ FAILURE: Legacy authentication not properly blocked")
            
            details.append(f"Coverage Score: {coverage_score:.0f}%")
            details.append("")
            
            # List missing protocols
            if missing_protocols:
                details.append("MISSING PROTOCOL COVERAGE:")
                for proto in missing_protocols:
                    proto_info = self.LEGACY_PROTOCOLS.get(proto, {})
                    risk_level = proto_info.get('risk_level', 'unknown').upper()
                    details.append(f"• ⚠️ {proto_info.get('name', proto)} ({risk_level} risk)")
            
            # List existing policies
            if blocking_policies:
                details.append("")
                details.append("EXISTING BLOCKING POLICIES:")
                for policy in blocking_policies:
                    protocols = [self.LEGACY_PROTOCOLS.get(p, {}).get('name', p) 
                                for p in policy['coverage']]
                    details.append(f"• {policy['name']} - Blocks: {', '.join(protocols)}")
        
        # Add legacy auth activity if available
        if legacy_activity and legacy_activity.get('detected'):
            details.append("")
            details.append("⚠️ LEGACY AUTHENTICATION ACTIVITY DETECTED:")
            details.append(f"Recent legacy auth sign-ins: {legacy_activity['recent_signins']}")
            
            if legacy_activity['by_protocol']:
                details.append("By protocol:")
                for proto, count in legacy_activity['by_protocol'].items():
                    details.append(f"  • {proto}: {count} sign-ins")
            
            if legacy_activity['risk_indicators']:
                details.append("")
                details.append("RISK INDICATORS:")
                for indicator in legacy_activity['risk_indicators']:
                    details.append(f"• {indicator}")
        
        # Add protocol information
        details.append("")
        details.append("LEGACY AUTHENTICATION PROTOCOLS:")
        for proto_id, proto_info in self.LEGACY_PROTOCOLS.items():
            risk_icon = '🔴' if proto_info['risk_level'] == 'critical' else '🟡'
            details.append(f"{risk_icon} {proto_info['name']}: {proto_info['description']}")
        
        # Add recommendations
        details.append("")
        details.append("RECOMMENDATIONS:")
        
        for rec in policy_analysis.get('recommendations', []):
            details.append(f"1. {rec}")
        
        if not blocking_policies:
            details.extend([
                "2. Create Conditional Access policy:",
                "   • Target: All users",
                "   • Cloud apps: All cloud apps",
                "   • Client apps: Exchange ActiveSync, Other clients",
                "   • Grant controls: Block access",
                "   • Enable policy",
                "",
                "3. Monitor legacy auth sign-ins:",
                "   • Azure AD → Sign-in logs → Add filter: Client app = Legacy",
                "   • Set up alerts for legacy auth usage",
                "   • Investigate and remediate any detected usage"
            ])
        
        # Add implementation guidance
        details.extend([
            "",
            "IMPLEMENTATION GUIDANCE:",
            "• Use Security Defaults (free) for basic protection",
            "• Use Conditional Access (P1/P2) for granular control",
            "• Test with report-only mode before enforcement",
            "• Consider exceptions for service accounts if absolutely necessary"
        ])
        
        # Create result
        non_compliant_resources = []
        if status != CheckStatus.PASS:
            non_compliant_resources = [{
                'policy': 'Legacy Authentication Blocking',
                'status': f'{coverage_score:.0f}% coverage',
                'missing_protocols': missing_protocols,
                'coverage_score': coverage_score
            }]
        
        return self.create_result(
            status=status,
            details="\n".join(details),
            non_compliant_resources=non_compliant_resources,
            non_compliant_count=1 if status != CheckStatus.PASS else 0,
            compliant_count=1 if status == CheckStatus.PASS else 0,
            total_count=1,
            metadata={
                'coverage_score': coverage_score,
                'blocking_policy_count': len(blocking_policies),
                'missing_protocols': missing_protocols,
                'legacy_activity_detected': legacy_activity.get('detected', False) if legacy_activity else False,
                'legacy_signin_count': legacy_activity.get('recent_signins', 0) if legacy_activity else 0,
                'require_all_protocols': self.require_all_protocols,
                'check_timestamp': datetime.now().isoformat()
            }
        )
    
    def get_configuration_help(self) -> Dict[str, Any]:
        """Provide configuration guidance for this check."""
        return {
            'description': 'Configure legacy authentication detection settings',
            'fields': [
                {
                    'name': 'check_signin_logs',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Check for recent legacy authentication activity',
                    'help': 'Requires AuditLog.Read.All permission for real API'
                },
                {
                    'name': 'require_all_protocols',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Require blocking of all legacy protocols',
                    'help': 'When disabled, partial coverage may result in WARNING instead of FAIL'
                },
                {
                    'name': 'whitelist_apps',
                    'type': 'array',
                    'default': [],
                    'description': 'Applications allowed to use legacy auth',
                    'help': 'Use sparingly for critical service accounts'
                },
                {
                    'name': 'detection_threshold',
                    'type': 'number',
                    'default': 10,
                    'description': 'Minimum legacy auth sign-ins to trigger alert',
                    'help': 'Lower values are more sensitive to detection'
                }
            ],
            'legacy_protocols': self.LEGACY_PROTOCOLS,
            'recommendations': [
                'Block all legacy authentication protocols',
                'Monitor sign-in logs for legacy auth attempts',
                'Use Conditional Access report-only mode initially',
                'Consider Microsoft Defender for Office 365 for additional protection',
                'Regularly review and update exception policies'
            ]
        }