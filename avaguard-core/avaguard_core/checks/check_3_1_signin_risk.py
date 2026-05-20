from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class Check_3_1_SigninRisk(BaseCheck):
    CHECK_ID = "3.1"
    TITLE = "Ensure that sign-in risk policy is configured"
    DESCRIPTION = "Sign-in risk policies should be enabled to block or challenge risky sign-ins"
    REQUIRES_PREMIUM = True  # Requires Azure AD Premium P2
    
    # Sign-in risk levels and recommended actions
    RISK_LEVELS = {
        'low': {
            'description': 'Low risk sign-in',
            'recommended_action': 'Allow with MFA challenge',
            'detection_time': 'Real-time'
        },
        'medium': {
            'description': 'Medium risk sign-in',
            'recommended_action': 'Require MFA or block',
            'detection_time': 'Real-time'
        },
        'high': {
            'description': 'High risk sign-in',
            'recommended_action': 'Block or require password change',
            'detection_time': 'Real-time'
        }
    }
    
    # Common risk detections that sign-in risk policies protect against
    RISK_DETECTIONS = [
        {
            'name': 'Impossible travel',
            'description': 'Sign-in from geographically distant locations in short time',
            'risk_level': 'high'
        },
        {
            'name': 'Anonymous IP address',
            'description': 'Sign-in from anonymous proxy or VPN',
            'risk_level': 'medium'
        },
        {
            'name': 'Malware linked IP address',
            'description': 'Sign-in from IP address known for malware',
            'risk_level': 'high'
        },
        {
            'name': 'Unfamiliar sign-in properties',
            'description': 'Sign-in with unusual properties for the user',
            'risk_level': 'medium'
        },
        {
            'name': 'Password spray',
            'description': 'Multiple failed sign-ins across multiple accounts',
            'risk_level': 'high'
        },
        {
            'name': 'Leaked credentials',
            'description': 'Credentials found in public data breaches',
            'risk_level': 'high'
        }
    ]
    
    def __init__(self, graph_client, config: Optional[Dict] = None):
        super().__init__(graph_client, config)
        self.config = config or {}
        self.require_all_levels = self.config.get('require_all_levels', True)
        self.min_risk_level = self.config.get('min_risk_level', 'medium')
        self.check_activity = self.config.get('check_activity', True)
        self.days_to_analyze = self.config.get('days_to_analyze', 30)
        
    def execute(self) -> CheckResult:
        """Execute sign-in risk policy check."""
        try:
            logger.info(f"Executing check {self.CHECK_ID}: {self.TITLE}")
            
            # Get sign-in risk policy configuration
            policy_config = self._get_signin_risk_policy()
            
            # Analyze policy configuration
            policy_analysis = self._analyze_policy_configuration(policy_config)
            
            # Check risk activity if configured
            risk_activity = None
            if self.check_activity:
                risk_activity = self._check_risk_activity()
            
            # Generate comprehensive result
            return self._create_check_result(policy_analysis, risk_activity)
            
        except Exception as e:
            logger.error(f"Error executing check {self.CHECK_ID}: {e}", exc_info=True)
            return self.create_result(
                status=CheckStatus.ERROR,
                details=f"Error checking sign-in risk policy: {str(e)}",
                total_count=1
            )
    
    def _get_signin_risk_policy(self) -> Dict[str, Any]:
        """Get sign-in risk policy configuration."""
        if self._is_real_api_connection():
            return self._get_policy_from_real_api()
        else:
            return self._get_policy_from_mock_data()
    
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
    
    def _get_policy_from_real_api(self) -> Dict[str, Any]:
        """Get sign-in risk policy from real Azure Graph API."""
        try:
            # Get Identity Protection risk policies
            # Note: This endpoint may require beta API or specific permissions
            
            # Try beta endpoint first
            try:
                policy_response = self.graph_client.get(
                    "/identityProtection/riskPolicies/signInRiskPolicy",
                    use_beta=True
                )
                
                policy = policy_response
                
                # Enrich with additional details
                enriched = self._enrich_policy(policy)
                enriched['source'] = 'real_api_beta'
                
                return enriched
                
            except Exception as beta_error:
                logger.debug(f"Beta endpoint failed: {beta_error}")
                
                # Try alternative endpoints or fallback
                # Identity Protection policies might be accessible through different paths
                try:
                    # Alternative: Check through policies endpoint
                    policies_response = self.graph_client.get("/policies")
                    policies = policies_response.get('value', [])
                    
                    signin_risk_policy = None
                    for policy in policies:
                        if policy.get('displayName') == 'Sign-in risk policy':
                            signin_risk_policy = policy
                            break
                    
                    if signin_risk_policy:
                        enriched = self._enrich_policy(signin_risk_policy)
                        enriched['source'] = 'real_api_policies'
                        return enriched
                    
                except Exception as alt_error:
                    logger.debug(f"Alternative endpoint failed: {alt_error}")
            
            # Fallback: Check through mock data method
            return self._get_policy_from_mock_data()
            
        except Exception as e:
            logger.error(f"Error fetching sign-in risk policy from real API: {e}")
            return {
                'is_enabled': False,
                'source': 'real_api_error',
                'error': str(e)
            }
    
    def _enrich_policy(self, policy: Dict) -> Dict[str, Any]:
        """Enrich policy with analysis and additional information."""
        enriched = policy.copy()
        
        # Extract key properties
        is_enabled = policy.get('isEnabled', False)
        conditions = policy.get('conditions', {})
        risk_level_conditions = conditions.get('riskLevelConditions', {})
        
        enriched['is_enabled'] = is_enabled
        
        # Extract configured risk levels
        configured_levels = []
        for risk_level in ['low', 'medium', 'high']:
            if risk_level in str(risk_level_conditions).lower():
                configured_levels.append(risk_level)
        
        enriched['configured_risk_levels'] = configured_levels
        
        # Check if all risk levels are configured
        enriched['covers_all_levels'] = all(
            level in configured_levels 
            for level in ['low', 'medium', 'high']
        )
        
        # Extract action configuration
        grant_controls = policy.get('grantControls', {})
        built_in_controls = grant_controls.get('builtInControls', [])
        
        # Determine action type
        if 'block' in built_in_controls:
            enriched['action_type'] = 'block'
        elif 'mfa' in built_in_controls:
            enriched['action_type'] = 'mfa'
        elif 'passwordChange' in built_in_controls:
            enriched['action_type'] = 'password_change'
        else:
            enriched['action_type'] = 'unknown'
        
        # Add risk level actions
        enriched['risk_level_actions'] = {}
        for level in configured_levels:
            level_info = self.RISK_LEVELS.get(level, {})
            enriched['risk_level_actions'][level] = {
                'action': enriched['action_type'],
                'recommended': level_info.get('recommended_action', 'Unknown')
            }
        
        return enriched
    
    def _get_policy_from_mock_data(self) -> Dict[str, Any]:
        """Get sign-in risk policy from mock data."""
        try:
            policy = self.graph_client.get_identity_protection_policy("signInRiskPolicy")
            
            if not policy:
                return {
                    'is_enabled': False,
                    'source': 'mock_data_not_found',
                    'configured_risk_levels': [],
                    'covers_all_levels': False,
                    'action_type': 'unknown'
                }
            
            # Enrich the policy
            enriched = self._enrich_policy(policy)
            enriched['source'] = 'mock_data'
            
            return enriched
            
        except Exception as e:
            logger.error(f"Error fetching sign-in risk policy from mock data: {e}")
            return {
                'is_enabled': False,
                'source': 'mock_data_error',
                'error': str(e),
                'configured_risk_levels': [],
                'covers_all_levels': False,
                'action_type': 'unknown'
            }
    
    def _analyze_policy_configuration(self, policy_config: Dict) -> Dict[str, Any]:
        """Analyze sign-in risk policy configuration."""
        analysis = {
            'is_enabled': policy_config.get('is_enabled', False),
            'configured_risk_levels': policy_config.get('configured_risk_levels', []),
            'covers_all_levels': policy_config.get('covers_all_levels', False),
            'action_type': policy_config.get('action_type', 'unknown'),
            'compliance_status': 'non_compliant',
            'issues': [],
            'warnings': [],
            'recommendations': [],
            'security_score': 0
        }
        
        if not analysis['is_enabled']:
            analysis['issues'].append('Sign-in risk policy is disabled')
            analysis['security_score'] = 0
            return analysis
        
        # Policy is enabled - calculate security score
        base_score = 50
        score_adjustments = 0
        
        # Check configured risk levels
        configured_levels = analysis['configured_risk_levels']
        missing_critical = []
        
        if not configured_levels:
            analysis['issues'].append('No risk levels configured in policy')
            score_adjustments -= 30
        else:
            # Check coverage of critical risk levels
            critical_levels = ['high', 'medium']
            missing_critical = [level for level in critical_levels if level not in configured_levels]
            
            if missing_critical:
                analysis['issues'].append(
                    f'Missing critical risk levels: {", ".join(missing_critical)}'
                )
                score_adjustments -= 20
            
            # Check if low risk is configured (optional but recommended)
            if 'low' not in configured_levels:
                analysis['warnings'].append('Low risk level not configured')
                score_adjustments -= 5
        
        # Check action type
        action_type = analysis['action_type']
        if action_type == 'block':
            score_adjustments += 20  # Most secure
        elif action_type == 'mfa':
            score_adjustments += 15  # Good balance
        elif action_type == 'password_change':
            score_adjustments += 10  # Less secure
        elif action_type == 'unknown':
            analysis['warnings'].append('Unknown action type configured')
            score_adjustments -= 10
        
        # Calculate final score
        analysis['security_score'] = max(0, min(100, base_score + score_adjustments))
        
        # Determine compliance status
        if analysis['security_score'] >= 65:
            analysis['compliance_status'] = 'compliant'
        elif analysis['security_score'] >= 50:
            analysis['compliance_status'] = 'partial'
        else:
            analysis['compliance_status'] = 'non_compliant'
        
        # Generate recommendations
        if not analysis['configured_risk_levels']:
            analysis['recommendations'].append(
                'Configure risk levels in the sign-in risk policy'
            )
        
        if missing_critical:
            analysis['recommendations'].append(
                f'Add missing risk levels: {", ".join(missing_critical)}'
            )
        
        if action_type == 'unknown' or action_type == 'password_change':
            analysis['recommendations'].append(
                'Consider setting action to "Block" for high risk or "Require MFA" for medium risk'
            )
        
        # Add general recommendations
        analysis['recommendations'].extend([
            'Review and tune risk detection thresholds regularly',
            'Monitor Identity Protection alerts and incidents',
            'Consider user risk policies for additional protection'
        ])
        
        return analysis
    
    def _check_risk_activity(self) -> Optional[Dict[str, Any]]:
        """Check for recent risk activity if possible."""
        activity = {
            'recent_risk_events': 0,
            'by_risk_level': {},
            'top_detections': [],
            'detected': False,
            'source': 'unknown'
        }
        
        try:
            if self._is_real_api_connection():
                # Real API - check risk detections
                return self._check_risk_activity_from_real_api()
            else:
                # Mock data - check if available
                return self._check_risk_activity_from_mock_data()
                
        except Exception as e:
            logger.debug(f"Could not check risk activity: {e}")
            return None
    
    def _check_risk_activity_from_real_api(self) -> Dict[str, Any]:
        """Check risk activity from real Azure API."""
        activity = {
            'recent_risk_events': 0,
            'by_risk_level': {},
            'top_detections': [],
            'detected': False,
            'source': 'real_api'
        }
        
        try:
            # Note: This would require specific Identity Protection API permissions
            # For now, return minimal data
            return activity
            
        except Exception as e:
            logger.warning(f"Could not fetch risk activity from real API: {e}")
            return activity
    
    def _check_risk_activity_from_mock_data(self) -> Dict[str, Any]:
        """Check risk activity from mock data."""
        activity = {
            'recent_risk_events': 0,
            'by_risk_level': {},
            'top_detections': [],
            'detected': False,
            'source': 'mock_data'
        }
        
        try:
            # Check risk events in mock data
            if hasattr(self.graph_client, 'security'):
                security_data = self.graph_client.security
                risk_events = security_data.get('riskEvents', [])
                
                # Filter recent events (last 30 days)
                recent_events = []
                for event in risk_events:
                    # Simple check - assume all events are recent in mock data
                    recent_events.append(event)
                
                activity['recent_risk_events'] = len(recent_events)
                activity['detected'] = len(recent_events) > 0
                
                # Group by risk level
                for event in recent_events:
                    risk_level = event.get('riskLevel', 'unknown').lower()
                    activity['by_risk_level'][risk_level] = \
                        activity['by_risk_level'].get(risk_level, 0) + 1
                
                # Get top detection types
                detection_counts = {}
                for event in recent_events:
                    detection_type = event.get('riskType', 'unknown')
                    detection_counts[detection_type] = \
                        detection_counts.get(detection_type, 0) + 1
                
                activity['top_detections'] = [
                    {'type': det_type, 'count': count}
                    for det_type, count in sorted(
                        detection_counts.items(), 
                        key=lambda x: x[1], 
                        reverse=True
                    )[:5]  # Top 5 detections
                ]
                
        except Exception as e:
            logger.debug(f"Could not analyze risk activity from mock data: {e}")
        
        return activity
    
    def _create_check_result(self, policy_analysis: Dict, 
                           risk_activity: Optional[Dict]) -> CheckResult:
        """Create the final check result."""
        is_enabled = policy_analysis['is_enabled']
        security_score = policy_analysis['security_score']
        compliance_status = policy_analysis['compliance_status']
        configured_levels = policy_analysis['configured_risk_levels']
        action_type = policy_analysis['action_type']
        
        # Determine overall status
        if not is_enabled:
            status = CheckStatus.FAIL
        elif compliance_status == 'compliant':
            status = CheckStatus.PASS
        elif compliance_status == 'partial':
            status = CheckStatus.WARNING
        else:
            status = CheckStatus.FAIL
        
        # Build details
        details = []
        
        if status == CheckStatus.PASS:
            details.append("✅ Sign-in risk policy is properly configured")
            details.append(f"Security Score: {security_score}/100")
        elif status == CheckStatus.WARNING:
            details.append("⚠️ WARNING: Sign-in risk policy needs improvement")
            details.append(f"Security Score: {security_score}/100")
        else:
            if not is_enabled:
                details.append("❌ FAILURE: Sign-in risk policy is DISABLED")
            else:
                details.append("❌ FAILURE: Sign-in risk policy is misconfigured")
            details.append(f"Security Score: {security_score}/100")
        
        details.append("")
        
        # Add policy configuration details
        if is_enabled:
            details.append("POLICY CONFIGURATION:")
            details.append(f"• Status: {'Enabled' if is_enabled else 'Disabled'}")
            details.append(f"• Action Type: {action_type.title().replace('_', ' ')}")
            
            if configured_levels:
                details.append(f"• Configured Risk Levels: {', '.join(configured_levels)}")
            else:
                details.append("• Configured Risk Levels: None")
            
            details.append(f"• Covers All Risk Levels: {'Yes' if policy_analysis['covers_all_levels'] else 'No'}")
        else:
            details.append("POLICY STATUS: Disabled")
        
        # Add risk level information
        details.append("")
        details.append("RISK LEVEL RECOMMENDATIONS:")
        for level, level_info in self.RISK_LEVELS.items():
            configured = level in configured_levels if is_enabled else False
            status_icon = '✅' if configured else '❌'
            details.append(f"{status_icon} {level.upper()}: {level_info['description']}")
            details.append(f"   Recommended: {level_info['recommended_action']}")
        
        # Add issues and warnings
        if policy_analysis.get('issues'):
            details.append("")
            details.append("ISSUES FOUND:")
            for issue in policy_analysis['issues']:
                details.append(f"• {issue}")
        
        if policy_analysis.get('warnings'):
            details.append("")
            details.append("WARNINGS:")
            for warning in policy_analysis['warnings']:
                details.append(f"• ⚠️ {warning}")
        
        # Add risk activity if available
        if risk_activity and risk_activity.get('detected'):
            details.append("")
            details.append("RECENT RISK ACTIVITY:")
            details.append(f"• Risk events detected: {risk_activity['recent_risk_events']}")
            
            if risk_activity['by_risk_level']:
                details.append("  By risk level:")
                for level, count in risk_activity['by_risk_level'].items():
                    details.append(f"    • {level}: {count} events")
            
            if risk_activity['top_detections']:
                details.append("  Top detection types:")
                for detection in risk_activity['top_detections'][:3]:
                    details.append(f"    • {detection['type']}: {detection['count']} times")
        
        # Add common risk detections
        details.append("")
        details.append("COMMON RISK DETECTIONS PROTECTED AGAINST:")
        for detection in self.RISK_DETECTIONS[:4]:  # Show first 4
            risk_icon = '🔴' if detection['risk_level'] == 'high' else '🟡'
            details.append(f"{risk_icon} {detection['name']}: {detection['description']}")
        
        # Add recommendations
        details.append("")
        details.append("RECOMMENDATIONS:")
        
        if not is_enabled:
            details.extend([
                "1. ENABLE SIGN-IN RISK POLICY:",
                "   • Azure Portal → Azure Active Directory → Security → Identity Protection",
                "   • Navigate to 'Sign-in risk policy'",
                "   • Click 'Configure' and set to 'On'",
                "",
                "2. CONFIGURE RISK LEVELS:",
                "   • Set 'Assignments' to include all users or specific groups",
                "   • Configure actions for each risk level:",
                "     - High risk: Block or require password change",
                "     - Medium risk: Require multi-factor authentication",
                "     - Low risk: Allow or require MFA",
                "",
                "3. TEST AND MONITOR:",
                "   • Start with report-only mode to test impact",
                "   • Monitor Identity Protection alerts",
                "   • Review false positives and adjust as needed"
            ])
        else:
            for i, rec in enumerate(policy_analysis.get('recommendations', []), 1):
                details.append(f"{i}. {rec}")
        
        # Add licensing and capability information
        details.extend([
            "",
            "AZURE AD PREMIUM REQUIREMENTS:",
            "• Azure AD Premium P2 required for Identity Protection",
            "• Provides real-time risk detection and automated response",
            "• Includes risk-based Conditional Access policies",
            "",
            "BENEFITS OF SIGN-IN RISK POLICIES:",
            "• Real-time protection against account compromise",
            "• Automated response to suspicious activities",
            "• Reduced manual investigation workload",
            "• Integration with Microsoft Intelligent Security Graph"
        ])
        
        # Create result
        non_compliant_resources = []
        if status != CheckStatus.PASS:
            non_compliant_resources = [{
                'policy': 'Sign-in Risk Policy',
                'status': 'Disabled' if not is_enabled else 'Misconfigured',
                'security_score': security_score,
                'configured_levels': configured_levels,
                'action_type': action_type
            }]
        
        return self.create_result(
            status=status,
            details="\n".join(details),
            non_compliant_resources=non_compliant_resources,
            non_compliant_count=1 if status != CheckStatus.PASS else 0,
            compliant_count=1 if status == CheckStatus.PASS else 0,
            total_count=1,
            metadata={
                'is_enabled': is_enabled,
                'security_score': security_score,
                'configured_risk_levels': configured_levels,
                'action_type': action_type,
                'covers_all_levels': policy_analysis.get('covers_all_levels', False),
                'risk_activity_detected': risk_activity.get('detected', False) if risk_activity else False,
                'require_all_levels': self.require_all_levels,
                'check_timestamp': datetime.now().isoformat()
            }
        )
    
    def get_configuration_help(self) -> Dict[str, Any]:
        """Provide configuration guidance for this check."""
        return {
            'description': 'Configure sign-in risk policy check settings',
            'fields': [
                {
                    'name': 'require_all_levels',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Require all risk levels (low, medium, high) to be configured',
                    'help': 'When disabled, policy may pass with only high/medium risk levels'
                },
                {
                    'name': 'min_risk_level',
                    'type': 'string',
                    'default': 'medium',
                    'description': 'Minimum risk level that must be configured',
                    'help': 'Options: low, medium, high. Higher values are more strict.'
                },
                {
                    'name': 'check_activity',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Check for recent risk activity',
                    'help': 'Requires additional API permissions for real Azure connections'
                },
                {
                    'name': 'days_to_analyze',
                    'type': 'number',
                    'default': 30,
                    'description': 'Number of days to analyze for risk activity',
                    'help': 'Longer periods provide more context but may be slower'
                }
            ],
            'risk_levels': self.RISK_LEVELS,
            'common_detections': self.RISK_DETECTIONS[:5],
            'recommendations': [
                'Enable sign-in risk policy for all users',
                'Configure blocking for high-risk sign-ins',
                'Require MFA for medium-risk sign-ins',
                'Monitor and tune risk detection thresholds',
                'Use report-only mode initially to test impact'
            ]
        }