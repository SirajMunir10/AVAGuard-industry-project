from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime
import re

logger = logging.getLogger(__name__)

class Check_2_1_Domains(BaseCheck):
    CHECK_ID = "2.1"
    TITLE = "Ensure that only approved domain names are used"
    DESCRIPTION = "Unverified or unused domains can be a security risk"
    REQUIRES_PREMIUM = False
    
    # Domain classification categories
    DOMAIN_CATEGORIES = {
        'verified': {
            'description': 'Fully verified and active domain',
            'compliance': 'compliant'
        },
        'unverified': {
            'description': 'Domain added but not verified',
            'compliance': 'non_compliant',
            'risk_level': 'high'
        },
        'onmicrosoft': {
            'description': 'Default *.onmicrosoft.com domain',
            'compliance': 'compliant',
            'risk_level': 'low'
        },
        'vanity': {
            'description': 'Custom branded domain',
            'compliance': 'compliant',
            'risk_level': 'medium'
        },
        'legacy': {
            'description': 'Old or deprecated domain',
            'compliance': 'warning',
            'risk_level': 'medium'
        },
        'external': {
            'description': 'External partner or acquisition domain',
            'compliance': 'warning',
            'risk_level': 'medium'
        }
    }
    
    # Common high-risk domain patterns
    HIGH_RISK_PATTERNS = [
        r'\.local$',
        r'\.internal$',
        r'\.test$',
        r'\.demo$',
        r'^test\.',
        r'^dev\.',
        r'^staging\.',
        r'^temp\.',
        r'microsoftonline\.com$',  # Should only be *.onmicrosoft.com
        r'\.co\.cc$',  # Free domain services
        r'\.tk$',
        r'\.ml$',
        r'\.ga$',
        r'\.cf$',
        r'\.gq$'
    ]
    
    def __init__(self, graph_client, config: Optional[Dict] = None):
        super().__init__(graph_client, config)
        self.config = config or {}
        self.allowed_unverified = set(self.config.get('allowed_unverified', []))
        self.check_domain_age = self.config.get('check_domain_age', True)
        self.max_unverified_age_days = self.config.get('max_unverified_age_days', 30)
        self.require_dns_validation = self.config.get('require_dns_validation', True)
        self.check_high_risk_patterns = self.config.get('check_high_risk_patterns', True)
        
    def execute(self) -> CheckResult:
        """Execute domain verification check."""
        try:
            logger.info(f"Executing check {self.CHECK_ID}: {self.TITLE}")
            
            # Get domains from Graph API
            domains = self._get_domains()
            
            if not domains:
                return self.create_result(
                    status=CheckStatus.WARNING,
                    details="No domains found in the tenant",
                    total_count=0
                )
            
            # Analyze domains for compliance
            analysis = self._analyze_domains(domains)
            
            # Generate comprehensive result
            return self._create_check_result(analysis)
            
        except Exception as e:
            logger.error(f"Error executing check {self.CHECK_ID}: {e}", exc_info=True)
            return self.create_result(
                status=CheckStatus.ERROR,
                details=f"Error checking domains: {str(e)}",
                total_count=0
            )
    
    def _get_domains(self) -> List[Dict[str, Any]]:
        """Get domains from Graph API."""
        if self._is_real_api_connection():
            return self._get_domains_from_real_api()
        else:
            return self._get_domains_from_mock_data()
    
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
    
    def _get_domains_from_real_api(self) -> List[Dict[str, Any]]:
        """Get domains from real Azure Graph API."""
        try:
            # Get domains with comprehensive properties
            domains_response = self.graph_client.get("/domains")
            domains = domains_response.get('value', [])
            
            # Enrich domains with additional analysis
            enriched_domains = []
            for domain in domains:
                enriched = self._enrich_domain(domain)
                enriched_domains.append(enriched)
            
            return enriched_domains
            
        except Exception as e:
            logger.error(f"Error fetching domains from real API: {e}")
            return []
    
    def _enrich_domain(self, domain: Dict) -> Dict[str, Any]:
        """Enrich domain data with classification and analysis."""
        enriched = domain.copy()
        domain_name = domain.get('id', '').lower()
        
        # Determine domain category
        category = self._classify_domain(domain_name, domain)
        enriched['category'] = category
        
        # Check for high-risk patterns
        if self.check_high_risk_patterns:
            is_high_risk = self._is_high_risk_domain(domain_name)
            enriched['is_high_risk'] = is_high_risk
            
            if is_high_risk:
                enriched['risk_indicators'] = self._get_risk_indicators(domain_name)
        
        # Check DNS validation if available
        if self.require_dns_validation and 'authenticationType' in domain:
            auth_type = domain.get('authenticationType', '')
            enriched['dns_validated'] = auth_type == 'Managed' or auth_type == 'Federated'
        else:
            enriched['dns_validated'] = domain.get('isVerified', False)
        
        # Get domain services
        if 'supportedServices' in domain:
            services = domain.get('supportedServices', [])
            enriched['services'] = services
            enriched['has_email'] = 'Email' in services
            enriched['has_sharepoint'] = 'SharePoint' in services
            enriched['has_teams'] = 'Teams' in services
        
        # Add age information if available
        if 'createdDateTime' in domain:
            enriched['created_date'] = domain.get('createdDateTime')
            if self.check_domain_age:
                age_days = self._calculate_domain_age(domain.get('createdDateTime'))
                enriched['age_days'] = age_days
        
        return enriched
    
    def _classify_domain(self, domain_name: str, domain: Dict) -> str:
        """Classify domain into categories."""
        is_verified = domain.get('isVerified', False)
        is_default = domain.get('isDefault', False)
        
        # Default Microsoft domain
        if domain_name.endswith('.onmicrosoft.com'):
            return 'onmicrosoft'
        
        # Unverified domains
        if not is_verified:
            return 'unverified'
        
        # Check for legacy patterns
        if self._is_legacy_domain(domain_name):
            return 'legacy'
        
        # Check for external/partner domains
        if self._is_external_domain(domain_name):
            return 'external'
        
        # Default to vanity domain
        return 'vanity'
    
    def _is_high_risk_domain(self, domain_name: str) -> bool:
        """Check if domain matches high-risk patterns."""
        for pattern in self.HIGH_RISK_PATTERNS:
            if re.search(pattern, domain_name, re.IGNORECASE):
                return True
        
        # Check for IP address domains
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_name.split('.')[0]):
            return True
        
        # Check for local/internal domains
        if any(term in domain_name for term in ['.local', '.internal', '.test', '.demo']):
            return True
        
        return False
    
    def _get_risk_indicators(self, domain_name: str) -> List[str]:
        """Get specific risk indicators for a domain."""
        indicators = []
        
        for pattern in self.HIGH_RISK_PATTERNS:
            if re.search(pattern, domain_name, re.IGNORECASE):
                # Extract the pattern that matched
                match = re.search(pattern, domain_name, re.IGNORECASE)
                if match:
                    indicators.append(f"Matches high-risk pattern: {pattern}")
        
        # Additional checks
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_name.split('.')[0]):
            indicators.append("Uses IP address instead of domain name")
        
        if '.local' in domain_name or '.internal' in domain_name:
            indicators.append("Uses internal domain naming convention")
        
        return indicators
    
    def _is_legacy_domain(self, domain_name: str) -> bool:
        """Check if domain appears to be legacy."""
        legacy_indicators = [
            'old',
            'legacy',
            'deprecated',
            'archive',
            'historical',
            'previous'
        ]
        
        # Check domain name parts
        name_parts = domain_name.split('.')
        for part in name_parts:
            if any(indicator in part.lower() for indicator in legacy_indicators):
                return True
        
        return False
    
    def _is_external_domain(self, domain_name: str) -> bool:
        """Check if domain appears to be explicit external/partner subdomain."""
        # Only flag domains with explicit external/partner subdomain patterns.
        # A simple root domain like 'mockcorp.com' is the tenant's own domain.
        external_subdomains = ['partner', 'vendor', 'external', 'thirdparty', 'guest']
        parts = domain_name.split('.')
        if len(parts) > 2:
            # e.g. partner.contoso.com — flag the subdomain prefix
            subdomain = parts[0].lower()
            if any(ext in subdomain for ext in external_subdomains):
                return True
        return False
    
    def _calculate_domain_age(self, created_date: Optional[str]) -> Optional[int]:
        """Calculate domain age in days."""
        if not created_date:
            return None
        
        try:
            # Clean date string
            date_str = created_date.replace('Z', '').split('.')[0]
            created = datetime.fromisoformat(date_str)
            now = datetime.now()
            
            return (now - created).days
        except Exception:
            return None
    
    def _get_domains_from_mock_data(self) -> List[Dict[str, Any]]:
        """Get domains from mock data."""
        try:
            domains = self.graph_client.get_domains()
            
            # Enrich domains with classification
            enriched_domains = []
            for domain in domains:
                enriched = self._enrich_domain(domain)
                enriched_domains.append(enriched)
            
            return enriched_domains
            
        except Exception as e:
            logger.error(f"Error fetching domains from mock data: {e}")
            return []
    
    def _analyze_domains(self, domains: List[Dict]) -> Dict[str, Any]:
        """Analyze domains for compliance and security."""
        analysis = {
            'total_domains': len(domains),
            'compliant_domains': [],
            'non_compliant_domains': [],
            'warning_domains': [],
            'domain_categories': {},
            'high_risk_domains': [],
            'unverified_domains': [],
            'statistics': {
                'verified_count': 0,
                'unverified_count': 0,
                'default_domains': 0,
                'vanity_domains': 0,
                'external_domains': 0
            }
        }
        
        for domain in domains:
            domain_name = domain.get('id', 'unknown')
            category = domain.get('category', 'unknown')
            is_verified = domain.get('isVerified', False)
            is_default = domain.get('isDefault', False)
            
            # Update statistics
            if category in analysis['statistics']:
                analysis['statistics'][f"{category}_count"] = \
                    analysis['statistics'].get(f"{category}_count", 0) + 1
            
            # Track domain categories
            if category not in analysis['domain_categories']:
                analysis['domain_categories'][category] = []
            analysis['domain_categories'][category].append(domain_name)
            
            # Check for high-risk domains
            if domain.get('is_high_risk', False):
                high_risk_info = {
                    'domain': domain_name,
                    'category': category,
                    'risk_indicators': domain.get('risk_indicators', []),
                    'is_verified': is_verified
                }
                analysis['high_risk_domains'].append(high_risk_info)
            
            # Check verification status
            if not is_verified:
                analysis['unverified_domains'].append({
                    'domain': domain_name,
                    'category': category,
                    'is_default': is_default,
                    'age_days': domain.get('age_days'),
                    'allowed': domain_name in self.allowed_unverified
                })
            
            # Determine compliance status
            if not is_verified and domain_name not in self.allowed_unverified:
                # Unverified and not allowed
                domain_info = {
                    'domain': domain_name,
                    'category': category,
                    'reason': 'Domain is not verified',
                    'is_default': is_default,
                    'age_days': domain.get('age_days'),
                    'services': domain.get('services', [])
                }
                
                # Check if unverified for too long
                age_days = domain.get('age_days')
                if age_days and age_days > self.max_unverified_age_days:
                    domain_info['reason'] = f'Domain unverified for {age_days} days (limit: {self.max_unverified_age_days})'
                
                analysis['non_compliant_domains'].append(domain_info)
                
            elif domain.get('is_high_risk', False):
                # High-risk domain
                analysis['warning_domains'].append({
                    'domain': domain_name,
                    'category': category,
                    'reason': 'High-risk domain pattern detected',
                    'risk_indicators': domain.get('risk_indicators', []),
                    'is_verified': is_verified
                })
                
            elif category in ['legacy', 'external']:
                # Legacy or external domain (warning)
                analysis['warning_domains'].append({
                    'domain': domain_name,
                    'category': category,
                    'reason': f'{category.title()} domain detected',
                    'is_verified': is_verified,
                    'services': domain.get('services', [])
                })
                
            else:
                # Compliant domain
                analysis['compliant_domains'].append({
                    'domain': domain_name,
                    'category': category,
                    'is_default': is_default,
                    'is_verified': is_verified,
                    'services': domain.get('services', [])
                })
        
        # Update verification statistics
        analysis['statistics']['verified_count'] = sum(
            1 for d in domains if d.get('isVerified', False)
        )
        analysis['statistics']['unverified_count'] = len(analysis['unverified_domains'])
        
        return analysis
    
    def _create_check_result(self, analysis: Dict) -> CheckResult:
        """Create the final check result."""
        total = analysis['total_domains']
        compliant = len(analysis['compliant_domains'])
        non_compliant = len(analysis['non_compliant_domains'])
        warning = len(analysis['warning_domains'])
        high_risk = len(analysis['high_risk_domains'])
        
        # Determine overall status
        if non_compliant == 0:
            if warning == 0:
                status = CheckStatus.PASS
            else:
                status = CheckStatus.WARNING
        else:
            status = CheckStatus.FAIL
        
        # Build details
        details = []
        
        if status == CheckStatus.PASS:
            details.append(f"✅ All {total} domains are compliant")
        elif status == CheckStatus.WARNING:
            details.append(f"⚠️ WARNING: Domain configuration needs review")
        else:
            details.append(f"❌ FAILURE: {non_compliant} non-compliant domain(s) found")
        
        details.append(f"Total domains analyzed: {total}")
        details.append(f"• Compliant domains: {compliant}")
        details.append(f"• Non-compliant domains: {non_compliant}")
        details.append(f"• Warning domains: {warning}")
        details.append(f"• High-risk domains: {high_risk}")
        
        # Add domain statistics
        details.append("")
        details.append("DOMAIN STATISTICS:")
        stats = analysis['statistics']
        details.append(f"• Verified domains: {stats.get('verified_count', 0)}")
        details.append(f"• Unverified domains: {stats.get('unverified_count', 0)}")
        
        if stats.get('onmicrosoft_count', 0) > 0:
            details.append(f"• *.onmicrosoft.com domains: {stats.get('onmicrosoft_count', 0)}")
        
        if stats.get('vanity_count', 0) > 0:
            details.append(f"• Vanity domains: {stats.get('vanity_count', 0)}")
        
        # Add non-compliant domains
        if analysis['non_compliant_domains']:
            details.append("")
            details.append("NON-COMPLIANT DOMAINS:")
            for domain in analysis['non_compliant_domains'][:5]:  # Show top 5
                age_info = ""
                if domain.get('age_days'):
                    age_info = f" ({domain['age_days']} days old)"
                details.append(f"• {domain['domain']}{age_info} - {domain['reason']}")
            
            if len(analysis['non_compliant_domains']) > 5:
                details.append(f"  ... and {len(analysis['non_compliant_domains']) - 5} more")
        
        # Add warning domains
        if analysis['warning_domains']:
            details.append("")
            details.append("WARNING DOMAINS:")
            for domain in analysis['warning_domains'][:3]:
                if domain['category'] == 'high_risk':
                    details.append(f"• ⚠️ {domain['domain']} - High-risk pattern detected")
                else:
                    details.append(f"• ⚠️ {domain['domain']} - {domain['reason']}")
        
        # Add high-risk domain details
        if analysis['high_risk_domains']:
            details.append("")
            details.append("HIGH-RISK DOMAINS:")
            for domain in analysis['high_risk_domains'][:3]:
                verified_status = "Verified" if domain['is_verified'] else "Unverified"
                details.append(f"• 🔴 {domain['domain']} ({verified_status})")
                for indicator in domain.get('risk_indicators', [])[:2]:
                    details.append(f"  - {indicator}")
        
        # Add allowed unverified domains
        allowed_unverified = [
            d for d in analysis['unverified_domains'] if d.get('allowed')
        ]
        if allowed_unverified:
            details.append("")
            details.append("ALLOWED UNVERIFIED DOMAINS:")
            for domain in allowed_unverified:
                details.append(f"• {domain['domain']} (Explicitly allowed)")
        
        # Add recommendations
        details.append("")
        details.append("RECOMMENDATIONS:")
        
        if analysis['non_compliant_domains']:
            details.extend([
                "1. VERIFY UNVERIFIED DOMAINS:",
                "   • Azure Portal → Azure Active Directory → Custom domain names",
                "   • Select unverified domain → Verify",
                "   • Add TXT or MX record to DNS as instructed",
                "   • Click 'Verify' after DNS changes propagate",
                "",
                "2. REMOVE UNNECESSARY DOMAINS:",
                "   • Review and remove domains no longer in use",
                "   • Consider impact on users and services before removal",
                "   • Update any applications using the domain",
                ""
            ])
        
        if analysis['high_risk_domains']:
            details.extend([
                "3. ADDRESS HIGH-RISK DOMAINS:",
                "   • Replace test/local domains with proper domains",
                "   • Update applications to use verified domains",
                "   • Remove domains with suspicious patterns",
                ""
            ])
        
        details.extend([
            "4. DOMAIN MANAGEMENT BEST PRACTICES:",
            "   • Use company-branded domains for user identities",
            "   • Keep *.onmicrosoft.com as fallback only",
            "   • Regularly review and audit domain configurations",
            "   • Implement domain lifecycle management",
            "",
            "5. DNS CONFIGURATION:",
            "   • Ensure proper MX records for email delivery",
            "   • Configure SPF, DKIM, and DMARC for email security",
            "   • Set up proper CNAME records for services",
            "   • Monitor DNS health and expiration"
        ])
        
        # Add compliance guidance
        details.extend([
            "",
            "COMPLIANCE GUIDANCE:",
            "• CIS Control 2.1: Ensure only approved domains are used",
            "• NIST CSF: PR.AC-5: Network integrity is protected",
            "• ISO 27001: A.13.1.3: Segregation in networks"
        ])
        
        # Create result
        non_compliant_resources = []
        if status != CheckStatus.PASS:
            non_compliant_resources = analysis['non_compliant_domains']
            
            # Add warning domains if in warning status
            if status == CheckStatus.WARNING:
                non_compliant_resources.extend(analysis['warning_domains'])
        
        return self.create_result(
            status=status,
            details="\n".join(details),
            non_compliant_resources=non_compliant_resources,
            non_compliant_count=non_compliant,
            compliant_count=compliant,
            total_count=total,
            metadata={
                'total_domains': total,
                'verified_domains': stats.get('verified_count', 0),
                'unverified_domains': stats.get('unverified_count', 0),
                'high_risk_domains': high_risk,
                'domain_categories': analysis['domain_categories'],
                'max_unverified_age_days': self.max_unverified_age_days,
                'allowed_unverified_count': len(allowed_unverified),
                'check_timestamp': datetime.now().isoformat()
            }
        )
    
    def get_configuration_help(self) -> Dict[str, Any]:
        """Provide configuration guidance for this check."""
        return {
            'description': 'Configure domain verification check settings',
            'fields': [
                {
                    'name': 'allowed_unverified',
                    'type': 'array',
                    'default': [],
                    'description': 'Domains allowed to remain unverified',
                    'help': 'Use for temporary domains or migration scenarios'
                },
                {
                    'name': 'check_domain_age',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Check age of unverified domains',
                    'help': 'Flags domains unverified for too long'
                },
                {
                    'name': 'max_unverified_age_days',
                    'type': 'number',
                    'default': 30,
                    'description': 'Maximum days a domain can remain unverified',
                    'help': 'After this period, domain is flagged as non-compliant'
                },
                {
                    'name': 'require_dns_validation',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Require proper DNS validation',
                    'help': 'Ensures domains have proper DNS records configured'
                },
                {
                    'name': 'check_high_risk_patterns',
                    'type': 'boolean',
                    'default': True,
                    'description': 'Check for high-risk domain patterns',
                    'help': 'Flags test/local/internal domains'
                }
            ],
            'domain_categories': self.DOMAIN_CATEGORIES,
            'high_risk_patterns': self.HIGH_RISK_PATTERNS[:10],  # Show first 10
            'recommendations': [
                'Verify all domains used in production',
                'Remove unused or test domains',
                'Use company-branded domains for user identities',
                'Regularly audit domain configurations',
                'Implement domain lifecycle management'
            ]
        }