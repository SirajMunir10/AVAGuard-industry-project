from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus
import logging
from typing import List, Dict, Any, Optional, Set
import re

logger = logging.getLogger(__name__)

class Check_1_23_CustomRoles(BaseCheck):
    CHECK_ID = "1.23"
    TITLE = "Ensure that no custom subscription owner roles exist"
    DESCRIPTION = "Custom roles with Owner permissions violate least privilege"
    REQUIRES_PREMIUM = False
    
    # Standard built-in role definitions from Azure
    STANDARD_BUILTIN_ROLES = {
        # Global roles
        "Global Administrator": {
            "templateId": "62e90394-69f5-4237-9190-012177145e10",
            "permissionLevel": "owner"
        },
        "Privileged Role Administrator": {
            "templateId": "e8611ab8-c189-46e8-94e1-60213ab1f814",
            "permissionLevel": "owner"
        },
        # Administrative roles
        "User Administrator": {
            "templateId": "fe930be7-5e62-47db-91af-98c3a49a38b1",
            "permissionLevel": "admin"
        },
        "Security Administrator": {
            "templateId": "194ae4cb-b126-40b2-bc5e-47205b6c23b2",
            "permissionLevel": "admin"
        },
        "Application Administrator": {
            "templateId": "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
            "permissionLevel": "admin"
        },
        # Reader roles
        "Global Reader": {
            "templateId": "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
            "permissionLevel": "reader"
        },
        "Directory Readers": {
            "templateId": "88d8e3e3-8f55-4a1e-953a-9b9898b8876b",
            "permissionLevel": "reader"
        },
        # Service-specific roles
        "Exchange Administrator": {
            "templateId": "29232cdf-9323-42fd-ade2-1d097af3e4de",
            "permissionLevel": "admin"
        },
        "SharePoint Administrator": {
            "templateId": "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
            "permissionLevel": "admin"
        },
        "Teams Administrator": {
            "templateId": "69091246-20e8-4a56-b4d2-92ace7f8b7b8",
            "permissionLevel": "admin"
        }
    }
    
    # High-risk custom role indicators (permissions that could grant owner-level access)
    HIGH_RISK_PERMISSIONS = [
        "*",  # Wildcard permissions
        "microsoft.authorization/*/write",
        "microsoft.authorization/roleassignments/write",
        "microsoft.authorization/roledefinitions/write",
        "microsoft.authorization/policyassignments/write",
        "microsoft.authorization/policydefinitions/write",
        "microsoft.azureactivedirectory/*",
        "microsoft.directory/applications/allproperties/alltasks",
        "microsoft.directory/users/allproperties/alltasks",
        "microsoft.directory/groups/allproperties/alltasks",
        "microsoft.subscription/subscriptions/write",
        "microsoft.subscription/subscriptions/delete",
        "microsoft.management/managementgroups/write"
    ]
    
    def __init__(self, graph_client, config: Optional[Dict] = None):
        super().__init__(graph_client, config)
        self.config = config or {}
        self.include_high_risk_only = self.config.get('include_high_risk_only', False)
        self.whitelist_custom_roles = set(self.config.get('whitelist_custom_roles', []))
        self.high_risk_threshold = self.config.get('high_risk_threshold', 3)  # Number of high-risk permissions
    
    def execute(self) -> CheckResult:
        """Execute the custom roles check."""
        logger.info(f"Executing check {self.CHECK_ID}")
        
        try:
            # Fetch directory roles
            directory_roles = self._fetch_directory_roles()
            
            if not directory_roles:
                return self.create_result(
                    CheckStatus.PASS,
                    details="No directory roles found to check",
                    total_count=0
                )
            
            # Analyze roles for compliance
            analysis = self._analyze_roles(directory_roles)
            
            # Generate result
            return self._create_check_result(analysis)
            
        except Exception as e:
            logger.error(f"Error executing {self.CHECK_ID}: {str(e)}", exc_info=True)
            return self.create_result(
                status=CheckStatus.ERROR,
                details=f"Error checking custom roles: {str(e)}",
                total_count=0
            )
    
    def _fetch_directory_roles(self) -> List[Dict[str, Any]]:
        """Fetch directory roles from Graph API."""
        logger.info("Fetching directory roles...")
        
        try:
            # Get directory roles
            roles_response = self.graph_client.get("/directoryRoles")
            roles = roles_response.get('value', [])
            
            # For real Azure API, also get role definitions
            if self._is_real_api_connection():
                # Try to get more detailed role definitions from Azure API
                detailed_roles = self._fetch_role_definitions()
                roles = self._enrich_roles_with_definitions(roles, detailed_roles)
            
            return roles
            
        except Exception as e:
            logger.error(f"Error fetching directory roles: {e}")
            return []
    
    def _is_real_api_connection(self) -> bool:
        """Determine if we're connected to real Azure API or mock data."""
        # Check if graph client has real API attributes
        if hasattr(self.graph_client, 'is_mock_client'):
            return not self.graph_client.is_mock_client
        
        # Check for Azure-specific attributes
        if hasattr(self.graph_client, 'tenant_id') and hasattr(self.graph_client, 'token'):
            return bool(self.graph_client.tenant_id and self.graph_client.token)
            
        # Default assumption - treat as mock
        return False
    
    def _fetch_role_definitions(self) -> List[Dict[str, Any]]:
        """Fetch detailed role definitions for real Azure API."""
        # Note: This would require Azure Resource Manager API access
        # For Graph API, we work with what's available
        
        try:
            # Try to get role definitions from Graph API
            # This endpoint may require additional permissions
            response = self.graph_client.get("/roleManagement/directory/roleDefinitions")
            return response.get('value', [])
        except Exception as e:
            logger.warning(f"Could not fetch role definitions: {e}")
            return []
    
    def _enrich_roles_with_definitions(self, roles: List[Dict], 
                                       definitions: List[Dict]) -> List[Dict]:
        """Enrich roles with definition details."""
        definition_map = {d.get('displayName'): d for d in definitions if d.get('displayName')}
        
        enriched_roles = []
        for role in roles:
            role_name = role.get('displayName')
            if role_name in definition_map:
                definition = definition_map[role_name]
                # Merge definition details into role
                enriched_role = role.copy()
                enriched_role.update({
                    'description': definition.get('description', ''),
                    'rolePermissions': definition.get('rolePermissions', []),
                    'isBuiltIn': definition.get('isBuiltIn', True),
                    'templateId': definition.get('templateId')
                })
                enriched_roles.append(enriched_role)
            else:
                # Add default values
                role_copy = role.copy()
                role_copy.update({
                    'description': role.get('description', ''),
                    'isBuiltIn': role.get('isSystem', True),
                    'templateId': role.get('roleTemplateId')
                })
                enriched_roles.append(role_copy)
        
        return enriched_roles
    
    def _analyze_roles(self, roles: List[Dict]) -> Dict[str, Any]:
        """Analyze roles for custom definitions and high-risk permissions."""
        non_compliant = []
        compliant_count = 0
        high_risk_custom_roles = []
        whitelisted_custom_roles = []
        
        for role in roles:
            role_name = role.get('displayName', 'Unknown Role')
            role_id = role.get('id', 'unknown')
            
            # Check if this is a whitelisted custom role
            if role_name in self.whitelist_custom_roles:
                whitelisted_custom_roles.append(role_name)
                compliant_count += 1
                continue
            
            # Determine if role is built-in or custom
            is_builtin = self._is_builtin_role(role)
            
            if is_builtin:
                compliant_count += 1
            else:
                # This is a custom role - check if it's high risk
                risk_level, risk_reasons = self._assess_role_risk(role)
                
                if self.include_high_risk_only and risk_level != "high":
                    # Only tracking high-risk custom roles
                    compliant_count += 1
                    continue
                
                # Create finding
                finding = {
                    'roleName': role_name,
                    'roleId': role_id,
                    'description': role.get('description', 'No description'),
                    'riskLevel': risk_level,
                    'reasons': risk_reasons,
                    'templateId': role.get('templateId'),
                    'isBuiltIn': is_builtin
                }
                
                if risk_level == "high":
                    high_risk_custom_roles.append(finding)
                    non_compliant.append(finding)
                else:
                    non_compliant.append(finding)
        
        return {
            'non_compliant_roles': non_compliant,
            'high_risk_custom_roles': high_risk_custom_roles,
            'whitelisted_custom_roles': whitelisted_custom_roles,
            'compliant_count': compliant_count,
            'total_roles': len(roles)
        }
    
    def _is_builtin_role(self, role: Dict) -> bool:
        """Determine if a role is built-in or custom."""
        # Check multiple indicators
        role_name = role.get('displayName', '').lower()
        template_id = role.get('templateId')
        
        # Check if role name is in standard built-in roles
        for builtin_name in self.STANDARD_BUILTIN_ROLES:
            if builtin_name.lower() == role_name:
                return True
        
        # Check if has isBuiltIn or isSystem flag
        if role.get('isBuiltIn') is True or role.get('isSystem') is True:
            return True
        
        # Check templateId against known built-in templates
        if template_id:
            for builtin_role in self.STANDARD_BUILTIN_ROLES.values():
                if template_id == builtin_role['templateId']:
                    return True
        
        # Check for Microsoft naming patterns
        if self._has_microsoft_naming_pattern(role_name):
            return True
        
        return False
    
    def _has_microsoft_naming_pattern(self, role_name: str) -> bool:
        """Check if role name follows Microsoft naming patterns."""
        # Microsoft built-in roles often follow specific patterns
        microsoft_patterns = [
            r'^.*administrator$',
            r'^.*reader$',
            r'^.*contributor$',
            r'^global.*$',
            r'^privileged.*$',
            r'^security.*$',
            r'^user.*$',
            r'^application.*$',
            r'^directory.*$',
            r'^exchange.*$',
            r'^sharepoint.*$',
            r'^teams.*$'
        ]
        
        for pattern in microsoft_patterns:
            if re.match(pattern, role_name, re.IGNORECASE):
                return True
        
        return False
    
    def _assess_role_risk(self, role: Dict) -> tuple:
        """Assess the risk level of a custom role."""
        risk_reasons = []
        
        # Check description for owner-like permissions
        description = role.get('description', '').lower()
        if any(term in description for term in ['owner', 'full access', 'unrestricted', 'all permissions']):
            risk_reasons.append("Description indicates owner-level permissions")
        
        # Check role name for risk indicators
        role_name = role.get('displayName', '').lower()
        risk_indicators = ['owner', 'superadmin', 'fullcontrol', 'godmode', 'breakglass']
        for indicator in risk_indicators:
            if indicator in role_name:
                risk_reasons.append(f"Role name contains risk indicator: '{indicator}'")
        
        # Check permissions (if available)
        permissions = role.get('rolePermissions', [])
        if permissions:
            high_risk_count = 0
            for permission in permissions:
                # Check for high-risk permission patterns
                perm_str = str(permission).lower()
                for high_risk_perm in self.HIGH_RISK_PERMISSIONS:
                    if high_risk_perm.lower() in perm_str:
                        high_risk_count += 1
                        risk_reasons.append(f"Contains high-risk permission: {high_risk_perm}")
            
            if high_risk_count >= self.high_risk_threshold:
                risk_reasons.append(f"Contains {high_risk_count} high-risk permission(s)")
        
        # Determine risk level
        if len(risk_reasons) >= 3:
            return "high", risk_reasons
        elif len(risk_reasons) >= 1:
            return "medium", risk_reasons
        else:
            return "low", ["Custom role detected"]
    
    def _create_check_result(self, analysis: Dict) -> CheckResult:
        """Create the final check result from analysis."""
        non_compliant = analysis['non_compliant_roles']
        high_risk_custom = analysis['high_risk_custom_roles']
        whitelisted = analysis['whitelisted_custom_roles']
        compliant_count = analysis['compliant_count']
        total_roles = analysis['total_roles']
        
        if not non_compliant:
            details = [
                f"No custom roles found ({total_roles} roles checked)",
                f"Built-in roles: {compliant_count}",
                f"Whitelisted custom roles: {len(whitelisted)}"
            ]
            
            return self.create_result(
                status=CheckStatus.PASS,
                details="\n".join(details),
                compliant_count=compliant_count,
                total_count=total_roles
            )
        
        # Create detailed breakdown
        details = [
            f"Found {len(non_compliant)} custom role(s):",
            f"• High-risk custom roles: {len(high_risk_custom)}",
            f"• Total custom roles: {len(non_compliant)}",
            f"• Built-in roles: {compliant_count}",
            f"• Whitelisted custom roles: {len(whitelisted)}",
            f"• Total scanned: {total_roles}",
            ""
        ]
        
        # Add high-risk custom roles details
        if high_risk_custom:
            details.append("HIGH-RISK CUSTOM ROLES:")
            for i, role in enumerate(high_risk_custom[:5], 1):
                details.append(f"  {i}. {role['roleName']}")
                for reason in role['reasons'][:2]:  # Show top 2 reasons
                    details.append(f"     - {reason}")
                details.append("")
        
        # Add medium/low risk custom roles count
        medium_low_count = len(non_compliant) - len(high_risk_custom)
        if medium_low_count > 0:
            details.append(f"Medium/Low risk custom roles: {medium_low_count}")
        
        # Add recommendations
        details.extend([
            "",
            "RECOMMENDATIONS:",
            "1. Review all custom roles for necessity and permissions",
            "2. Remove or restrict high-risk custom roles",
            "3. Ensure custom roles follow least privilege principle",
            "4. Document business justification for custom roles",
            "5. Implement regular review process for custom roles"
        ])
        
        # Create compliance result
        status = CheckStatus.FAIL
        if len(high_risk_custom) == 0 and len(non_compliant) > 0:
            # Only low/medium risk custom roles
            details.insert(0, "⚠️ WARNING: Custom roles found but no high-risk roles detected")
            status = CheckStatus.WARNING
        
        return self.create_result(
            status=status,
            details="\n".join(details),
            non_compliant_resources=non_compliant,
            non_compliant_count=len(non_compliant),
            compliant_count=compliant_count,
            total_count=total_roles,
            metadata={
                'high_risk_custom_roles': len(high_risk_custom),
                'whitelisted_custom_roles': len(whitelisted),
                'risk_assessment_threshold': self.high_risk_threshold,
                'analysis_timestamp': self._get_timestamp()
            }
        )
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def get_configuration_help(self) -> Dict[str, Any]:
        """Provide configuration guidance for this check."""
        return {
            'description': 'Configure custom role detection settings',
            'fields': [
                {
                    'name': 'include_high_risk_only',
                    'type': 'boolean',
                    'default': False,
                    'description': 'Only flag high-risk custom roles',
                    'help': 'When enabled, only custom roles with owner-like permissions are flagged'
                },
                {
                    'name': 'high_risk_threshold',
                    'type': 'number',
                    'default': 3,
                    'description': 'Number of high-risk permissions to trigger high-risk classification',
                    'help': 'Lower values make the check more sensitive'
                },
                {
                    'name': 'whitelist_custom_roles',
                    'type': 'array',
                    'default': [],
                    'description': 'List of custom role names to whitelist',
                    'help': 'e.g., ["App-Specific-Admin", "Limited-Support-Role"]'
                }
            ],
            'recommendations': [
                'Use Azure PIM for privileged role assignments',
                'Regularly audit custom role definitions and usage',
                'Document business justification for each custom role',
                'Implement approval workflows for custom role creation',
                'Review role assignments at least quarterly'
            ],
            'high_risk_permissions': self.HIGH_RISK_PERMISSIONS[:10]  # Show first 10
        }
    
    def get_standard_roles_reference(self) -> Dict[str, Dict]:
        """Get reference of standard built-in roles for reporting."""
        return self.STANDARD_BUILTIN_ROLES.copy()