# avaguard-core/avaguard_core/checks/__init__.py
"""
AVAGuard Compliance Checks Registry - Updated to use dictionary format.
"""

from .base_check import BaseCheck, CheckResult, CheckStatus, CISSeverity

# Import using your actual class names
from .check_1_1_mfa import Check_1_1_MFA
from .check_1_3_security_defaults import Check_1_3_SecurityDefaults
from .check_1_5_guest_roles import Check_1_5_GuestRoles
from .check_1_8_sspr import Check_1_8_SSPR
from .check_1_11_legacy_auth import Check_1_11_LegacyAuth
from .check_1_23_custom_roles import Check_1_23_CustomRoles
from .check_2_1_domains import Check_2_1_Domains
from .check_3_1_signin_risk import Check_3_1_SigninRisk
from .check_inactive_users import Check_InactiveUsers
from .check_password_age import Check_PasswordAge

from typing import Dict, Type
from avaguard_core.checks.protocol import CheckProtocol

# Create dictionary mapping (check_id -> class)
AVAILABLE_CHECKS: Dict[str, Type[CheckProtocol]] = {
    "1.1": Check_1_1_MFA,
    "1.3": Check_1_3_SecurityDefaults,
    "1.5": Check_1_5_GuestRoles,
    "1.8": Check_1_8_SSPR,
    "1.11": Check_1_11_LegacyAuth,
    "1.23": Check_1_23_CustomRoles,
    "2.1": Check_2_1_Domains,
    "3.1": Check_3_1_SigninRisk,
    "inactive_users": Check_InactiveUsers,
    "password_age": Check_PasswordAge,
}

# Define tier-based access using dictionary
FREE_TIER_CHECKS: Dict[str, Type[CheckProtocol]] = {
    "1.3": Check_1_3_SecurityDefaults,
    "1.5": Check_1_5_GuestRoles,
    "1.11": Check_1_11_LegacyAuth,
    "1.23": Check_1_23_CustomRoles,
    "2.1": Check_2_1_Domains,
    "password_age": Check_PasswordAge,
}

PREMIUM_CHECKS: Dict[str, Type[CheckProtocol]] = {
    "1.1": Check_1_1_MFA,
    "1.8": Check_1_8_SSPR,
    "3.1": Check_3_1_SigninRisk,
    "inactive_users": Check_InactiveUsers,
}

# For backward compatibility, also keep the lists
AVAILABLE_CHECKS_LIST = [
    Check_1_1_MFA,
    Check_1_3_SecurityDefaults,
    Check_1_5_GuestRoles,
    Check_1_8_SSPR,
    Check_1_11_LegacyAuth,
    Check_1_23_CustomRoles,
    Check_2_1_Domains,
    Check_3_1_SigninRisk,
    Check_PasswordAge,
    Check_InactiveUsers
]

PREMIUM_CHECKS_LIST = [
    Check_1_1_MFA,
    Check_1_8_SSPR,
    Check_3_1_SigninRisk,
    Check_InactiveUsers
]

FREE_TIER_CHECKS_LIST = [
    c for c in AVAILABLE_CHECKS_LIST if c not in PREMIUM_CHECKS_LIST
]

# Export everything
__all__ = [
    'BaseCheck', 'CheckResult', 'CheckStatus', 'CISSeverity',
    
    # Dictionaries (for desktop app)
    'AVAILABLE_CHECKS', 'FREE_TIER_CHECKS', 'PREMIUM_CHECKS',
    
    # Lists (for backward compatibility)
    'AVAILABLE_CHECKS_LIST', 'FREE_TIER_CHECKS_LIST', 'PREMIUM_CHECKS_LIST',
    
    # Individual check classes
    'Check_1_1_MFA', 'Check_1_3_SecurityDefaults', 'Check_1_5_GuestRoles',
    'Check_1_8_SSPR', 'Check_1_11_LegacyAuth', 'Check_1_23_CustomRoles',
    'Check_2_1_Domains', 'Check_3_1_SigninRisk', 'Check_InactiveUsers',
    'Check_PasswordAge'
]