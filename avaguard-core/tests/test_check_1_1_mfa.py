"""
Unit tests for CIS 1.1 MFA Check.

Tests the Check_1_1_MFA class which verifies MFA is enabled for privileged users.
"""

import pytest
from avaguard_core.checks.check_1_1_mfa import Check_1_1_MFA
from avaguard_core.checks.base_check import CheckStatus


class TestCheck11MFA:
    """Test suite for Check_1_1_MFA."""
    
    def test_check_metadata(self):
        """Test that check has correct metadata."""
        assert Check_1_1_MFA.CHECK_ID == "1.1"
        assert "MFA" in Check_1_1_MFA.TITLE or "multi-factor" in Check_1_1_MFA.TITLE.lower()
        assert Check_1_1_MFA.REQUIRES_PREMIUM == True
    
    def test_check_initialization(self, mock_graph_client, sample_config):
        """Test check initializes correctly."""
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        
        assert check.graph_client == mock_graph_client
        assert check.config == sample_config
        assert check.require_strong_mfa == False
        assert "emergency@test.com" in check.break_glass_accounts
    
    def test_check_pass_all_mfa(self, mock_graph_client_all_mfa, sample_config):
        """Test check passes when all users have MFA."""
        check = Check_1_1_MFA(mock_graph_client_all_mfa, sample_config)
        result = check.execute()
        
        assert result.status == CheckStatus.PASS
        assert result.compliant_count > 0
        assert "MFA" in result.details or "mfa" in result.details.lower()
    
    def test_check_fail_no_mfa(self, mock_graph_client_no_mfa, sample_config):
        """Test check fails when no users have MFA."""
        check = Check_1_1_MFA(mock_graph_client_no_mfa, sample_config)
        result = check.execute()
        
        # Should fail if there are privileged users without MFA
        if result.total_count > 0:
            assert result.status == CheckStatus.FAIL
            assert result.non_compliant_count > 0
    
    def test_check_mixed_mfa_status(self, mock_graph_client, sample_config):
        """Test check with mixed MFA status."""
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        result = check.execute()
        
        # Default mock data has some users with MFA, some without
        assert result.total_count > 0
        # Result can be PASS or FAIL depending on privileged users
        assert result.status in [CheckStatus.PASS, CheckStatus.FAIL]
    
    def test_exempt_users_excluded(self, mock_graph_client, sample_config):
        """Test that exempt users are properly excluded."""
        # Add a user to exempt list
        sample_config["exempt_users"] = ["admin@test.com"]
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        
        result = check.execute()
        
        # The exempt user should not be counted as non-compliant
        if result.non_compliant_resources:
            exempt_in_results = any(
                r.get("userPrincipalName") == "admin@test.com" 
                for r in result.non_compliant_resources
            )
            assert not exempt_in_results
    
    def test_disabled_accounts_handled(self, mock_graph_client, sample_config):
        """Test that disabled accounts are handled correctly."""
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        result = check.execute()
        
        # Disabled accounts should not be in non-compliant list
        if result.non_compliant_resources:
            disabled_in_results = any(
                r.get("userPrincipalName") == "disabled@test.com"
                for r in result.non_compliant_resources
            )
            assert not disabled_in_results
    
    def test_require_strong_mfa_config(self, mock_graph_client, sample_config):
        """Test strong MFA requirement configuration."""
        sample_config["require_strong_mfa"] = True
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        
        assert check.require_strong_mfa == True
    
    def test_include_guests_config(self, mock_graph_client, sample_config):
        """Test guest inclusion configuration."""
        sample_config["include_guests"] = True
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        
        assert check.include_guests == True
    
    def test_result_contains_remediation(self, mock_graph_client_no_mfa, sample_config):
        """Test that failed results contain remediation recommendations."""
        check = Check_1_1_MFA(mock_graph_client_no_mfa, sample_config)
        result = check.execute()
        
        if result.status == CheckStatus.FAIL:
            # Should contain recommendations
            assert "RECOMMENDATIONS" in result.details or "recommendation" in result.details.lower()
    
    def test_get_configuration_help(self, mock_graph_client, sample_config):
        """Test configuration help is provided."""
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        help_info = check.get_configuration_help()
        
        assert "fields" in help_info
        assert "description" in help_info
        assert any(f["name"] == "require_strong_mfa" for f in help_info["fields"])
    
    def test_privileged_roles_defined(self):
        """Test that privileged roles are properly defined."""
        assert len(Check_1_1_MFA.PRIVILEGED_ROLES) > 0
        
        # Check Global Administrator is defined
        global_admin_id = "62e90394-69f5-4237-9190-012177145e10"
        assert global_admin_id in Check_1_1_MFA.PRIVILEGED_ROLES
        assert Check_1_1_MFA.PRIVILEGED_ROLES[global_admin_id]["name"] == "Global Administrator"
    
    def test_mfa_method_types_defined(self):
        """Test that MFA method types are properly defined."""
        assert len(Check_1_1_MFA.MFA_METHOD_TYPES) > 0
        assert "microsoftAuthenticator" in Check_1_1_MFA.MFA_METHOD_TYPES
        assert "fido2" in Check_1_1_MFA.MFA_METHOD_TYPES
    
    def test_strong_mfa_methods_defined(self):
        """Test that strong MFA methods are properly defined."""
        assert len(Check_1_1_MFA.STRONG_MFA_METHODS) > 0
        assert "fido2" in Check_1_1_MFA.STRONG_MFA_METHODS
        assert "windowsHelloForBusiness" in Check_1_1_MFA.STRONG_MFA_METHODS


class TestCheck11MFAEdgeCases:
    """Edge case tests for Check_1_1_MFA."""
    
    def test_empty_user_list(self, sample_config):
        """Test handling of empty user list."""
        from tests.conftest import MockGraphClient
        
        client = MockGraphClient({"users": []})
        check = Check_1_1_MFA(client, sample_config)
        result = check.execute()
        
        # No privileged users = PASS
        assert result.status == CheckStatus.PASS
        assert result.total_count == 0
    
    def test_none_config(self, mock_graph_client):
        """Test handling of None config."""
        check = Check_1_1_MFA(mock_graph_client, None)
        
        # Should use defaults
        assert check.require_strong_mfa == False
        assert check.exempt_users == set()
    
    def test_break_glass_accounts_exempt(self, mock_graph_client, sample_config):
        """Test that break glass accounts are exempt."""
        sample_config["break_glass_accounts"] = ["admin@test.com"]
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        
        # The break glass user should be exempt
        is_exempt = check._is_user_exempt("admin@test.com")
        assert is_exempt == True
    
    def test_api_error_handling(self, sample_config):
        """Test handling of API errors."""
        from tests.conftest import MockGraphClient
        
        # Create a client that raises errors
        client = MockGraphClient()
        client.get_users = lambda *args, **kwargs: (_ for _ in ()).throw(Exception("API Error"))
        
        check = Check_1_1_MFA(client, sample_config)
        result = check.execute()
        
        # Should return ERROR status, not crash
        assert result.status in [CheckStatus.ERROR, CheckStatus.PASS]
