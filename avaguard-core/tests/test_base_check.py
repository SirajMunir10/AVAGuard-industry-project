"""
Unit tests for BaseCheck and CheckResult classes.

Tests the foundation classes that all checks inherit from.
"""

import pytest
from dataclasses import fields
from avaguard_core.checks.base_check import (
    BaseCheck, 
    CheckResult, 
    CheckStatus, 
    CISSeverity
)


class TestCheckStatus:
    """Tests for CheckStatus enum."""
    
    def test_status_values_exist(self):
        """Test all required status values exist."""
        assert CheckStatus.PASS
        assert CheckStatus.FAIL
        assert CheckStatus.WARNING
        assert CheckStatus.ERROR
        assert CheckStatus.SKIPPED
    
    def test_severity_ordering(self):
        """Test severity ordering is correct (higher = more critical)."""
        assert CheckStatus.FAIL.severity > CheckStatus.WARNING.severity
        assert CheckStatus.WARNING.severity > CheckStatus.PASS.severity
        assert CheckStatus.FAIL.severity > CheckStatus.ERROR.severity  # FAIL (4) > ERROR (3)


class TestCISSeverity:
    """Tests for CISSeverity enum."""
    
    def test_severity_values_exist(self):
        """Test all severity levels exist."""
        assert CISSeverity.CRITICAL
        assert CISSeverity.HIGH
        assert CISSeverity.MEDIUM
        assert CISSeverity.LOW


class TestCheckResult:
    """Tests for CheckResult dataclass."""
    
    def test_result_creation(self):
        """Test creating a CheckResult."""
        result = CheckResult(
            check_id="1.1",
            title="Test Check",
            status=CheckStatus.PASS,
            compliant_count=10,
            total_count=10
        )
        
        assert result.check_id == "1.1"
        assert result.title == "Test Check"
        assert result.status == CheckStatus.PASS
        assert result.compliant_count == 10
        assert result.total_count == 10
    
    def test_compliance_percentage_full(self):
        """Test compliance percentage when fully compliant."""
        result = CheckResult(
            check_id="1.1",
            title="Test",
            status=CheckStatus.PASS,
            compliant_count=10,
            total_count=10
        )
        
        assert result.compliance_percentage == 100.0
    
    def test_compliance_percentage_partial(self):
        """Test compliance percentage when partially compliant."""
        result = CheckResult(
            check_id="1.1",
            title="Test",
            status=CheckStatus.FAIL,
            compliant_count=7,
            total_count=10
        )
        
        assert result.compliance_percentage == 70.0
    
    def test_compliance_percentage_zero(self):
        """Test compliance percentage when non-compliant."""
        result = CheckResult(
            check_id="1.1",
            title="Test",
            status=CheckStatus.FAIL,
            compliant_count=0,
            total_count=10
        )
        
        assert result.compliance_percentage == 0.0
    
    def test_compliance_percentage_no_total(self):
        """Test compliance percentage when total is zero."""
        result = CheckResult(
            check_id="1.1",
            title="Test",
            status=CheckStatus.PASS,
            compliant_count=0,
            total_count=0
        )
        
        assert result.compliance_percentage == 100.0  # No items = compliant
    
    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = CheckResult(
            check_id="1.1",
            title="Test Check",
            status=CheckStatus.PASS,
            compliant_count=10,
            total_count=10,
            details="All good"
        )
        
        result_dict = result.to_dict()
        
        assert isinstance(result_dict, dict)
        assert result_dict["check_id"] == "1.1"
        assert result_dict["title"] == "Test Check"
        assert result_dict["status"] == "PASS"
        assert "compliance_percentage" in result_dict
    
    def test_to_audit_format(self):
        """Test converting result to audit format."""
        result = CheckResult(
            check_id="1.1",
            title="Test Check",
            status=CheckStatus.FAIL,
            compliant_count=5,
            non_compliant_count=5,
            total_count=10
        )
        
        audit_format = result.to_audit_format()
        
        assert isinstance(audit_format, dict)
        assert "control" in audit_format  # Uses 'control' not 'check_id'
        assert "status" in audit_format
        assert "compliance_score" in audit_format
    
    def test_overall_score(self):
        """Test overall score calculation."""
        result = CheckResult(
            check_id="1.1",
            title="Test",
            status=CheckStatus.PASS,
            compliant_count=8,
            total_count=10,
            cis_severity=CISSeverity.HIGH  # Use cis_severity, not severity
        )
        
        score = result.overall_score
        assert isinstance(score, (int, float))
        assert 0 <= score <= 100


class TestBaseCheck:
    """Tests for BaseCheck abstract class."""
    
    def test_class_vars_exist(self):
        """Test required class variables exist."""
        assert hasattr(BaseCheck, 'CHECK_ID')
        assert hasattr(BaseCheck, 'TITLE')
        assert hasattr(BaseCheck, 'DESCRIPTION')
        assert hasattr(BaseCheck, 'CIS_CONTROL_ID')
    
    def test_cannot_instantiate_abstract(self, mock_graph_client):
        """Test that BaseCheck cannot be instantiated directly."""
        # BaseCheck should be abstract due to execute() method
        with pytest.raises(TypeError):
            BaseCheck(mock_graph_client)
    
    def test_concrete_check_inherits(self, mock_graph_client, sample_config):
        """Test that concrete checks inherit properly."""
        from avaguard_core.checks.check_1_1_mfa import Check_1_1_MFA
        
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        
        assert isinstance(check, BaseCheck)
        assert hasattr(check, 'execute')
        assert hasattr(check, 'create_result')
    
    def test_execute_with_timing(self, mock_graph_client, sample_config):
        """Test execute_with_timing method."""
        from avaguard_core.checks.check_1_1_mfa import Check_1_1_MFA
        
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        result = check.execute_with_timing()
        
        assert isinstance(result, CheckResult)
        # Uses duration_seconds, not execution_time_ms
        assert hasattr(result, 'duration_seconds')
        assert result.duration_seconds >= 0
    
    def test_validate_configuration(self, mock_graph_client, sample_config):
        """Test configuration validation."""
        from avaguard_core.checks.check_1_1_mfa import Check_1_1_MFA
        
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        errors = check.validate_configuration()
        
        assert isinstance(errors, list)
    
    def test_get_metadata(self):
        """Test get_metadata class method."""
        from avaguard_core.checks.check_1_1_mfa import Check_1_1_MFA
        
        metadata = Check_1_1_MFA.get_metadata()
        
        assert isinstance(metadata, dict)
        assert "check_id" in metadata
        assert "title" in metadata


class TestCreateResult:
    """Tests for the create_result factory method."""
    
    def test_create_pass_result(self, mock_graph_client, sample_config):
        """Test creating a passing result."""
        from avaguard_core.checks.check_1_1_mfa import Check_1_1_MFA
        
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        
        result = check.create_result(
            status=CheckStatus.PASS,
            details="All checks passed",
            compliant_count=10,
            total_count=10
        )
        
        assert result.status == CheckStatus.PASS
        assert result.check_id == "1.1"
        assert result.compliant_count == 10
    
    def test_create_fail_result_with_resources(self, mock_graph_client, sample_config):
        """Test creating a failing result with non-compliant resources."""
        from avaguard_core.checks.check_1_1_mfa import Check_1_1_MFA
        
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        
        non_compliant = [
            {"userPrincipalName": "user1@test.com"},
            {"userPrincipalName": "user2@test.com"}
        ]
        
        result = check.create_result(
            status=CheckStatus.FAIL,
            details="Some checks failed",
            non_compliant_resources=non_compliant,
            non_compliant_count=2,
            compliant_count=8,
            total_count=10
        )
        
        assert result.status == CheckStatus.FAIL
        assert result.non_compliant_count == 2
        assert len(result.non_compliant_resources) == 2
    
    def test_create_error_result(self, mock_graph_client, sample_config):
        """Test creating an error result."""
        from avaguard_core.checks.check_1_1_mfa import Check_1_1_MFA
        
        check = Check_1_1_MFA(mock_graph_client, sample_config)
        
        result = check.create_result(
            status=CheckStatus.ERROR,
            details="API connection failed",
            error_message="Connection timeout"
        )
        
        assert result.status == CheckStatus.ERROR
        assert result.error_message == "Connection timeout"
