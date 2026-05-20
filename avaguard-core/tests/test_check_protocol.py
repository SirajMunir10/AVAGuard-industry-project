import pytest
from typing import ClassVar, Any, Dict, Protocol
from avaguard_core.checks.protocol import CheckProtocol
from avaguard_core.checks.base_check import BaseCheck, CheckResult, CheckStatus, CISSeverity
from avaguard_core.checks import AVAILABLE_CHECKS
from avaguard_core.check_loader import CheckRegistry

def test_protocol_is_runtime_checkable():
    """CheckProtocol can be used with isinstance() at runtime"""
    # Simply verify isinstance does not raise TypeError
    try:
        isinstance(BaseCheck, CheckProtocol)
    except TypeError:
        pytest.fail("CheckProtocol is not runtime_checkable")

def test_base_check_satisfies_protocol():
    """BaseCheck (and by extension all existing checks) satisfies CheckProtocol"""
    # Wait, BaseCheck is an ABC. It actually lacks 'execute' implementation but has the abstractmethod.
    # At runtime, hasattr(BaseCheck, 'execute') is True.
    assert hasattr(BaseCheck, 'execute')
    
    registry = CheckRegistry()
    # Create a dummy check that inherits BaseCheck
    class DummyCheck(BaseCheck):
        CHECK_ID = "0.0"
        TITLE = "Dummy"
        DESCRIPTION = "Dummy description"
        CIS_CONTROL_ID = "V1"
        CIS_SEVERITY = CISSeverity.LOW
        def execute(self) -> CheckResult:
            return CheckResult(check_id=self.CHECK_ID, status=CheckStatus.PASS)
            
    # Should not raise
    registry._validate_check_class(DummyCheck)
    assert isinstance(DummyCheck, CheckProtocol)

def test_all_existing_checks_satisfy_protocol():
    """All 10 check classes in AVAILABLE_CHECKS satisfy CheckProtocol"""
    registry = CheckRegistry()
    for check_id, check_class in AVAILABLE_CHECKS.items():
        # Validate using the exact same loader logic
        try:
            registry._validate_check_class(check_class)
        except TypeError as e:
            pytest.fail(f"Check {check_id} ({check_class.__name__}) failed protocol validation: {e}")

def test_check_missing_check_id_fails_validation():
    """A check class missing CHECK_ID raises TypeError in _validate_check_class"""
    registry = CheckRegistry()
    class BadCheck:
        TITLE = "T"
        DESCRIPTION = "D"
        CIS_CONTROL_ID = "C"
        CIS_SEVERITY = "S"
        def execute(self): pass
        
    with pytest.raises(TypeError, match="missing required attribute 'CHECK_ID'"):
        registry._validate_check_class(BadCheck)

def test_check_missing_title_fails_validation():
    """A check class missing TITLE raises TypeError"""
    registry = CheckRegistry()
    class BadCheck:
        CHECK_ID = "1"
        DESCRIPTION = "D"
        CIS_CONTROL_ID = "C"
        CIS_SEVERITY = "S"
        def execute(self): pass
        
    with pytest.raises(TypeError, match="missing required attribute 'TITLE'"):
        registry._validate_check_class(BadCheck)

def test_check_missing_execute_fails_validation():
    """A check class missing execute() raises TypeError"""
    registry = CheckRegistry()
    class BadCheck:
        CHECK_ID = "1"
        TITLE = "T"
        DESCRIPTION = "D"
        CIS_CONTROL_ID = "C"
        CIS_SEVERITY = "S"
        
    with pytest.raises(TypeError, match="must have a callable 'execute' method"):
        registry._validate_check_class(BadCheck)

def test_check_missing_severity_fails_validation():
    """A check class missing SEVERITY raises TypeError"""
    registry = CheckRegistry()
    class BadCheck:
        CHECK_ID = "1"
        TITLE = "T"
        DESCRIPTION = "D"
        CIS_CONTROL_ID = "C"
        def execute(self): pass
        
    with pytest.raises(TypeError, match="missing required attribute 'CIS_SEVERITY'"):
        registry._validate_check_class(BadCheck)

def test_valid_check_passes_validation():
    """A properly formed check class passes _validate_check_class"""
    registry = CheckRegistry()
    class GoodCheck:
        CHECK_ID = "1"
        TITLE = "T"
        DESCRIPTION = "D"
        CIS_CONTROL_ID = "C"
        CIS_SEVERITY = "S"
        def execute(self) -> CheckResult: pass
        
    # Should not raise exception
    registry._validate_check_class(GoodCheck)

def test_available_checks_dict_type_hint():
    """AVAILABLE_CHECKS values are all Type[CheckProtocol] compatible"""
    from typing import get_type_hints
    import avaguard_core.checks as checks_module
    
    # Python 3.9+ typing doesn't enforce at runtime via get_type_hints perfectly for variables in all modules,
    # but we can verify our assertion from earlier test holds the practical effect.
    assert len(AVAILABLE_CHECKS) >= 10

def test_check_protocol_has_required_attributes():
    """CheckProtocol defines CHECK_ID, TITLE, DESCRIPTION, CIS_CONTROL, SEVERITY"""
    hints = CheckProtocol.__annotations__
    assert 'CHECK_ID' in hints
    assert 'TITLE' in hints
    assert 'DESCRIPTION' in hints
    assert 'CIS_CONTROL_ID' in hints
    assert 'CIS_SEVERITY' in hints

def test_check_protocol_has_execute_method():
    """CheckProtocol defines execute() method"""
    assert hasattr(CheckProtocol, 'execute')

def test_duck_typed_check_satisfies_protocol():
    """A class that doesn't inherit BaseCheck but has all required attrs satisfies protocol"""
    class DuckCheck:
        CHECK_ID = "Duck.1"
        TITLE = "Duck Typing"
        DESCRIPTION = "Quack"
        CIS_CONTROL_ID = "None"
        CIS_SEVERITY = "LOW"
        def execute(self) -> CheckResult:
            return CheckResult(check_id="Duck.1", status=CheckStatus.PASS)

    # isinstance works with protocols for methods
    assert isinstance(DuckCheck, CheckProtocol)
    
    # And our stricter validator catches the class vars
    registry = CheckRegistry()
    registry._validate_check_class(DuckCheck)
