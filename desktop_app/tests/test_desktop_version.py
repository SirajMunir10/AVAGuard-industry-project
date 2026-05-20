from unittest.mock import patch
import pytest
from desktop_app.utils.dependency_check import validate_core_dependency

def test_desktop_passes_valid_version():
    with patch.dict('sys.modules', {'avaguard_core': type('Mock', (object,), {'__version__': '0.1.0'})()}):
        result = validate_core_dependency()
    assert result == '0.1.0'

def test_desktop_fails_old_version():
    with patch.dict('sys.modules', {'avaguard_core': type('Mock', (object,), {'__version__': '0.0.1'})()}):
        with patch('PyQt6.QtWidgets.QMessageBox') as mock_box:
            with pytest.raises(SystemExit):
                validate_core_dependency()
    mock_box.critical.assert_called_once()

def test_desktop_missing_dependency():
    with patch.dict('sys.modules', {'avaguard_core': None}):
        with patch('PyQt6.QtWidgets.QMessageBox') as mock_box:
            with pytest.raises(SystemExit):
                validate_core_dependency()
    mock_box.critical.assert_called_once()
