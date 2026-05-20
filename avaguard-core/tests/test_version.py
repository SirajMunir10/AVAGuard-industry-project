import os
import re
import pytest
import avaguard_core

def test_version_exists():
    """Ensure version is defined and non-empty"""
    assert avaguard_core.__version__ is not None
    assert isinstance(avaguard_core.__version__, str)
    assert len(avaguard_core.__version__) > 0

def test_version_format():
    """Ensure version follows semantic versioning X.Y.Z"""
    pattern = r'^\d+\.\d+\.\d+$'
    assert re.match(pattern, avaguard_core.__version__), \
        f"Version '{avaguard_core.__version__}' does not follow X.Y.Z format"

def test_version_file_matches():
    """Ensure VERSION file matches __version__"""
    current = os.path.dirname(os.path.abspath(avaguard_core.__file__))

    for _ in range(4):  # Walk up max 4 levels
        version_path = os.path.join(current, 'VERSION')
        if os.path.exists(version_path):
            with open(version_path, 'r') as f:
                file_version = f.read().strip()
            assert file_version != ""
            assert avaguard_core.__version__ == file_version
            return
        current = os.path.dirname(current)

    pytest.fail("VERSION file not found within 4 parent directories")
