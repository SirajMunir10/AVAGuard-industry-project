from avaguard.cli import _check_core_version, MIN_CORE_VERSION
import pytest

def test_cli_version_check_passes_current():
    _check_core_version(_override="0.1.0")

def test_cli_version_check_passes_future():
    _check_core_version(_override="9.9.9")

def test_cli_version_check_fails_old():
    with pytest.raises(SystemExit) as exc:
        _check_core_version(_override="0.0.1")
    assert exc.value.code == 1

def test_min_version_valid():
    from packaging.version import Version
    Version(MIN_CORE_VERSION)
