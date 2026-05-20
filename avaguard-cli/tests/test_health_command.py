import pytest
import json
import configparser
from pathlib import Path
import requests
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from avaguard.cli import cli
from avaguard.health import HealthChecker, HealthStatus, HealthReport


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def valid_config(tmp_path):
    """A config.ini with valid Azure credentials and existing mock file."""
    mock_file = tmp_path / "mock_data.json"
    mock_file.write_text('{"users": []}')

    config = configparser.ConfigParser()
    config['Azure'] = {
        'tenant_id': '12345678-1234-1234-1234-1234567890ab',
        'client_id': '12345678-1234-1234-1234-1234567890ab',
        'client_secret': 'aabbccddeeffgghhiijjkkllmmnnoopp',
    }
    config['General'] = {'mock_data_file': str(mock_file)}
    config['portal'] = {'url': 'http://localhost:8000'}

    config_file = tmp_path / "config.ini"
    with open(config_file, 'w') as f:
        config.write(f)
    return str(config_file)


@pytest.fixture
def minimal_config(tmp_path):
    """A config.ini with no Azure credentials."""
    config = configparser.ConfigParser()
    config['Azure'] = {'tenant_id': '', 'client_id': '', 'client_secret': ''}
    config['portal'] = {'url': 'http://localhost:8000'}
    config_file = tmp_path / "config.ini"
    with open(config_file, 'w') as f:
        config.write(f)
    return str(config_file)


# ── Unit Tests for HealthChecker ──────────────────────────────────────────────

def test_health_command_registered():
    """avaguard health command is registered in CLI."""
    runner = CliRunner()
    result = runner.invoke(cli, ['health', '--help'])
    assert result.exit_code == 0
    assert 'health' in result.output.lower()


def test_health_all_checks_run(valid_config):
    """HealthChecker.run_all() returns exactly 10 check results."""
    with patch('requests.get', side_effect=requests.exceptions.ConnectionError):
        checker = HealthChecker(valid_config)
        report = checker.run_all()
    assert report.total == 10


def test_health_passes_with_valid_config(valid_config):
    """All non-portal checks pass with a valid config."""
    with patch('requests.get', side_effect=requests.exceptions.ConnectionError):
        checker = HealthChecker(valid_config)
        report = checker.run_all()
    non_portal = [c for c in report.checks if c.name != 'portal_reachable']
    failed = [c for c in non_portal if c.status == HealthStatus.FAIL]
    assert failed == [], f"Unexpected failures: {[c.name for c in failed]}"


def test_health_fails_with_missing_config(tmp_path):
    """FAIL reported when config.ini does not exist."""
    checker = HealthChecker(str(tmp_path / "nonexistent.ini"))
    report = checker.run_all()
    config_check = next(c for c in report.checks if c.name == 'config_file_exists')
    assert config_check.status == HealthStatus.FAIL


def test_health_warns_invalid_credentials(minimal_config):
    """WARN reported for missing Azure credentials."""
    with patch('requests.get', side_effect=requests.exceptions.ConnectionError):
        checker = HealthChecker(minimal_config)
        report = checker.run_all()
    cred_check = next(c for c in report.checks if c.name == 'azure_credentials')
    assert cred_check.status == HealthStatus.WARN


def test_health_warns_portal_unreachable(minimal_config):
    """WARN reported when portal URL is not reachable."""
    with patch('requests.get', side_effect=requests.exceptions.ConnectionError):
        checker = HealthChecker(minimal_config)
        report = checker.run_all()
    portal_check = next(c for c in report.checks if c.name == 'portal_reachable')
    assert portal_check.status == HealthStatus.WARN


def test_health_exit_code_0_warnings_only(minimal_config):
    """Exit code is 0 when only warnings are present (no failures)."""
    with patch('requests.get', side_effect=requests.exceptions.ConnectionError):
        checker = HealthChecker(minimal_config)
        report = checker.run_all()
    assert report.failed == 0
    assert report.exit_code == 0


def test_health_exit_code_1_on_failure(tmp_path):
    """Exit code is 1 when FAIL checks are present."""
    checker = HealthChecker(str(tmp_path / "does_not_exist.ini"))
    report = checker.run_all()
    assert report.failed > 0
    assert report.exit_code == 1


def test_health_json_output_valid(minimal_config):
    """--json flag produces valid JSON output."""
    runner = CliRunner()
    with patch('requests.get', side_effect=requests.exceptions.ConnectionError):
        result = runner.invoke(cli, ['health', '--config-file', minimal_config, '--json'])
    try:
        data = json.loads(result.output)
    except json.JSONDecodeError:
        pytest.fail(f"Output is not valid JSON: {result.output}")
    assert 'checks' in data
    assert 'total' in data
    assert 'passed' in data
    assert 'failed' in data
    assert 'warnings' in data
    assert 'exit_code' in data


def test_health_json_contains_all_10_checks(minimal_config):
    """JSON output contains exactly 10 health check results."""
    runner = CliRunner()
    with patch('requests.get', side_effect=requests.exceptions.ConnectionError):
        result = runner.invoke(cli, ['health', '--config-file', minimal_config, '--json'])
    data = json.loads(result.output)
    assert data['total'] == 10
    assert len(data['checks']) == 10
