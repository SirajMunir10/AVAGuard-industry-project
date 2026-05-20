import os
import sys
import json
import requests
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from datetime import datetime


class HealthStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


@dataclass
class HealthCheckResult:
    name: str
    status: HealthStatus
    message: str
    detail: Optional[str] = None


@dataclass
class HealthReport:
    checks: List[HealthCheckResult] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == HealthStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == HealthStatus.FAIL)

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.status == HealthStatus.WARN)

    @property
    def exit_code(self) -> int:
        """Returns 1 if any FAIL checks exist, 0 otherwise."""
        return 1 if self.failed > 0 else 0

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "exit_code": self.exit_code,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "message": c.message,
                    "detail": c.detail,
                }
                for c in self.checks
            ],
        }


class HealthChecker:
    """
    Runs a series of local health checks on the AVAGuard installation.
    No Azure API calls are made. All checks are local or lightweight HTTP.
    """

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self._config = None  # Loaded lazily after config file check

    def run_all(self) -> HealthReport:
        """Run all health checks and return a HealthReport."""
        report = HealthReport()

        # Run in this exact order
        report.checks.append(self._check_config_exists())
        report.checks.append(self._check_config_parseable())
        report.checks.append(self._check_azure_credentials())
        report.checks.append(self._check_mock_data_file())
        report.checks.append(self._check_mock_data_size())
        report.checks.append(self._check_core_version())
        report.checks.append(self._check_core_importable())
        report.checks.append(self._check_portal_reachable())
        report.checks.append(self._check_output_dir_writable())
        report.checks.append(self._check_log_dir_writable())

        return report

    # ------------------------------------------------------------------ #
    # Individual checks                                                    #
    # ------------------------------------------------------------------ #

    def _check_config_exists(self) -> HealthCheckResult:
        if self.config_path.exists():
            return HealthCheckResult(
                name="config_file_exists",
                status=HealthStatus.PASS,
                message=f"Found at {self.config_path.resolve()}",
            )
        return HealthCheckResult(
            name="config_file_exists",
            status=HealthStatus.FAIL,
            message=f"Not found at {self.config_path.resolve()}",
            detail="Create config.ini from config.example.ini",
        )

    def _check_config_parseable(self) -> HealthCheckResult:
        if not self.config_path.exists():
            return HealthCheckResult(
                name="config_parseable",
                status=HealthStatus.FAIL,
                message="Skipped — config file missing",
            )
        import configparser
        parser = configparser.ConfigParser()
        try:
            parser.read(self.config_path)
            self._config = parser
            return HealthCheckResult(
                name="config_parseable",
                status=HealthStatus.PASS,
                message="Valid INI format",
            )
        except configparser.Error as e:
            return HealthCheckResult(
                name="config_parseable",
                status=HealthStatus.FAIL,
                message="Failed to parse config.ini",
                detail=str(e),
            )

    def _check_azure_credentials(self) -> HealthCheckResult:
        from avaguard_core.config_validator import validate_config
        report = validate_config(str(self.config_path))
        errors = [e for e in report.get_errors()
                  if e.field in ('tenant_id', 'client_id', 'client_secret')]
        if not errors:
            return HealthCheckResult(
                name="azure_credentials",
                status=HealthStatus.PASS,
                message="Azure credentials appear valid",
            )
        field_names = ", ".join(e.field for e in errors)
        return HealthCheckResult(
            name="azure_credentials",
            status=HealthStatus.WARN,
            message=f"Invalid or missing: {field_names}",
            detail="Live scans will not work. Use --mock for testing.",
        )

    def _check_mock_data_file(self) -> HealthCheckResult:
        if self._config is None:
            return HealthCheckResult(
                name="mock_data_file",
                status=HealthStatus.WARN,
                message="Skipped — config not loaded",
            )
        mock_path_str = self._config.get(
            'General', 'mock_data_file',
            fallback='mock_data/enterprise_dataset.json'
        ).strip()
        mock_path = Path(mock_path_str)
        if not mock_path.is_absolute():
            mock_path = self.config_path.parent / mock_path

        if mock_path.exists():
            return HealthCheckResult(
                name="mock_data_file",
                status=HealthStatus.PASS,
                message=f"Found at {mock_path.resolve()}",
            )
        return HealthCheckResult(
            name="mock_data_file",
            status=HealthStatus.WARN,
            message=f"Not found at {mock_path.resolve()}",
            detail="Mock scans will fall back to default dataset",
        )

    def _check_mock_data_size(self) -> HealthCheckResult:
        if self._config is None:
            return HealthCheckResult(
                name="mock_data_size",
                status=HealthStatus.WARN,
                message="Skipped — config not loaded",
            )
        mock_path_str = self._config.get(
            'General', 'mock_data_file',
            fallback='mock_data/enterprise_dataset.json'
        ).strip()
        mock_path = Path(mock_path_str)
        if not mock_path.is_absolute():
            mock_path = self.config_path.parent / mock_path

        if not mock_path.exists():
            return HealthCheckResult(
                name="mock_data_size",
                status=HealthStatus.WARN,
                message="Skipped — mock file not found",
            )
        size_bytes = mock_path.stat().st_size
        size_kb = size_bytes / 1024
        if size_bytes > 0:
            return HealthCheckResult(
                name="mock_data_size",
                status=HealthStatus.PASS,
                message=f"File size: {size_kb:.1f} KB",
            )
        return HealthCheckResult(
            name="mock_data_size",
            status=HealthStatus.WARN,
            message="Mock data file is empty (0 bytes)",
            detail="Regenerate using: python Mockdata.py",
        )

    def _check_core_version(self) -> HealthCheckResult:
        try:
            import avaguard_core
            version = avaguard_core.__version__
            return HealthCheckResult(
                name="core_version",
                status=HealthStatus.PASS,
                message=f"avaguard-core version: {version}",
            )
        except Exception as e:
            return HealthCheckResult(
                name="core_version",
                status=HealthStatus.FAIL,
                message="Could not read avaguard-core version",
                detail=str(e),
            )

    def _check_core_importable(self) -> HealthCheckResult:
        try:
            import avaguard_core
            from avaguard_core.checks import AVAILABLE_CHECKS
            check_count = len(AVAILABLE_CHECKS)
            return HealthCheckResult(
                name="core_importable",
                status=HealthStatus.PASS,
                message=f"avaguard-core imports OK ({check_count} checks registered)",
            )
        except ImportError as e:
            return HealthCheckResult(
                name="core_importable",
                status=HealthStatus.FAIL,
                message="avaguard-core import failed",
                detail=f"{e}\nFix: pip install -e ./avaguard-core",
            )

    def _check_portal_reachable(self) -> HealthCheckResult:
        portal_url = 'http://localhost:8000'
        if self._config is not None:
            portal_url = self._config.get(
                'portal', 'url', fallback='http://localhost:8000'
            ).strip() or 'http://localhost:8000'

        health_url = portal_url.rstrip('/') + '/api/health/'
        try:
            response = requests.get(health_url, timeout=5)
            if response.status_code == 200:
                return HealthCheckResult(
                    name="portal_reachable",
                    status=HealthStatus.PASS,
                    message=f"Portal responding at {portal_url}",
                )
            return HealthCheckResult(
                name="portal_reachable",
                status=HealthStatus.WARN,
                message=f"Portal returned HTTP {response.status_code}",
                detail=f"URL: {health_url}",
            )
        except requests.exceptions.ConnectionError:
            return HealthCheckResult(
                name="portal_reachable",
                status=HealthStatus.WARN,
                message=f"Portal unreachable at {portal_url}",
                detail="Start portal with: python web_portal/manage.py runserver",
            )
        except requests.exceptions.Timeout:
            return HealthCheckResult(
                name="portal_reachable",
                status=HealthStatus.WARN,
                message=f"Portal timed out after 5 seconds",
                detail=f"URL: {health_url}",
            )

    def _check_output_dir_writable(self) -> HealthCheckResult:
        return self._check_dir_writable(
            "output_dir_writable",
            self.config_path.parent / "output" / "reports",
        )

    def _check_log_dir_writable(self) -> HealthCheckResult:
        return self._check_dir_writable(
            "log_dir_writable",
            self.config_path.parent / "output" / "logs",
        )

    def _check_dir_writable(self, name: str, path: Path) -> HealthCheckResult:
        try:
            path.mkdir(parents=True, exist_ok=True)
            test_file = path / ".avaguard_write_test"
            test_file.write_text("test")
            test_file.unlink()
            return HealthCheckResult(
                name=name,
                status=HealthStatus.PASS,
                message=f"{path} is writable",
            )
        except (OSError, PermissionError) as e:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.FAIL,
                message=f"{path} is not writable",
                detail=str(e),
            )
