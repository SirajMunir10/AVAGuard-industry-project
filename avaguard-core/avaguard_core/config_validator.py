import configparser
import re
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any
from pathlib import Path

class ValidationSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

@dataclass
class ValidationResult:
    field: str
    severity: ValidationSeverity
    message: str
    suggested_fix: str

@dataclass
class ConfigValidationReport:
    is_valid_for_live: bool = True
    is_valid_for_mock: bool = True
    results: List[ValidationResult] = field(default_factory=list)
    normalized_config: Dict[str, Any] = field(default_factory=dict)

    def has_errors(self) -> bool:
        return any(r.severity == ValidationSeverity.ERROR for r in self.results)

    def has_warnings(self) -> bool:
        return any(r.severity == ValidationSeverity.WARNING for r in self.results)

    def get_errors(self) -> List[ValidationResult]:
        return [r for r in self.results if r.severity == ValidationSeverity.ERROR]

    def get_warnings(self) -> List[ValidationResult]:
        return [r for r in self.results if r.severity == ValidationSeverity.WARNING]


class ConfigValidator:
    """Class-based pure logic validator for configuration."""
    
    GUID_PATTERN = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    
    def __init__(self):
        pass  # No state here to prevent accumulation across multiple validate() calls

    def validate(self, config_path_str: str) -> ConfigValidationReport:
        self.report = ConfigValidationReport()  # Fresh report every call
        self.config_parser = configparser.ConfigParser()
        
        config_path = Path(config_path_str)
        
        # Initialize normalized config defaults early
        self.report.normalized_config = {
            'tenant_id': '',
            'client_id': '',
            'client_secret': '',
            'mock_data_file': 'mock_data/enterprise_dataset.json',
            'portal_url': ''
        }

        # 1. Check existence
        if not config_path.exists():
            self.report.is_valid_for_live = False
            self.report.results.append(ValidationResult(
                field="config_file", severity=ValidationSeverity.ERROR,
                message="Configuration file not found.",
                suggested_fix="Create config.ini from config.example.ini"
            ))
            return self.report

        # 2. Try parsing
        try:
            self.config_parser.read(config_path)
        except configparser.Error as e:
            self.report.is_valid_for_live = False
            self.report.is_valid_for_mock = False
            self.report.results.append(ValidationResult(
                field="config_file", severity=ValidationSeverity.ERROR,
                message=f"Failed to parse INI config: {e}",
                suggested_fix="Ensure file is valid INI format."
            ))
            return self.report

        # 3. Field Validations
        self._validate_azure_credentials()
        self._validate_mock_file(config_path.parent)
        self._validate_portal_url()

        # Final structural validity
        if self.report.has_errors():
            self.report.is_valid_for_live = False

        return self.report

    def _validate_azure_credentials(self):
        tenant_id = self.config_parser.get('Azure', 'tenant_id', fallback='').strip()
        client_id = self.config_parser.get('Azure', 'client_id', fallback='').strip()
        secret = self.config_parser.get('Azure', 'client_secret', fallback='').strip()

        self.report.normalized_config['tenant_id'] = tenant_id
        self.report.normalized_config['client_id'] = client_id
        self.report.normalized_config['client_secret'] = secret

        placeholder_vals = ("none", "your_tenant_id", "your_client_id", "your_client_secret", "")

        if not tenant_id or tenant_id.lower() in placeholder_vals or not self.GUID_PATTERN.match(tenant_id):
            self.report.results.append(ValidationResult(
                field="tenant_id", severity=ValidationSeverity.ERROR,
                message="Invalid or missing tenant_id format.",
                suggested_fix="Provide a valid Azure Active Directory GUID."
            ))

        if not client_id or client_id.lower() in placeholder_vals or not self.GUID_PATTERN.match(client_id):
            self.report.results.append(ValidationResult(
                field="client_id", severity=ValidationSeverity.ERROR,
                message="Invalid or missing client_id format.",
                suggested_fix="Provide a valid Azure Application Registration GUID."
            ))

        if not secret or secret.lower() in placeholder_vals or len(secret) < 20 or " " in secret:
            self.report.results.append(ValidationResult(
                field="client_secret", severity=ValidationSeverity.ERROR,
                message="client_secret is missing, too short, or contains spaces.",
                suggested_fix="Provide a valid Azure App Client Secret (>=20 chars, no spaces)."
            ))

    def _validate_mock_file(self, base_path: Path):
        mock_file = self.config_parser.get('General', 'mock_data_file', fallback='').strip()
        
        if mock_file:
            self.report.normalized_config['mock_data_file'] = mock_file
            mock_path = Path(mock_file)
            if not mock_path.is_absolute():
                mock_path = base_path / mock_path

            if not mock_path.exists():
                self.report.results.append(ValidationResult(
                    field="mock_data_file", severity=ValidationSeverity.WARNING,
                    message=f"Mock data path not found at {mock_file}. Falling back to default dataset.",
                    suggested_fix="Verify the path in config.ini or leave blank to use defaults."
                ))
                self.report.normalized_config['mock_data_file'] = 'mock_data/enterprise_dataset.json'

    def _validate_portal_url(self):
        url = self.config_parser.get('portal', 'url', fallback='').strip()
        
        if not url:
            self.report.results.append(ValidationResult(
                field="portal_url", severity=ValidationSeverity.INFO,
                message="Portal URL is empty. Portal sync disabled.",
                suggested_fix="Add URL if you wish to sync results."
            ))
            return

        self.report.normalized_config['portal_url'] = url
        if not url.startswith(('http://', 'https://')):
            self.report.results.append(ValidationResult(
                field="portal_url", severity=ValidationSeverity.WARNING,
                message=f"Invalid Portal URL format: {url}",
                suggested_fix="URL must begin with http:// or https://"
            ))

def validate_config(config_path: str) -> ConfigValidationReport:
    """Convenience wrapper."""
    validator = ConfigValidator()
    return validator.validate(config_path)
