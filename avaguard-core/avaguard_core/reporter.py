"""
AVAGuard Core - Enhanced Reporting Module (SRS-Compliant)
Generates enterprise-grade compliance reports in HTML, JSON, PDF, Excel formats.
"""

import json
import csv
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, ClassVar, Union
from dataclasses import dataclass, field
from enum import Enum

from avaguard_core.checks.base_check import CheckResult, CheckStatus, CISSeverity
from avaguard_core.risk_scorer import RiskScorer

logger = logging.getLogger(__name__)

class ReportFormat(str, Enum):
    """Supported report formats."""
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    EXCEL = "excel"

class ReportTier(str, Enum):
    """Report tier classification matching SRS."""
    BASIC = "basic"
    ENTERPRISE = "enterprise"
    PREMIUM = "premium"

@dataclass
class ReportMetadata:
    """Comprehensive metadata for SRS-compliant reports."""
    # Core metadata matching new code
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    initiated_by: str = "system"
    target_tenant: Optional[str] = None
    environment: str = "production"
    scope: str = "Azure CIS Benchmark"
    tier: ReportTier = ReportTier.ENTERPRISE
    
    # Optional advanced fields for backward compatibility
    overall_score: float = 0.0
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    error_checks: int = 0
    generated_by: str = "AVAGuard Compliance Engine"
    version: str = "2.2.0"
    compliance_standard: str = "CIS Microsoft Azure Foundations Benchmark"
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    cis_controls_checked: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'scan_id': self.scan_id,
            'timestamp': self.timestamp.isoformat(),
            'initiated_by': self.initiated_by,
            'target_tenant': self.target_tenant,
            'environment': self.environment,
            'scope': self.scope,
            'tier': self.tier.value,
            'overall_score': self.overall_score,
            'total_checks': self.total_checks,
            'passed_checks': self.passed_checks,
            'failed_checks': self.failed_checks,
            'error_checks': self.error_checks,
            'generated_by': self.generated_by,
            'version': self.version,
            'compliance_standard': self.compliance_standard,
            'audit_id': self.audit_id,
            'cis_controls_checked': self.cis_controls_checked
        }

class EnhancedReporter:  # <--- RENAMED to match main.py
    """SRS-compliant enhanced reporter with multi-format support."""
    
    # Theme configurations matching SRS tiers
    THEMES: ClassVar[Dict[ReportTier, Dict[str, str]]] = {
        ReportTier.BASIC: {
            "primary": "#0f172a", "accent": "#3b82f6",
            "success": "#10b981", "warning": "#f59e0b", "danger": "#ef4444",
            "bg": "#f8fafc", "card_bg": "#ffffff", "text": "#1e293b"
        },
        ReportTier.ENTERPRISE: {
            "primary": "#1e40af", "accent": "#8b5cf6",
            "success": "#059669", "warning": "#d97706", "danger": "#dc2626",
            "bg": "#f1f5f9", "card_bg": "#ffffff", "text": "#0f172a"
        },
        ReportTier.PREMIUM: {
            "primary": "#7c3aed", "accent": "#ec4899",
            "success": "#10b981", "warning": "#f59e0b", "danger": "#ef4444",
            "bg": "#fafaf9", "card_bg": "#ffffff", "text": "#1c1917"
        }
    }
    

    

    
    def __init__(self, output_dir: str = "reports", metadata: Optional[ReportMetadata] = None):
        """Initialize reporter with output directory and metadata."""
        self.output_dir = output_dir
        self.metadata = metadata or ReportMetadata()
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Set theme based on tier
        self.theme = self.THEMES.get(self.metadata.tier, self.THEMES[ReportTier.ENTERPRISE])
        
        # Note: CSS theme colors are now handled directly in the Jinja2 template
        # via the 'theme' object.
        
        logger.info(f"EnhancedReporter initialized: output_dir={self.output_dir}, tier={self.metadata.tier.value}")

    def generate_reports(self, results: List[CheckResult], 
                        formats: Optional[List[ReportFormat]] = None) -> List[str]:
        """
        Generate comprehensive reports in specified formats.
        
        Args:
            results: List of CheckResult objects
            formats: List of report formats to generate
            
        Returns:
            List of filepaths to generated reports
        """
        if formats is None:
            formats = [ReportFormat.HTML, ReportFormat.CSV]
            
        if not results:
            logger.warning("No results provided for report generation")
            return []
        
        # Update metadata with results
        self._update_metadata_from_results(results)
        
        timestamp = self.metadata.timestamp.strftime("%Y%m%d_%H%M%S")
        scan_id = self.metadata.scan_id
        generated_files = []
        
        try:
            # Generate requested formats
            for fmt in formats:
                filepath = self._generate_single_format(fmt, results, timestamp, scan_id)
                if filepath:
                    generated_files.append(filepath)
            
            logger.info(f"Generated {len(generated_files)} report(s) successfully")
            self._log_report_metrics(generated_files)
            
            return generated_files
            
        except Exception as e:
            logger.error(f"Error generating reports: {str(e)}", exc_info=True)
            raise
    
    def _generate_single_format(self, fmt: ReportFormat, results: List[CheckResult],
                               timestamp: str, scan_id: str) -> Optional[str]:
        """Generate a single format report."""
        try:
            if fmt == ReportFormat.HTML:
                return self._write_html(results, timestamp, scan_id)
            elif fmt == ReportFormat.JSON:
                return self._write_json(results, timestamp, scan_id)
            elif fmt == ReportFormat.CSV:
                return self._write_csv(results, timestamp, scan_id)
            elif fmt == ReportFormat.PDF:
                return self._write_pdf(results, timestamp, scan_id)
            elif fmt == ReportFormat.EXCEL:
                logger.warning("Excel generation not yet implemented")
                return None
        except Exception as e:
            logger.error(f"Failed to generate {fmt.value} report: {e}")
            return None
            
    def _write_pdf(self, results: List[CheckResult], timestamp: str, scan_id: str) -> Optional[str]:
        """Generate PDF structural framework report."""
        try:
            from avaguard_core.pdf_renderer import PDFRenderer
            filename = f"avaguard_scan_{timestamp}.pdf"
            filepath = os.path.join(self.output_dir, filename)
            return PDFRenderer.generate_pdf(results, filepath, scan_id, timestamp)
        except ImportError as e:
            logger.error(f"Cannot generate PDF. Ensure reportlab is installed: {e}")
            return None
    

    def _write_html(self, results: List[CheckResult], timestamp: str, scan_id: str) -> str:
        """Generate interactive HTML report via Jinja2."""
        try:
            from jinja2 import Environment, PackageLoader, select_autoescape
        except ImportError:
            logger.error("Jinja2 is required for HTML reports. Run: pip install jinja2")
            return ""

        filename = f"avaguard_scan_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)

        passed = sum(1 for r in results if str(getattr(r.status, 'value', r.status)) == "PASS")
        failed = sum(1 for r in results if str(getattr(r.status, 'value', r.status)) == "FAIL")
        warning = sum(1 for r in results if str(getattr(r.status, 'value', r.status)) == "WARNING")

        score = RiskScorer.calculate_score(results)
        score_color = self._get_score_color(score)

        env = Environment(
            loader=PackageLoader("avaguard_core", "templates"),
            autoescape=select_autoescape(["html", "xml"])
        )
        env.globals['getattr'] = getattr

        template = env.get_template("report_base.html.j2")
        html_content = template.render(
            metadata=self.metadata,
            theme=self.theme,
            results=results,
            score=score,
            score_color=score_color,
            passed=passed,
            failed=failed,
            warning=warning
        )

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return filepath

    def _write_json(self, results: List[CheckResult], timestamp: str, scan_id: str) -> str:
        """Generate machine-readable JSON report."""
        filename = f"avaguard_scan_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        report_data = {
            'metadata': self.metadata.to_dict(),
            'summary': self._calculate_summary(results),
            'checks': [self._result_to_dict(r) for r in results],
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"JSON report generated: {filepath}")
        return filepath
    
    def _write_csv(self, results: List[CheckResult], timestamp: str, scan_id: str) -> str:
        """Generate CSV report for quick analysis."""
        filename = f"avaguard_scan_{timestamp}.csv"
        filepath = os.path.join(self.output_dir, filename)
        
        fieldnames = [
            'check_id', 'cis_control_id', 'title', 'status', 
            'section', 'severity', 'priority',
            'compliant_count', 'non_compliant_count', 'total_count',
            'compliance_percentage', 'duration_seconds', 'api_calls_count',
            'requires_premium', 'error_message', 'remediation'
        ]
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                try:
                    # Safely extract values
                    status_val = result.status.value if hasattr(result.status, 'value') else str(result.status)
                    severity_val = getattr(result, 'cis_severity', CISSeverity.MEDIUM)
                    if hasattr(severity_val, 'value'):
                        severity_val = severity_val.value
                    
                    writer.writerow({
                        'check_id': result.check_id,
                        'cis_control_id': getattr(result, 'cis_control_id', result.check_id),
                        'title': result.title[:200],
                        'status': status_val,
                        'section': self._extract_cis_section(result.check_id),
                        'severity': str(severity_val),
                        'priority': getattr(result, 'priority', 'Medium'),
                        'compliant_count': result.compliant_count,
                        'non_compliant_count': result.non_compliant_count,
                        'total_count': result.total_count,
                        'compliance_percentage': round(result.compliance_percentage, 2),
                        'duration_seconds': round(getattr(result, 'duration_seconds', 0.0), 3),
                        'api_calls_count': getattr(result, 'api_calls_count', 0),
                        'requires_premium': getattr(result, 'requires_premium', False),
                        'error_message': getattr(result, 'error_message', '')[:100] if getattr(result, 'error_message', None) else '',
                        'remediation': getattr(result, 'remediation', '')[:500]
                    })
                except Exception as e:
                    logger.warning(f"Error writing CSV row for check {result.check_id}: {e}")
                    continue
        
        logger.info(f"CSV report generated: {filepath}")
        return filepath
    
    def _update_metadata_from_results(self, results: List[CheckResult]):
        """Update metadata based on scan results."""
        self.metadata.total_checks = len(results)
        self.metadata.passed_checks = sum(1 for r in results if str(getattr(r.status, 'value', r.status)) == "PASS")
        self.metadata.failed_checks = sum(1 for r in results if str(getattr(r.status, 'value', r.status)) == "FAIL")
        self.metadata.error_checks = sum(1 for r in results if str(getattr(r.status, 'value', r.status)) == "ERROR")
        
        if self.metadata.total_checks > 0:
            self.metadata.overall_score = RiskScorer.calculate_score(results)
        
        # Extract CIS controls checked
        self.metadata.cis_controls_checked = [
            getattr(r, 'cis_control_id', r.check_id)
            for r in results
            if hasattr(r, 'cis_control_id') or 'CIS' in r.check_id
        ]
    
    def _calculate_summary(self, results: List[CheckResult]) -> Dict[str, Any]:
        """Calculate comprehensive summary statistics."""
        total = len(results)
        passed = sum(1 for r in results if str(getattr(r.status, 'value', r.status)) == "PASS")
        failed = sum(1 for r in results if str(getattr(r.status, 'value', r.status)) == "FAIL")
        warning = sum(1 for r in results if str(getattr(r.status, 'value', r.status)) == "WARNING")
        error = sum(1 for r in results if str(getattr(r.status, 'value', r.status)) == "ERROR")
        
        # Resource-level statistics
        total_resources = sum(getattr(r, 'total_count', 0) for r in results)
        compliant_resources = sum(getattr(r, 'compliant_count', 0) for r in results)
        non_compliant_resources = total_resources - compliant_resources
        
        overall_score = RiskScorer.calculate_score(results)
        compliance_rate = round((compliant_resources / total_resources * 100), 1) if total_resources > 0 else 0.0
        
        return {
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'warning': warning,
            'errors': error,
            'overall_score': overall_score,
            'total_resources': total_resources,
            'compliant_resources': compliant_resources,
            'non_compliant_resources': non_compliant_resources,
            'compliance_rate': compliance_rate,
        }
    
    def _result_to_dict(self, result: CheckResult) -> Dict[str, Any]:
        """Convert CheckResult to dictionary."""
        try:
            return result.to_dict()
        except AttributeError:
            # Fallback for older CheckResult objects
            return {
                'check_id': result.check_id,
                'title': result.title,
                'status': result.status.value if hasattr(result.status, 'value') else str(result.status),
                'details': result.details,
                'compliant_count': result.compliant_count,
                'non_compliant_count': result.non_compliant_count,
                'total_count': result.total_count,
                'compliance_percentage': round(result.compliance_percentage, 2),
                'non_compliant_resources': result.non_compliant_resources,
                'compliant_resources': result.compliant_resources,
                'remediation': getattr(result, 'remediation', ''),
                'error_message': getattr(result, 'error_message', None),
                'requires_premium': getattr(result, 'requires_premium', False)
            }
    
    def _extract_cis_section(self, check_id: str) -> str:
        """Extract CIS section from check ID."""
        try:
            clean_id = str(check_id)
            if '.' in clean_id:
                return clean_id.split('.')[0]
            elif '_' in clean_id:
                import re
                numbers = re.findall(r'\d+', clean_id)
                return numbers[0] if numbers else ""
        except Exception:
            pass
        return ""
    def _get_score_color(self, score: float) -> str:
        """Get color based on compliance score."""
        if score >= 80:
            return self.theme['success']
        elif score >= 60:
            return self.theme['warning']
        else:
            return self.theme['danger']
    
    def _log_report_metrics(self, generated_files: List[str]):
        """Log report generation metrics."""
        total_size = 0
        for filepath in generated_files:
            if os.path.exists(filepath):
                total_size += os.path.getsize(filepath)
        
        logger.info(f"Report generation completed: {len(generated_files)} files, {total_size/1024:.1f}KB total")




# Backwards compatibility alias
Reporter = EnhancedReporter        