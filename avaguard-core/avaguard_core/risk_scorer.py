"""
AVAGuard Core - Risk Scoring Module
Calculates weighted compliance scores based on CIS severity levels.
"""

from typing import List, Dict, Any
from avaguard_core.checks.base_check import CheckResult, CheckStatus, CISSeverity

class RiskScorer:
    """Computes weighted risk scores based on check results and severities."""
    
    SEVERITY_WEIGHTS = {
        CISSeverity.CRITICAL: 10.0,
        CISSeverity.HIGH: 7.0,
        CISSeverity.MEDIUM: 4.0,
        CISSeverity.LOW: 1.0,
    }

    @classmethod
    def calculate_score(cls, results: List[CheckResult]) -> float:
        """
        Calculate an organizational risk score from 0.0 to 100.0 based on severity weights.
        
        Args:
            results: A list of CheckResult objects from a scan.
            
        Returns:
            A float representing the weighted compliance score (0-100).
        """
        if not results:
            return 0.0
            
        total_possible_weight = 0.0
        earned_weight = 0.0
        
        for result in results:
            severity = getattr(result, 'cis_severity', CISSeverity.MEDIUM)
            weight = cls.SEVERITY_WEIGHTS.get(severity, 4.0)
            total_possible_weight += weight
            
            # Support partial compliance percentages if provided by complex checks
            if getattr(result, 'compliance_percentage', None) is not None:
                # E.g., if a check is 80% compliant, it earns 80% of its weight
                earned_weight += weight * (result.compliance_percentage / 100.0)
            else:
                # Fallback to binary PASS/FAIL
                if result.status == CheckStatus.PASS:
                    earned_weight += weight
                # FAIL and ERROR earn zero weight
                    
        if total_possible_weight == 0:
            return 0.0
            
        return round((earned_weight / total_possible_weight) * 100.0, 1)

    @classmethod
    def calculate_metrics(cls, results: List[CheckResult]) -> Dict[str, Any]:
        """Calculate detailed scoring metrics."""
        score = cls.calculate_score(results)
        
        passed = sum(1 for r in results if r.status == CheckStatus.PASS)
        failed = sum(1 for r in results if r.status == CheckStatus.FAIL)
        errors = sum(1 for r in results if r.status == CheckStatus.ERROR)
        
        return {
            "overall_score": score,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "total": len(results),
            "risk_level": cls.get_risk_level(score)
        }
        
    @staticmethod
    def get_risk_level(score: float) -> str:
        """Categorize organizational risk level based on the weighted score."""
        if score >= 90:
            return "LOW"
        elif score >= 70:
            return "MEDIUM"
        elif score >= 50:
            return "HIGH"
        else:
            return "CRITICAL"
