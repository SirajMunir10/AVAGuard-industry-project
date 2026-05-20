"""
AVAGuard Core - Compliance Framework Mapper
Maps CIS Benchmarks to broader compliance frameworks (NIST 800-53, ISO 27001).
"""

from typing import Dict, List, Any
from dataclasses import dataclass
from avaguard_core.checks.base_check import CheckResult, CheckStatus

@dataclass
class FrameworkMapping:
    nist_800_53: List[str]
    iso_27001: List[str]
    description: str

class FrameworkMapper:
    """Maps CIS Azure checks to enterprise frameworks."""
    
    # Static mapping based on CIS Controls mapping tables
    MAPPINGS: Dict[str, FrameworkMapping] = {
        "1.1": FrameworkMapping(
            nist_800_53=["AC-2(1)", "IA-2(1)", "IA-2(2)", "IA-8"],
            iso_27001=["A.9.4.2", "A.9.2.1"],
            description="Require MFA for all users"
        ),
        "1.3": FrameworkMapping(
            nist_800_53=["AC-3", "AC-17", "IA-2"],
            iso_27001=["A.9.1.1", "A.9.1.2"],
            description="Enable Security Defaults"
        ),
        "1.8": FrameworkMapping(
            nist_800_53=["IA-5(1)", "AC-2(1)"],
            iso_27001=["A.9.4.3"],
            description="Enable Self-Service Password Reset (SSPR)"
        ),
        "1.11": FrameworkMapping(
            nist_800_53=["AC-2(4)", "AC-17(2)", "CM-7(1)"],
            iso_27001=["A.13.1.1", "A.13.2.1", "A.9.1.2"],
            description="Block Legacy Authentication"
        ),
        "2.1": FrameworkMapping(
            nist_800_53=["SC-20", "SC-21"],
            iso_27001=["A.13.1.3", "A.14.1.2"],
            description="Ensure that only approved domain names are used"
        ),
        "3.1": FrameworkMapping(
            nist_800_53=["AU-6", "SI-4(4)"],
            iso_27001=["A.12.4.1", "A.16.1.2"],
            description="Sign-in Risk Policy (AADP2)"
        )
    }
    
    @classmethod
    def get_mapping(cls, check_id: str) -> FrameworkMapping:
        """Get the framework mapping for a specific CIS check."""
        return cls.MAPPINGS.get(check_id, FrameworkMapping(
            nist_800_53=["General Control"],
            iso_27001=["General Control"],
            description="Standard Security Control"
        ))

    @classmethod
    def generate_framework_report(cls, results: List[CheckResult]) -> Dict[str, Any]:
        """Aggregate compliance state across frameworks from current results."""
        framework_status = {
            "NIST 800-53": {"covered_controls": set(), "failed_controls": set()},
            "ISO 27001": {"covered_controls": set(), "failed_controls": set()},
        }
        
        for result in results:
            cis_id = getattr(result, 'cis_control_id', result.check_id)
            mapping = cls.get_mapping(cis_id)
            is_fail = result.status in (CheckStatus.FAIL, CheckStatus.ERROR)
            
            for ctrl in mapping.nist_800_53:
                framework_status["NIST 800-53"]["covered_controls"].add(ctrl)
                if is_fail:
                    framework_status["NIST 800-53"]["failed_controls"].add(ctrl)
                    
            for ctrl in mapping.iso_27001:
                framework_status["ISO 27001"]["covered_controls"].add(ctrl)
                if is_fail:
                    framework_status["ISO 27001"]["failed_controls"].add(ctrl)
                    
        return {
            "NIST 800-53": {
                "covered": sorted(list(framework_status["NIST 800-53"]["covered_controls"])),
                "at_risk": sorted(list(framework_status["NIST 800-53"]["failed_controls"])),
                "compliance_score": cls._calc(
                    len(framework_status["NIST 800-53"]["covered_controls"]),
                    len(framework_status["NIST 800-53"]["failed_controls"])
                )
            },
            "ISO 27001": {
                "covered": sorted(list(framework_status["ISO 27001"]["covered_controls"])),
                "at_risk": sorted(list(framework_status["ISO 27001"]["failed_controls"])),
                "compliance_score": cls._calc(
                    len(framework_status["ISO 27001"]["covered_controls"]),
                    len(framework_status["ISO 27001"]["failed_controls"])
                )
            }
        }
        
    @staticmethod
    def _calc(total: int, failed: int) -> float:
        if total == 0: return 0.0
        return round(((total - failed) / total) * 100, 1)
