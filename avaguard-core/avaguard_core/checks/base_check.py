"""Base class for CIS compliance checks - Refined Version."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, ClassVar
from datetime import datetime
from enum import Enum
import logging

# Setup logger for all checks
logger = logging.getLogger(__name__)

# === Refined: Moved CISSeverity before CheckStatus for better organization ===
class CISSeverity(Enum):
    """CIS control severity levels as per SRS Appendix A."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class CheckStatus(Enum):
    """Status of a compliance check with severity levels."""
    PASS = "PASS"          # Control fully compliant
    FAIL = "FAIL"          # Control non-compliant
    WARNING = "WARNING"    # Partial compliance or attention needed
    ERROR = "ERROR"        # Technical error during check
    SKIPPED = "SKIPPED"    # Check skipped (e.g., premium feature on free tier)
    
    @property
    def severity(self) -> int:
        """Get severity score for sorting (higher = more critical)."""
        severity_map = {
            'FAIL': 4,
            'ERROR': 3,
            'WARNING': 2,
            'PASS': 1,
            'SKIPPED': 0
        }
        return severity_map.get(self.value, 0)

@dataclass
class CheckResult:
    """Enhanced result of a compliance check with full SRS schema support."""
    # Core identification (from SRS Table 7.1)
    check_id: str = ""  # Moved to top for better visibility
    title: str = ""
    scan_id: Optional[str] = None  # UUID linking to parent scan
    
    # Status and counts
    status: CheckStatus = CheckStatus.SKIPPED
    compliant_count: int = 0
    non_compliant_count: int = 0
    warning_count: int = 0
    total_count: int = 0
    details: str = ""
    
    # Resource tracking (SRS evidence collection)
    non_compliant_resources: List[Dict[str, Any]] = field(default_factory=list)
    compliant_resources: List[Dict[str, Any]] = field(default_factory=list)
    warning_resources: List[Dict[str, Any]] = field(default_factory=list)
    
    # SRS compliance metadata
    cis_control_id: str = ""  # Full CIS ID like "1.1"
    category: str = ""  # Authentication, User Management, etc.
    cis_severity: CISSeverity = CISSeverity.MEDIUM  # From SRS Appendix A
    priority: str = "Medium"  # Critical, High, Medium, Low - Added default
    
    # Extended metadata for SRS requirements
    metadata: Dict[str, Any] = field(default_factory=dict)  # Raw API evidence
    evidence: Dict[str, Any] = field(default_factory=dict)  # SRS FR-14
    initiated_by: Optional[str] = None  # SRS Table 7.1
    target_tenant: Optional[str] = None  # SRS Table 7.1
    
    # Remediation and error handling
    remediation: str = ""
    error_message: Optional[str] = None
    error_traceback: Optional[str] = None  # Detailed error info
    
    # Timing and resource usage
    timestamp: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0  # Performance tracking
    api_calls_count: int = 0  # SRS FR-28 performance metrics
    
    # Licensing and access
    requires_premium: bool = False
    api_permissions_required: List[str] = field(default_factory=list)
    
    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage (SRS scoring)."""
        if self.total_count == 0:
            return 100.0 if self.status == CheckStatus.PASS else 0.0
        return (self.compliant_count / self.total_count) * 100
    
    @property
    def overall_score(self) -> float:
        """Calculate weighted score considering severity."""
        base_score = self.compliance_percentage
        # Apply severity weight (SRS compliance scoring)
        severity_weights = {
            CISSeverity.CRITICAL: 1.0,
            CISSeverity.HIGH: 0.8,
            CISSeverity.MEDIUM: 0.6,
            CISSeverity.LOW: 0.4
        }
        weight = severity_weights.get(self.cis_severity, 0.5)
        return base_score * weight
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary matching SRS Table 7.1 schema."""
        return {
            # SRS Table 7.1 fields
            'scan_id': self.scan_id,
            'timestamp': self.timestamp.isoformat(),
            'initiated_by': self.initiated_by,
            'target_tenant': self.target_tenant,
            'cis_control_id': self.cis_control_id,
            'status': self.status.value,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'severity': self.cis_severity.value,
            
            # Extended fields
            'check_id': self.check_id,
            'title': self.title,
            'category': self.category,
            'priority': self.priority,
            'compliant_count': self.compliant_count,
            'non_compliant_count': self.non_compliant_count,
            'warning_count': self.warning_count,
            'total_count': self.total_count,
            'compliance_percentage': round(self.compliance_percentage, 2),
            'overall_score': round(self.overall_score, 2),
            'details': self.details,
            'non_compliant_resources': self.non_compliant_resources,
            'compliant_resources': self.compliant_resources,
            'warning_resources': self.warning_resources,
            'metadata': self.metadata,
            'error_message': self.error_message,
            'error_traceback': self.error_traceback,
            'duration_seconds': round(self.duration_seconds, 3),
            'api_calls_count': self.api_calls_count,
            'requires_premium': self.requires_premium,
            'api_permissions_required': self.api_permissions_required
        }
    
    def to_audit_format(self) -> Dict[str, Any]:
        """Format for audit trail (SRS FR-29, FR-32)."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'control': f"{self.cis_control_id} - {self.title}",
            'status': self.status.value,
            'severity': self.cis_severity.value,
            'tenant': self.target_tenant,
            'user': self.initiated_by,
            'compliance_score': round(self.compliance_percentage, 1),
            'resource_count': self.total_count,
            'evidence_hash': hash(str(self.evidence))  # For tamper detection
        }

class BaseCheck(ABC):
    """Abstract base class for all CIS compliance checks with enhanced features."""
    
    # Class-level metadata - MUST be overridden by subclasses
    CHECK_ID: ClassVar[str] = ""
    TITLE: ClassVar[str] = ""
    DESCRIPTION: ClassVar[str] = ""
    
    # SRS Appendix A metadata
    CIS_CONTROL_ID: ClassVar[str] = ""  # Full CIS ID like "1.1"
    CATEGORY: ClassVar[str] = ""  # Authentication, User Management, etc.
    CIS_SEVERITY: ClassVar[CISSeverity] = CISSeverity.MEDIUM
    PRIORITY: ClassVar[str] = "Medium"  # Critical, High, Medium, Low
    
    # Technical requirements
    REQUIRES_PREMIUM: ClassVar[bool] = False
    API_PERMISSIONS_REQUIRED: ClassVar[List[str]] = field(default_factory=list)
    SUPPORTED_API_VERSIONS: ClassVar[List[str]] = ["v1.0", "beta"]
    
    def __init__(self, graph_client, config: Optional[Dict] = None):
        """
        Initialize check with dependencies.
        
        Args:
            graph_client: Instance of GraphAPIClient (live or mock)
            config: Dictionary with check configuration
                   Example: {
                       'tenant_id': 'xxx',
                       'initiated_by': 'user@domain.com',
                       'scan_id': 'uuid',
                       'check_specific': {...}
                   }
        """
        self.graph_client = graph_client
        self.config = config or {}
        self._api_calls = 0  # Track API usage
        self._start_time: Optional[datetime] = None
        
    @abstractmethod
    def execute(self) -> CheckResult:
        """
        Execute the compliance check logic.
        
        Returns:
            CheckResult object with detailed compliance assessment.
        """
        pass
    
    def _track_api_call(self):
        """Increment API call counter for performance tracking."""
        self._api_calls += 1
    
    def _safe_graph_call(self, method_name: str, *args, **kwargs) -> Any:
        """
        Wrapper for Graph API calls with error handling and tracking.
        
        Args:
            method_name: Name of the graph_client method to call
            *args, **kwargs: Arguments to pass to the method
            
        Returns:
            Result of the API call or None on error
        """
        try:
            self._track_api_call()
            method = getattr(self.graph_client, method_name)
            return method(*args, **kwargs)
        except Exception as e:
            logger.error(f"Graph API call failed in {self.CHECK_ID}: {e}")
            return None
    
    def create_result(
        self,
        status: CheckStatus,
        compliant_count: int = 0,
        non_compliant_count: int = 0,
        warning_count: int = 0,
        total_count: int = 0,
        details: str = "",
        non_compliant_resources: Optional[List[Dict]] = None,
        compliant_resources: Optional[List[Dict]] = None,
        warning_resources: Optional[List[Dict]] = None,
        evidence: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
        remediation: str = "",
        error_message: Optional[str] = None,
        error_traceback: Optional[str] = None
    ) -> CheckResult:
        """
        Enhanced factory method for creating CheckResult with full SRS compliance.
        
        Args:
            status: Check status
            compliant_count: Number of compliant resources
            non_compliant_count: Number of non-compliant resources
            warning_count: Number of resources with warnings
            total_count: Total resources checked
            details: Human-readable result summary
            non_compliant_resources: List of non-compliant resources with details
            compliant_resources: List of compliant resources
            warning_resources: List of resources with warnings
            evidence: Raw API responses supporting the evaluation (SRS FR-14)
            metadata: Additional check-specific metadata
            remediation: Guidance for addressing failures
            error_message: Error description if check failed
            error_traceback: Full traceback for debugging
            
        Returns:
            Fully populated CheckResult object
        """
        # Calculate duration if tracking was enabled
        duration = 0.0
        if self._start_time:
            duration = (datetime.now() - self._start_time).total_seconds()
        
        result = CheckResult(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            scan_id=self.config.get('scan_id'),
            status=status,
            compliant_count=compliant_count,
            non_compliant_count=non_compliant_count,
            warning_count=warning_count,
            total_count=total_count,
            details=details,
            non_compliant_resources=non_compliant_resources or [],
            compliant_resources=compliant_resources or [],
            warning_resources=warning_resources or [],
            cis_control_id=self.CIS_CONTROL_ID,
            category=self.CATEGORY,
            cis_severity=self.CIS_SEVERITY,
            priority=self.PRIORITY,
            evidence=evidence or {},
            metadata=metadata or {},
            initiated_by=self.config.get('initiated_by'),
            target_tenant=self.config.get('tenant_id'),
            remediation=remediation,
            error_message=error_message,
            error_traceback=error_traceback,
            duration_seconds=duration,
            api_calls_count=self._api_calls,
            requires_premium=self.REQUIRES_PREMIUM,
            api_permissions_required=self.API_PERMISSIONS_REQUIRED
        )
        
        return result
    
    def execute_with_timing(self) -> CheckResult:
        """
        Execute check with performance timing and error handling.
        
        Returns:
            CheckResult with timing and error information
        """
        self._start_time = datetime.now()
        
        try:
            result = self.execute()
            # Ensure metadata includes timing
            if hasattr(result, 'duration_seconds'):
                result.duration_seconds = (datetime.now() - self._start_time).total_seconds()
            return result
        except Exception as e:
            logger.exception(f"Check {self.CHECK_ID} failed with error: {e}")
            return self.create_result(
                status=CheckStatus.ERROR,
                details=f"Check execution failed: {str(e)}",
                error_message=str(e),
                error_traceback=self._format_traceback()
            )
    
    def _format_traceback(self) -> str:
        """Format traceback for storage in results."""
        import traceback
        return traceback.format_exc()
    
    def validate_configuration(self) -> List[str]:
        """
        Validate check configuration before execution.
        
        Returns:
            List of validation errors, empty if valid
        """
        errors = []
        
        # Validate required metadata
        if not self.CHECK_ID:
            errors.append("CHECK_ID must be set")
        if not self.TITLE:
            errors.append("TITLE must be set")
        if not self.CIS_CONTROL_ID:
            errors.append("CIS_CONTROL_ID must be set")
        
        # Validate configuration
        if self.REQUIRES_PREMIUM and not self.config.get('is_premium', False):
            errors.append(f"Check {self.CHECK_ID} requires premium tier")
        
        return errors
    
    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        """Get check metadata for registry and documentation."""
        return {
            'check_id': cls.CHECK_ID,
            'cis_control_id': cls.CIS_CONTROL_ID,
            'title': cls.TITLE,
            'description': cls.DESCRIPTION,
            'category': cls.CATEGORY,
            'severity': cls.CIS_SEVERITY.value,
            'priority': cls.PRIORITY,
            'requires_premium': cls.REQUIRES_PREMIUM,
            'api_permissions': cls.API_PERMISSIONS_REQUIRED,
            'supported_api_versions': cls.SUPPORTED_API_VERSIONS
        }