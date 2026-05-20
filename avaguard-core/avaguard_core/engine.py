from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Type
import concurrent.futures
import logging
import os

from .checks.base_check import CheckResult, CheckStatus
from .checks.protocol import CheckProtocol

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Structured response container for a complete CIS compliance scan."""
    scan_id: str
    timestamp: datetime
    metrics: Dict[str, Any]
    results: List[CheckResult] = field(default_factory=list)

class ScanEngine:
    """Core execution engine for compliance scans using ThreadPoolExecutor."""
    
    def __init__(self, client):
        self.client = client
        
    def execute_checks(self, checks: Dict[str, Type[CheckProtocol]], check_config: dict = None) -> ScanResult:
        scan_id = f"SCAN_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        scan_result = ScanResult(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc),
            metrics={}
        )
        
        def run_single(check_id: str, check_class: Type[CheckProtocol]):
            logger.debug(f"Thread starting for check: {check_id}")
            try:
                try:
                    check = check_class(self.client, config=check_config)
                except TypeError:
                    check = check_class(self.client)
                
                result = check.execute()
                
                if not getattr(result, 'check_id', None):
                    result.check_id = check_id
                    
                return result
            except Exception as e:
                logger.warning(f"Check {check_id} failed during execution: {e}", exc_info=True)
                return CheckResult(
                    check_id=check_id,
                    title=getattr(check_class, 'TITLE', check_id),
                    description=getattr(check_class, 'DESCRIPTION', ""),
                    status=CheckStatus.ERROR,
                    compliant_count=0,
                    total_count=0,
                    details=f"Execution failed: {str(e)}"
                )

        max_workers = min(10, (os.cpu_count() or 1) * 2)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_check = {
                executor.submit(run_single, cid, cls): cid 
                for cid, cls in checks.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_check):
                cid = future_to_check[future]
                try:
                    res = future.result()
                    scan_result.results.append(res)
                except Exception as e:
                    logger.warning(f"Unhandled exception retrieving {cid} result: {e}")

        return scan_result
