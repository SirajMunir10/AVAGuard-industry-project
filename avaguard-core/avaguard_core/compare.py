import json
from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class ScanDiff:
    newly_failing: List[str] = field(default_factory=list)
    newly_passing: List[str] = field(default_factory=list)
    unchanged: List[str] = field(default_factory=list)
    score_delta: float = 0.0

def _get_status(r: dict) -> str:
    status = r.get('status', 'ERROR')
    if isinstance(status, dict) and 'value' in status:
        return status['value']
    return str(status)

def compare_scans(scan_a: dict, scan_b: dict) -> ScanDiff:
    """Compare two scan dict payloads and generate a diff."""
    
    diff = ScanDiff()
    
    # Calculate score delta
    score_a = scan_a.get('overall_score', 0.0)
    score_b = scan_b.get('overall_score', 0.0)
    diff.score_delta = round(score_b - score_a, 2)
    
    results_a = {r.get('check_id'): _get_status(r) for r in scan_a.get('results', []) if r.get('check_id')}
    results_b = {r.get('check_id'): _get_status(r) for r in scan_b.get('results', []) if r.get('check_id')}
    
    for cid, stat_b in results_b.items():
        stat_a = results_a.get(cid)
        if stat_a == stat_b:
            diff.unchanged.append(cid)
        elif stat_b == 'PASS' and stat_a != 'PASS':
            diff.newly_passing.append(cid)
        elif stat_b == 'FAIL' and stat_a != 'FAIL':
            diff.newly_failing.append(cid)
            
    # Handle checks that only exist in A
    for cid, stat_a in results_a.items():
        if cid not in results_b:
            # Assume it became absent/changed state if we want, but typically diff relies on new scan
            pass
            
    return diff
