import os
import json
import pytest
from datetime import datetime
from avaguard_core.engine import ScanResult, ScanEngine
from avaguard_core.checks.base_check import CheckResult, CheckStatus
from avaguard_core.compare import compare_scans, ScanDiff

def test_scan_result_dataclass():
    res = ScanResult(
        scan_id="001",
        timestamp=datetime.now(),
        metrics={"duration": 1.5},
        results=[CheckResult(check_id="1", status=CheckStatus.PASS)]
    )
    assert res.scan_id == "001"
    assert len(res.results) == 1

def test_scan_engine_thread_pool():
    class DummyCheck:
        def __init__(self, client, config=None):
            pass
        def execute(self):
            return CheckResult(check_id="dummy", status=CheckStatus.PASS)

    engine = ScanEngine(client=None)
    checks = {"dummy": DummyCheck}
    r = engine.execute_checks(checks)
    assert r.results[0].check_id == "dummy"
    assert r.results[0].status == CheckStatus.PASS

def test_compare_scans():
    scan_a = {
        "overall_score": 50.0,
        "results": [
            {"check_id": "c1", "status": "FAIL"},
            {"check_id": "c2", "status": "PASS"},
            {"check_id": "c3", "status": "PASS"}
        ]
    }
    scan_b = {
        "overall_score": 80.0,
        "results": [
            {"check_id": "c1", "status": "PASS"},  # newly passing
            {"check_id": "c2", "status": "FAIL"},  # newly failing
            {"check_id": "c3", "status": "PASS"}   # unchanged
        ]
    }
    
    diff = compare_scans(scan_a, scan_b)
    assert diff.score_delta == 30.0
    assert "c1" in diff.newly_passing
    assert "c2" in diff.newly_failing
    assert "c3" in diff.unchanged
