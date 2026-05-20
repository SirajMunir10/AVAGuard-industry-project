import sys
import json

with open('c:\\AVA\\desktop_app\\workers\\enhanced_worker.py', 'r', encoding='utf-8') as f:
    content = f.read()

lines = content.split('\n')

for i, line in enumerate(lines):
    if 'self.log_message.emit(f"Validating dataset... Found {user_count} users.", "info")' in line:
        indent = line.split('self.log_message')[0]
        # We need to extract expected failures.
        lines.insert(i+1, indent + 'try:')
        lines.insert(i+2, indent + '    pct = data.get("metadata", {}).get("config", {}).get("generation", {}).get("failure_injection_rate", 0)')
        lines.insert(i+3, indent + '    self.expected_failure_pct = pct * 100')
        lines.insert(i+4, indent + '    self.expected_failure_count = int(user_count * pct)')
        lines.insert(i+5, indent + '    self.log_message.emit(f"Expected Failures: {self.expected_failure_count} ({self.expected_failure_pct}%)", "info")')
        lines.insert(i+6, indent + 'except Exception as e:')
        lines.insert(i+7, indent + '    self.expected_failure_count = -1')
        lines.insert(i+8, indent + '    logger.warning(f"Could not parse expected failures: {e}")')
        break

for i, line in enumerate(lines):
    if 'raise SessionRevokedError("Session revoked during check execution")' in line:
        indent = line.split('raise')[0]
        lines.insert(i, indent + 'logger.info(f"Scan cancellation started at {datetime.now().isoformat()}")')
        lines.insert(i+1, indent + 'self.scan_progress.emit(100, "Scan cancelled due to session revocation.")')
        lines.insert(i+2, indent + 'logger.info(f"Scan cancellation ended at {datetime.now().isoformat()}")')
        break

for i, line in enumerate(lines):
    if 'return results' in line and 'def _execute_checks' not in line:
        indent = line.split('return')[0]
        # At the end of _execute_checks, validate summary
        lines.insert(i, indent + 'actual_failures = sum(1 for r in results if r.status != CheckStatus.PASS)')
        lines.insert(i+1, indent + 'if hasattr(self, "expected_failure_count") and self.expected_failure_count >= 0:')
        lines.insert(i+2, indent + '    if actual_failures != self.expected_failure_count:')
        lines.insert(i+3, indent + '        logger.warning(f"SCAN SUMMARY DEVIATION: Expected {self.expected_failure_count} failures, but found {actual_failures}")')
        lines.insert(i+4, indent + '        self.log_message.emit(f"Validation Warning: Found {actual_failures} failures (Expected {self.expected_failure_count})", "warning")')
        lines.insert(i+5, indent + '    else:')
        lines.insert(i+6, indent + '        logger.info(f"SCAN SUMMARY VALIDATED: Exactly {actual_failures} failures detected as expected.")')
        lines.insert(i+7, indent + '        self.log_message.emit(f"Validation Match: Exactly {actual_failures} failures detected.", "success")')
        break

with open('c:\\AVA\\desktop_app\\workers\\enhanced_worker.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
