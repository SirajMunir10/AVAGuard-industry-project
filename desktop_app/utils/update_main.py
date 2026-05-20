import sys

with open('c:\\AVA\\desktop_app\\views\\main_window_enhanced.py', 'r', encoding='utf-8') as f:
    content = f.read()

lines = content.split('\n')

for i, line in enumerate(lines):
    if 'logger.info("Enhanced AVAGuard Desktop started")' in line:
        indent = line.split('logger')[0]
        lines.insert(i, indent + 'self._revocation_in_progress = False')
        lines.insert(i+1, indent + '# QA Diagnostic Output')
        lines.insert(i+2, indent + 'logger.info("""')
        lines.insert(i+3, indent + '============= QA DIAGNOSTIC =============')
        lines.insert(i+4, indent + 'Config Path: {self.config_path}')
        lines.insert(i+5, indent + 'Active Dataset: [Lazy loaded by worker]')
        lines.insert(i+6, indent + 'Heartbeat Interval: 10000ms')
        lines.insert(i+7, indent + 'Session State: INITIALIZING')
        lines.insert(i+8, indent + '=========================================""".format(self=self))')
        break

for i, line in enumerate(lines):
    if 'def handle_session_revoked(self, reason=""): ' in line or 'def handle_session_revoked(self, reason=""):\r' in line or 'def handle_session_revoked(self, reason=""):' in line:
        indent = line.split('def')[0]
        lines.insert(i+2, indent + '    if getattr(self, "_revocation_in_progress", False):')
        lines.insert(i+3, indent + '        return')
        lines.insert(i+4, indent + '    self._revocation_in_progress = True')
        break

for i, line in enumerate(lines):
    if 'sys.exit(0)' in line and 'sys.exit(1)' not in line:
        indent = line.split('sys')[0]
        lines.insert(i, indent + 'import os')
        lines.insert(i+1, indent + 'from PyQt6.QtWidgets import QApplication')
        lines.insert(i+2, indent + 'QApplication.quit()')
        lines.insert(i+4, indent + 'os._exit(0)')
        break

with open('c:\\AVA\\desktop_app\\views\\main_window_enhanced.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
