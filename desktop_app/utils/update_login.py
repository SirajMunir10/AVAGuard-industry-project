import sys
from datetime import datetime

with open('c:\\AVA\\desktop_app\\ui\\login_dialog.py', 'r', encoding='utf-8') as f:
    content = f.read()

lines = content.split('\n')

for i, line in enumerate(lines):
    if 'if response.status_code == 200:' in line:
        indent = line.split('if')[0]
        lines.insert(i+1, indent + '    logger.info(f"Heartbeat success at {datetime.now().isoformat()}")')
        break

for i, line in enumerate(lines):
    if 'GlobalSessionManager().revoke()' in line:
        indent = line.split('GlobalSessionManager')[0]
        lines.insert(i+1, indent + 'logger.error(f"Session revoked detected at {datetime.now().isoformat()}")')
        break

for i, line in enumerate(lines):
    if 'import requests' in line:
        if 'from datetime import datetime' not in content:
            lines.insert(i, 'from datetime import datetime')
            break

with open('c:\\AVA\\desktop_app\\ui\\login_dialog.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
