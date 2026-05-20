import sys

with open('c:\\AVA\\desktop_app\\workers\\sync_worker.py', 'r', encoding='utf-8') as f:
    content = f.read()

lines = content.split('\n')
for i, line in enumerate(lines):
    if "if e.__class__.__name__ == 'SessionRevokedException':" in line:
        indent = line.split('if')[0]
        lines[i] = indent + "if e.__class__.__name__ in ['SessionRevokedException', 'SessionRevokedError'] or isinstance(e, SessionRevokedError):"
        lines[i+1] = indent + "    logger.info(f'Sync cancellation started (exception) at {datetime.now().isoformat()}')"
        lines[i+2] = indent + "    self.session_revoked.emit(str(e))"
        lines.insert(i+3, indent + "    logger.info(f'Sync cancellation ended (exception) at {datetime.now().isoformat()}')")
        lines.insert(i+4, indent + "    return")
        del lines[i+5:i+6]
        break

for i, line in enumerate(lines):
    if "from utils.session_manager import GlobalSessionManager" in line:
        if "from utils.exceptions import SessionRevokedError" not in content:
            lines.insert(i+1, "from utils.exceptions import SessionRevokedError")
            lines.insert(i+2, "from datetime import datetime")
            break

with open('c:\\AVA\\desktop_app\\workers\\sync_worker.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
