"""
AVAGuard Desktop - Sync Worker Module

Background worker for synchronizing scans with the web portal.
"""

import logging
from PyQt6.QtCore import QThread, pyqtSignal
from utils.session_manager import GlobalSessionManager
from utils.exceptions import SessionRevokedError
from datetime import datetime

# Import web_client's own SessionRevokedException (different class, same purpose)
try:
    from web_client import SessionRevokedException
except ImportError:
    SessionRevokedException = None

logger = logging.getLogger(__name__)

class SyncWorker(QThread):
    """
    Background worker for synchronizing scans.
    
    Signals:
        progress: Emitted with (current, total, status_text)
        finished: Emitted with (synced_count, failed_count, error_details)
    """
    progress = pyqtSignal(int, int, str)
    finished = pyqtSignal(int, int, list)
    session_revoked = pyqtSignal(str)
    
    def __init__(self, db, web_client, unsynced_scans):
        super().__init__()
        self.db = db
        self.web_client = web_client
        self.unsynced_scans = unsynced_scans
        self.is_running = True
        
    def stop(self):
        self.is_running = False
        
    def run(self):
        synced_count = 0
        failed_count = 0
        error_details = []
        total = len(self.unsynced_scans)
        
        for i, scan in enumerate(self.unsynced_scans):
            if GlobalSessionManager().is_revoked():
                logger.info(f"Sync cancellation started at {datetime.now().isoformat()}")
                self.is_running = False
                self.session_revoked.emit("Session revoked during sync")
                logger.info(f"Sync cancellation ended at {datetime.now().isoformat()}")
                return
            if not self.is_running:
                break
                
            scan_id = scan['scan_id']
            self.progress.emit(i, total, f"Syncing scan {scan_id[:8]}...")
            
            try:
                # Get full details
                details = self.db.get_scan_details(scan_id)
                if not details:
                    failed_count += 1
                    error_details.append(f"Scan {scan_id[:8]}: No details found in local DB.")
                    continue

                checks = details.get('checks', [])
                
                success, msg = self.web_client.upload_scan(
                    scan_id=scan_id,
                    overall_score=scan['overall_score'],
                    passed_count=scan['passed_checks'],
                    failed_count=scan['failed_checks'],
                    total_checks=scan['total_checks'],
                    results=checks
                )
                
                if success:
                    self.db.mark_as_synced(scan_id)
                    synced_count += 1
                else:
                    # Check if the failure was because of session revocation
                    # (GlobalSessionManager will be set if web_client detected a 403 revocation)
                    if GlobalSessionManager().is_revoked():
                        logger.info(f"Sync cancelled after revoked-session failure at {datetime.now().isoformat()}")
                        self.session_revoked.emit("Session revoked during sync (403 detected)")
                        return
                    failed_count += 1
                    # Clean up the message (truncate if still too long somehow)
                    clean_msg = str(msg)[:200]
                    error_details.append(f"Scan {scan_id[:8]}: {clean_msg}")
                    
            except Exception as e:
                is_revoked_exc = (
                    isinstance(e, SessionRevokedError)
                    or (SessionRevokedException and isinstance(e, SessionRevokedException))
                    or e.__class__.__name__ in ['SessionRevokedException', 'SessionRevokedError']
                )
                if is_revoked_exc:
                    logger.info(f'Sync cancellation started (exception) at {datetime.now().isoformat()}')
                    # Sync upload rejected with revocation — this IS a genuine session rejection.
                    # Set the global token here so all threads are informed.
                    GlobalSessionManager().revoke()
                    self.session_revoked.emit(str(e))
                    logger.info(f'Sync cancellation ended (exception) at {datetime.now().isoformat()}')
                    return
                error_msg = f"Exception syncing {scan_id[:8]}: {str(e)}"
                logger.error(error_msg)
                failed_count += 1
                error_details.append(error_msg)
                
        if self.is_running:
            self.progress.emit(total, total, "Sync complete")
            self.finished.emit(synced_count, failed_count, error_details)
