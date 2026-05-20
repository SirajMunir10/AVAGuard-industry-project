from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        """
        Start background threads when the app is ready.
        - Sync worker: syncs desktop scans every 30 seconds
        - Cleanup worker: cleans expired sessions and old audit logs
        Only runs in the main process (not the autoreloader).
        """
        import os
        import threading
        import time
        from django.conf import settings
        
        # Prevent running twice when using runserver with autoreload
        if os.environ.get('RUN_MAIN') != 'true':
            # This is the reloader process, don't start threads
            return

        def sync_worker():
            """Background thread to sync desktop scans periodically."""
            # Wait for DB to be fully ready
            time.sleep(5)
            
            from core.sync_service import sync_desktop_scans
            import logging
            logger = logging.getLogger(__name__)
            
            logger.info("Starting background sync service...")
            
            while True:
                try:
                    result = sync_desktop_scans()
                    if result['success'] and result['synced'] > 0:
                        logger.info(f"Background Sync: {result['message']}")
                    elif not result['success']:
                         # Silent fail if DB locked or not found to avoid spam
                         pass
                except Exception as e:
                    logger.error(f"Background Sync Error: {e}")
                
                # Sync every 30 seconds
                time.sleep(30)

        def cleanup_worker():
            """
            Background thread to clean up expired sessions and old audit logs.
            - Session cleanup: every 5 minutes (revokes sessions > 24 hours)
            - Audit log cleanup: every hour (deletes logs > 3 days)
            """
            # Wait for DB to be fully ready
            time.sleep(10)
            
            import logging
            logger = logging.getLogger(__name__)
            
            logger.info("Starting background cleanup service...")
            
            # Track when we last ran audit cleanup (expensive operation)
            last_audit_cleanup = 0
            AUDIT_CLEANUP_INTERVAL = 3600  # 1 hour in seconds
            SESSION_CLEANUP_INTERVAL = 300  # 5 minutes in seconds
            
            while True:
                try:
                    # Import models here to avoid circular imports
                    from core.models import ActiveSession, AuditLog
                    
                    # Session cleanup - revoke sessions older than 24 hours
                    sessions_revoked = ActiveSession.cleanup_expired(max_age_hours=24)
                    if sessions_revoked > 0:
                        logger.info(f"Cleanup: Revoked {sessions_revoked} expired session(s)")
                    
                    # Audit log archival - archive logs older than 90 days (run hourly)
                    current_time = time.time()
                    if current_time - last_audit_cleanup >= AUDIT_CLEANUP_INTERVAL:
                        logs_archived = AuditLog.archive_old_logs(days=90)
                        if logs_archived > 0:
                            logger.info(f"Archival: Archived {logs_archived} old audit log(s)")
                        last_audit_cleanup = current_time
                        
                except Exception as e:
                    logger.error(f"Background Cleanup Error: {e}")
                
                # Check sessions every 5 minutes
                time.sleep(SESSION_CLEANUP_INTERVAL)

        # Start the sync thread as a daemon
        sync_thread = threading.Thread(target=sync_worker, daemon=True)
        sync_thread.start()
        
        # Start the cleanup thread as a daemon
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()

