"""
AVAGuard Web Portal - Sync Service

Handles synchronization of scan data from Desktop SQLite to Web PostgreSQL.
This enables the Tethered Security Model where desktop scans automatically
appear in the web portal.
"""

import os
import json
import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from django.db import transaction
from django.utils import timezone
from django.conf import settings

from .models import ScanResult, Organization, User, AuditLog

logger = logging.getLogger(__name__)


class DesktopSyncService:
    """
    Service to synchronize scan data from Desktop app's SQLite database
    to the Web Portal's PostgreSQL database.
    
    Architecture:
        Desktop App (SQLite) → Sync Service → Web Portal (PostgreSQL)
    
    The Desktop app stores scans locally in SQLite. When online, this service
    pulls new scans and syncs them to PostgreSQL for web viewing.
    """
    
    # Default path to desktop SQLite database
    DEFAULT_DESKTOP_DB_PATH = Path.home() / '.avaguard' / 'scans.db'
    
    def __init__(self, desktop_db_path=None, organization=None):
        """
        Initialize the sync service.
        
        Args:
            desktop_db_path: Path to the desktop SQLite database file.
                            Defaults to ~/.avaguard/scans.db
            organization: Organization to associate synced scans with.
        """
        self.desktop_db_path = Path(desktop_db_path or self.DEFAULT_DESKTOP_DB_PATH)
        self.organization = organization
        self.synced_count = 0
        self.error_count = 0
        
    def is_desktop_db_available(self):
        """Check if the desktop database file exists and is readable."""
        return self.desktop_db_path.exists() and self.desktop_db_path.is_file()
    
    def get_desktop_connection(self):
        """Create a read-only connection to the desktop SQLite database."""
        if not self.is_desktop_db_available():
            raise FileNotFoundError(f"Desktop database not found: {self.desktop_db_path}")
        
        # Open in read-only mode with URI
        conn = sqlite3.connect(
            f"file:{self.desktop_db_path}?mode=ro",
            uri=True,
            timeout=10
        )
        conn.row_factory = sqlite3.Row
        return conn
    
    def get_last_sync_timestamp(self):
        """Get the timestamp of the last successful sync."""
        # Check for the most recent synced scan
        latest_scan = ScanResult.objects.filter(
            organization=self.organization
        ).order_by('-uploaded_at').first()
        
        if latest_scan:
            return latest_scan.uploaded_at
        
        # Default to 30 days ago for first sync
        return timezone.now() - timedelta(days=30)
    
    def fetch_unsynced_scans(self, since_timestamp=None):
        """
        Fetch scans from desktop database that haven't been synced yet.
        
        Args:
            since_timestamp: Only fetch scans newer than this timestamp.
        
        Returns:
            List of scan dictionaries ready for import.
        """
        if not since_timestamp:
            since_timestamp = self.get_last_sync_timestamp()
        
        try:
            conn = self.get_desktop_connection()
            cursor = conn.cursor()
            
            # Query desktop scans table
            # Note: Adjust this query based on actual desktop database schema
            query = """
                SELECT 
                    scan_id,
                    tenant_id,
                    scan_timestamp,
                    overall_score,
                    passed_count,
                    failed_count,
                    warning_count,
                    skipped_count,
                    json_report,
                    created_at
                FROM scans
                WHERE created_at > ?
                ORDER BY created_at ASC
            """
            
            cursor.execute(query, (since_timestamp.isoformat(),))
            rows = cursor.fetchall()
            
            scans = []
            for row in rows:
                scans.append({
                    'scan_id': row['scan_id'],
                    'tenant_id': row['tenant_id'],
                    'scan_timestamp': row['scan_timestamp'],
                    'score': row['overall_score'],
                    'passed_count': row['passed_count'],
                    'failed_count': row['failed_count'],
                    'warning_count': row['warning_count'],
                    'skipped_count': row['skipped_count'],
                    'json_data': json.loads(row['json_report']) if row['json_report'] else {},
                    'created_at': row['created_at'],
                })
            
            conn.close()
            logger.info(f"Found {len(scans)} unsynced scans in desktop database")
            return scans
            
        except sqlite3.Error as e:
            logger.error(f"SQLite error while fetching scans: {e}")
            raise
        except Exception as e:
            logger.error(f"Error fetching unsynced scans: {e}")
            raise
    
    @transaction.atomic
    def sync_scan(self, scan_data, user=None):
        """
        Sync a single scan from desktop to web database.
        
        Args:
            scan_data: Dictionary containing scan information.
            user: User to associate with the scan (optional).
        
        Returns:
            Created ScanResult instance or None if already exists.
        """
        # Check if scan already exists
        existing = ScanResult.objects.filter(
            scan_id=scan_data['scan_id']
        ).exists()
        
        if existing:
            logger.debug(f"Scan {scan_data['scan_id']} already synced, skipping")
            return None
        
        try:
            # Determine status based on score
            score = scan_data.get('score', 0)
            if score >= 80:
                status = 'PASS'
            elif score >= 60:
                status = 'WARNING'
            else:
                status = 'FAIL'
            
            # Create the scan result
            scan = ScanResult.objects.create(
                scan_id=scan_data['scan_id'],
                organization=self.organization,
                user=user,
                score=score,
                status=status,
                passed_count=scan_data.get('passed_count', 0),
                failed_count=scan_data.get('failed_count', 0),
                warning_count=scan_data.get('warning_count', 0),
                skipped_count=scan_data.get('skipped_count', 0),
                json_data=scan_data.get('json_data', {}),
                is_sensitive=False,  # Default to public
            )
            
            logger.info(f"Synced scan {scan.scan_id} with score {scan.score}%")
            self.synced_count += 1
            return scan
            
        except Exception as e:
            logger.error(f"Error syncing scan {scan_data.get('scan_id')}: {e}")
            self.error_count += 1
            raise
    
    def sync_all(self, user=None, since_timestamp=None):
        """
        Synchronize all unsynced scans from desktop to web portal.
        
        Args:
            user: User to associate with synced scans.
            since_timestamp: Only sync scans newer than this.
        
        Returns:
            Dictionary with sync results.
        """
        self.synced_count = 0
        self.error_count = 0
        
        if not self.is_desktop_db_available():
            logger.info(
                f"Desktop sync skipped — no local database found at: {self.desktop_db_path}\n"
                "This is normal if scanning via the Portal API upload flow. "
                "Place the desktop SQLite database at the path above to enable local sync."
            )
            return {
                'success': False,
                'message': f'Desktop database not found at {self.desktop_db_path}',
                'synced': 0,
                'errors': 0,
            }
        
        try:
            scans = self.fetch_unsynced_scans(since_timestamp)
            
            for scan_data in scans:
                try:
                    self.sync_scan(scan_data, user)
                except Exception as e:
                    logger.error(f"Failed to sync scan: {e}")
                    continue
            
            # Log the sync event
            if self.synced_count > 0:
                AuditLog.log(
                    action='DESKTOP_SYNC',
                    user=user,
                    organization=self.organization,
                    details=f'Synced {self.synced_count} scans from desktop'
                )
            
            return {
                'success': True,
                'message': f'Synced {self.synced_count} scans',
                'synced': self.synced_count,
                'errors': self.error_count,
            }
            
        except Exception as e:
            logger.error(f"Sync failed: {e}")
            return {
                'success': False,
                'message': str(e),
                'synced': self.synced_count,
                'errors': self.error_count,
            }


def sync_desktop_scans(organization_id=None, user_id=None):
    """
    Convenience function to trigger a desktop sync.
    
    Can be called from Django management commands, Celery tasks, or views.
    
    Usage:
        # From Django shell
        from core.sync_service import sync_desktop_scans
        result = sync_desktop_scans()
        print(result)
        
        # From Celery task
        @celery_app.task
        def scheduled_sync():
            return sync_desktop_scans()
    """
    organization = None
    user = None
    
    if organization_id:
        try:
            organization = Organization.objects.get(id=organization_id)
        except Organization.DoesNotExist:
            pass
    
    if user_id:
        try:
            user = User.objects.get(id=user_id)
            if not organization:
                organization = user.organization
        except User.DoesNotExist:
            pass
    
    service = DesktopSyncService(organization=organization)
    return service.sync_all(user=user)


# ============================================
# Management Command Support
# ============================================

def run_sync_command():
    """
    Entry point for management command.
    
    Create a management command at:
    web_portal/core/management/commands/sync_desktop.py
    
    from django.core.management.base import BaseCommand
    from core.sync_service import run_sync_command
    
    class Command(BaseCommand):
        help = 'Sync scans from desktop SQLite to web PostgreSQL'
        
        def handle(self, *args, **options):
            result = run_sync_command()
            self.stdout.write(self.style.SUCCESS(result['message']))
    """
    return sync_desktop_scans()
