"""
AVAGuard Desktop - Enhanced Desktop Application
Enterprise-grade compliance scanner with SRS-compliant features.
"""

import sys
import os
import sqlite3
import configparser
import logging
import uuid
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Tuple, Any, ClassVar, Type
from dataclasses import dataclass, field








# ============================================================================
# INITIALIZATION & PATHS
# ============================================================================
# print("🛡️  Initializing AVAGuard Desktop v1.0..")
# current_dir = os.path.dirname(os.path.abspath(__file__))
# project_root = os.path.dirname(current_dir)

# # Define library paths
# # CORRECT paths
# sys.path.insert(0, os.path.join(project_root, 'avaguard-core'))
# sys.path.insert(0, os.path.join(project_root, 'avaguard-cli'))

# # Add to system path for imports
# if project_root not in sys.path:
#     sys.path.insert(0, project_root)
# if core_path not in sys.path:
#     sys.path.insert(0, core_path)
# if cli_path not in sys.path:
#     sys.path.insert(0, cli_path)

# print(f"📁 Project Root: {project_root}")
# print(f"📦 Core Path: {core_path}")






    # ... error handling ...



print("🛡️  Initializing AVAGuard Desktop v1.0...")
import sys
import os

# Since we installed via pip -e, we can import directly
try:
    import avaguard_core
    from avaguard_core.reporter import EnhancedReporter as Reporter, ReportMetadata, ReportTier
    import avaguard.cli
    print("✅ AVAGuard libraries found.")
except ImportError as e:
    print(f"❌ CRITICAL ERROR: Libraries not installed. {e}")
    print("Run: pip install -e ./avaguard-core && pip install -e ./avaguard-cli")
    sys.exit(1)

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))










# ============================================================================
# SETUP LOGGING
# ============================================================================
log_dir = Path(project_root) / "logs"
log_dir.mkdir(exist_ok=True)

log_file = log_dir / f"avaguard_desktop_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logger = logging.getLogger(__name__)

# ============================================================================
# PYQT6 IMPORTS
# ============================================================================
print("📦 Importing PyQt6...")
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QTextEdit, QLabel, QProgressBar, QCheckBox,
        QTabWidget, QTableWidget, QTableWidgetItem,
        QHeaderView, QFileDialog, QLineEdit, QComboBox, QGroupBox, 
        QFormLayout, QSpinBox, QMenu, QToolBar, QStatusBar,
        QDialog, QDialogButtonBox, QListWidget, QListWidgetItem,
        QSplitter, QFrame
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QUrl
    from PyQt6.QtGui import QColor, QFont, QIcon, QPalette, QBrush, QAction, QDesktopServices
    print("✅ PyQt6 imported successfully")
except ImportError as e:
    print(f"❌ ERROR: PyQt6 not found. Install with: pip install PyQt6")
    logger.critical(f"PyQt6 import failed: {e}")
    sys.exit(1)

# ============================================================================
# CORE IMPORTS
# ============================================================================
print("📦 Importing Core Libraries...")
try:
    from avaguard_core.checks import AVAILABLE_CHECKS, FREE_TIER_CHECKS, PREMIUM_CHECKS
    from avaguard_core.checks.base_check import CheckResult, CheckStatus, CISSeverity, BaseCheck
    from avaguard_core.reporter import EnhancedReporter, ReportMetadata, ReportTier
    from avaguard_core.reporter import EnhancedReporter, ReportMetadata, ReportTier
    from avaguard_core.auth import AzureAuthenticator
    from web_client import WebPortalClient
    from workers.sync_worker import SyncWorker
    print(f"✅ Core imported. Found {len(AVAILABLE_CHECKS)} checks.")
except ImportError as e:
    print(f"❌ CORE IMPORT ERROR: {e}")
    AVAILABLE_CHECKS = {}
    FREE_TIER_CHECKS = {}
    PREMIUM_CHECKS = {}
    # Create dummy BaseCheck for type hints
    class BaseCheck: pass
    import traceback
    traceback.print_exc()
    sys.exit(1)
    sys.exit(1)

def check_internet(host="8.8.8.8", port=53, timeout=3):
    """Check for internet connectivity."""
    import socket
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error:
        return False

# ============================================================================
# ENHANCED DATABASE MANAGER (SRS-COMPLIANT)
# ============================================================================
@dataclass
class ScanMetadata:
    """SRS Table 7.1 compliant scan metadata."""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    initiated_by: str = "system"
    target_tenant: Optional[str] = None
    overall_score: float = 0.0
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    error_checks: int = 0
    warning_checks: int = 0
    tier: str = "FREE"
    environment: str = "mock"
    scope: str = "Azure CIS Benchmark v2.0"
    duration_seconds: float = 0.0
    api_calls_count: int = 0
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            'scan_id': self.scan_id,
            'timestamp': self.timestamp.isoformat(),
            'initiated_by': self.initiated_by,
            'target_tenant': self.target_tenant,
            'overall_score': self.overall_score,
            'total_checks': self.total_checks,
            'passed_checks': self.passed_checks,
            'failed_checks': self.failed_checks,
            'error_checks': self.error_checks,
            'warning_checks': self.warning_checks,
            'tier': self.tier,
            'environment': self.environment,
            'scope': self.scope,
            'duration_seconds': self.duration_seconds,
            'api_calls_count': self.api_calls_count,
            'audit_id': self.audit_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanMetadata':
        """Create from dictionary."""
        metadata = cls()
        for key, value in data.items():
            if hasattr(metadata, key):
                if key == 'timestamp' and isinstance(value, str):
                    setattr(metadata, key, datetime.fromisoformat(value.replace('Z', '')))
                else:
                    setattr(metadata, key, value)
        return metadata

class EnhancedDatabaseManager:
    """SRS-compliant database manager with enhanced features."""
    
    DB_VERSION: ClassVar[int] = 3
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
        logger.info(f"Database initialized: {db_path}")
    
    def _init_db(self):
        """Initialize database with SRS-compliant schema."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Database info table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS db_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            
            # Scan history table (SRS Table 7.1)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    scan_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    initiated_by TEXT,
                    target_tenant TEXT,
                    overall_score REAL DEFAULT 0,
                    total_checks INTEGER DEFAULT 0,
                    passed_checks INTEGER DEFAULT 0,
                    failed_checks INTEGER DEFAULT 0,
                    error_checks INTEGER DEFAULT 0,
                    warning_checks INTEGER DEFAULT 0,
                    tier TEXT,
                    environment TEXT,
                    scope TEXT,
                    duration_seconds REAL DEFAULT 0,
                    api_calls_count INTEGER DEFAULT 0,
                    audit_id TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    synced BOOLEAN DEFAULT 0
                )
            ''')
            
            # Check results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS check_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    check_id TEXT NOT NULL,
                    cis_control_id TEXT,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    compliant_count INTEGER DEFAULT 0,
                    non_compliant_count INTEGER DEFAULT 0,
                    warning_count INTEGER DEFAULT 0,
                    total_count INTEGER DEFAULT 0,
                    compliance_percentage REAL DEFAULT 0,
                    details TEXT,
                    severity TEXT,
                    category TEXT,
                    evidence TEXT,  -- JSON encoded
                    remediation TEXT,
                    error_message TEXT,
                    duration_seconds REAL DEFAULT 0,
                    api_calls_count INTEGER DEFAULT 0,
                    requires_premium BOOLEAN DEFAULT 0,
                    FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id)
                )
            ''')
            
            # Resource details table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS resource_details (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    check_result_id INTEGER,
                    resource_type TEXT,
                    resource_name TEXT,
                    resource_id TEXT,
                    status TEXT,
                    reason TEXT,
                    details TEXT,
                    FOREIGN KEY (check_result_id) REFERENCES check_results(id)
                )
            ''')
            
            # Performance metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    scan_id TEXT PRIMARY KEY,
                    total_duration REAL,
                    avg_check_duration REAL,
                    total_api_calls INTEGER,
                    memory_usage_mb REAL,
                    FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id)
                )
            ''')
            
            # Audit log table (SRS FR-29)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    user TEXT,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT
                )
            ''')
            
            # Check DB version and migrate if needed
            cursor.execute('SELECT value FROM db_info WHERE key = "version"')
            result = cursor.fetchone()
            current_version = int(result[0]) if result else 0
            
            if current_version < self.DB_VERSION:
                self._migrate_database(conn, cursor, current_version)
                cursor.execute('INSERT OR REPLACE INTO db_info (key, value) VALUES ("version", ?)', 
                             (str(self.DB_VERSION),))
            
            conn.commit()
            conn.close()
            
            logger.info("Database schema initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def _migrate_database(self, conn: sqlite3.Connection, cursor: sqlite3.Cursor, from_version: int):
        """Migrate database schema."""
        logger.info(f"Migrating database from version {from_version} to {self.DB_VERSION}")
        
        if from_version == 0:
            # Initial version, nothing to migrate
            pass
        elif from_version == 1:
            # Add new columns if needed
            try:
                cursor.execute('ALTER TABLE scan_history ADD COLUMN warning_checks INTEGER DEFAULT 0')
                cursor.execute('ALTER TABLE scan_history ADD COLUMN audit_id TEXT')
                cursor.execute('ALTER TABLE check_results ADD COLUMN warning_count INTEGER DEFAULT 0')
            except sqlite3.OperationalError:
                # Columns might already exist
                pass
        
        elif from_version == 2:
            # Upgrade to v3 (Sync support)
            try:
                cursor.execute('ALTER TABLE scan_history ADD COLUMN synced BOOLEAN DEFAULT 0')
            except sqlite3.OperationalError:
                pass
        
        conn.commit()
        logger.info("Database migration completed")
    
    def save_scan(self, metadata: ScanMetadata, results: List[CheckResult]) -> str:
        """Save complete scan with metadata and results."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Save scan metadata
            metadata_dict = metadata.to_dict()
            cursor.execute('''
                INSERT OR REPLACE INTO scan_history 
                (scan_id, timestamp, initiated_by, target_tenant, overall_score, 
                 total_checks, passed_checks, failed_checks, error_checks, warning_checks,
                 tier, environment, scope, duration_seconds, api_calls_count, audit_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metadata.scan_id,
                metadata.timestamp.isoformat(),
                metadata.initiated_by,
                metadata.target_tenant,
                metadata.overall_score,
                metadata.total_checks,
                metadata.passed_checks,
                metadata.failed_checks,
                metadata.error_checks,
                metadata.warning_checks,
                metadata.tier,
                metadata.environment,
                metadata.scope,
                metadata.duration_seconds,
                metadata.api_calls_count,
                metadata.audit_id
            ))
            
            # Save check results
            for result in results:
                cursor.execute('''
                    INSERT INTO check_results 
                    (scan_id, check_id, cis_control_id, title, status, 
                     compliant_count, non_compliant_count, warning_count, total_count,
                     compliance_percentage, details, severity, category, 
                     evidence, remediation, error_message, duration_seconds, 
                     api_calls_count, requires_premium)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metadata.scan_id,
                    result.check_id,
                    getattr(result, 'cis_control_id', result.check_id),
                    result.title,
                    result.status.value if hasattr(result.status, 'value') else str(result.status),
                    result.compliant_count,
                    result.non_compliant_count,
                    getattr(result, 'warning_count', 0),
                    result.total_count,
                    result.compliance_percentage,
                    result.details,
                    getattr(result, 'cis_severity', CISSeverity.MEDIUM).value,
                    getattr(result, 'category', ''),
                    json.dumps(getattr(result, 'evidence', {})),
                    getattr(result, 'remediation', ''),
                    getattr(result, 'error_message', ''),
                    getattr(result, 'duration_seconds', 0.0),
                    getattr(result, 'api_calls_count', 0),
                    getattr(result, 'requires_premium', False)
                ))
                
                check_result_id = cursor.lastrowid
                
                # Save resource details
                for resource in result.non_compliant_resources:
                    cursor.execute('''
                        INSERT INTO resource_details 
                        (check_result_id, resource_type, resource_name, resource_id, status, reason, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        check_result_id,
                        resource.get('type', 'unknown'),
                        resource.get('name', 'unknown'),
                        resource.get('id', ''),
                        'non_compliant',
                        resource.get('reason', ''),
                        json.dumps(resource)
                    ))
                
                for resource in getattr(result, 'compliant_resources', []):
                    cursor.execute('''
                        INSERT INTO resource_details 
                        (check_result_id, resource_type, resource_name, resource_id, status, reason, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        check_result_id,
                        resource.get('type', 'unknown'),
                        resource.get('name', 'unknown'),
                        resource.get('id', ''),
                        'compliant',
                        '',
                        json.dumps(resource)
                    ))
            
            conn.commit()
            logger.info(f"Scan saved: {metadata.scan_id}")
            
            # Log audit trail
            self._log_audit(
                action="scan_completed",
                user=metadata.initiated_by,
                details=f"Scan completed: {metadata.scan_id} - Score: {metadata.overall_score}%"
            )
            
            return metadata.scan_id
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to save scan: {e}")
            raise
        finally:
            conn.close()
    
    def get_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve scan history."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM scan_history 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            scans = [dict(row) for row in rows]
            conn.close()
            
            return scans
        except Exception as e:
            logger.error(f"Failed to retrieve scans: {e}")
            return []
    
    def get_scan_details(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed scan results."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get scan metadata
            cursor.execute('SELECT * FROM scan_history WHERE scan_id = ?', (scan_id,))
            scan_row = cursor.fetchone()
            
            if not scan_row:
                return None
            
            scan_data = dict(scan_row)
            
            # Get check results
            cursor.execute('''
                SELECT * FROM check_results 
                WHERE scan_id = ? 
                ORDER BY check_id
            ''', (scan_id,))
            
            check_rows = cursor.fetchall()
            scan_data['checks'] = [dict(row) for row in check_rows]
            
            # Get resource counts
            cursor.execute('''
                SELECT cr.check_id, rd.status, COUNT(*) as count
                FROM check_results cr
                LEFT JOIN resource_details rd ON cr.id = rd.check_result_id
                WHERE cr.scan_id = ?
                GROUP BY cr.check_id, rd.status
            ''', (scan_id,))
            
            resource_stats = cursor.fetchall()
            scan_data['resource_stats'] = [dict(row) for row in resource_stats]
            
            conn.close()
            return scan_data
            
        except Exception as e:
            logger.error(f"Failed to retrieve scan details: {e}")
            return None
    
    def _log_audit(self, action: str, user: str = "system", details: str = "",
                  ip_address: str = "", user_agent: str = ""):
        """Log audit trail entry (SRS FR-29)."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO audit_log 
                (timestamp, action, user, details, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                action,
                user,
                details,
                ip_address,
                user_agent
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to log audit: {e}")
    
    def export_scan(self, scan_id: str, export_path: str) -> bool:
        """Export scan to JSON format."""
        try:
            scan_data = self.get_scan_details(scan_id)
            if not scan_data:
                return False
            
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(scan_data, f, indent=2, default=str)
            
            self._log_audit(
                action="scan_exported",
                details=f"Scan exported: {scan_id} to {export_path}"
            )
            
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            logger.error(f"Export failed: {e}")
            return False

    def get_unsynced_scans(self) -> List[Dict[str, Any]]:
        """Get list of unsynced scans."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM scan_history WHERE synced = 0')
            rows = cursor.fetchall()
            
            scans = [dict(row) for row in rows]
            conn.close()
            return scans
        except Exception as e:
            logger.error(f"Failed to get unsynced scans: {e}")
            return []

    def mark_as_synced(self, scan_id: str):
        """Mark a scan as synced."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('UPDATE scan_history SET synced = 1 WHERE scan_id = ?', (scan_id,))
            conn.commit()
            conn.close()
            logger.info(f"Marked scan {scan_id} as synced")
        except Exception as e:
            logger.error(f"Failed to mark scan synced: {e}")

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_scans,
                    AVG(overall_score) as avg_score,
                    MAX(overall_score) as best_score,
                    MIN(overall_score) as worst_score,
                    SUM(passed_checks) as total_passed,
                    SUM(failed_checks) as total_failed
                FROM scan_history
            ''')
            
            row = cursor.fetchone()
            stats = dict(row) if row else {}
            
            # Get recent trend
            cursor.execute('''
                SELECT overall_score, timestamp 
                FROM scan_history 
                ORDER BY timestamp DESC 
                LIMIT 10
            ''')
            
            trend_rows = cursor.fetchall()
            stats['recent_scores'] = [dict(r) for r in trend_rows]
            
            conn.close()
            return stats
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}

