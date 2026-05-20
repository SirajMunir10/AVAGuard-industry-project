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
from utils.session_manager import GlobalSessionManager
from utils.themed_dialog import AVADialog








# ============================================================================
# INITIALIZATION & PATHS
# ============================================================================
# print(" Initializing AVAGuard Desktop v1.0..")
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



print(" Initializing AVAGuard Desktop v1.0...")
import sys
import os

# Since we installed via pip -e, we can import directly
try:
    import avaguard_core
    from avaguard_core.reporter import EnhancedReporter as Reporter, ReportMetadata, ReportTier
    import avaguard.cli
    print("AVAGuard libraries found.")
except ImportError as e:
    print(f"CRITICAL ERROR: Libraries not installed. {e}")
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
        QMessageBox, QTabWidget, QTableWidget, QTableWidgetItem,
        QHeaderView, QFileDialog, QLineEdit, QComboBox, QGroupBox, 
        QFormLayout, QSpinBox, QMenu, QToolBar, QStatusBar,
        QDialog, QDialogButtonBox, QListWidget, QListWidgetItem,
        QSplitter, QFrame
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QUrl
    from PyQt6.QtGui import QColor, QFont, QIcon, QPalette, QBrush, QAction, QDesktopServices
    print("PyQt6 imported successfully")
except ImportError as e:
    print(f"ERROR: PyQt6 not found. Install with: pip install PyQt6")
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
    print(f"Core imported. Found {len(AVAILABLE_CHECKS)} checks.")
except ImportError as e:
    print(f"CORE IMPORT ERROR: {e}")
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
from models.database import ScanMetadata, EnhancedDatabaseManager
from workers.enhanced_worker import EnhancedScanWorker
import ui.login_dialog

class EnhancedMainWindow(QMainWindow):
    """Enhanced main window with SRS-compliant features."""
    
    def __init__(self, portal_url: str = 'http://localhost:8000', parent=None):
        super().__init__(parent)
        self.setWindowTitle("AVAGuard Desktop - Azure Compliance Scanner")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize components
        self.scan_results: List[CheckResult] = []
        self.worker: Optional[EnhancedScanWorker] = None
        self.current_scan_metadata: Optional[ScanMetadata] = None
        self.portal_url = portal_url
        self.web_client: Optional[WebPortalClient] = None
        self.access_token: Optional[str] = None
        
        # Device token for portal authorization
        self.device_token: str = 'auth_' + uuid.uuid4().hex[:12] + '_' + uuid.uuid4().hex[:8]
        
        # Database (Resolved to project root)
        repo_root = os.path.dirname(project_root)
        self.db_path = os.path.join(repo_root, 'avaguard_enterprise.db')
        self.db = EnhancedDatabaseManager(self.db_path)
        
        # Configuration
        self.config_path = os.path.join(project_root, 'config.ini')
        
        # UI State
        self.dark_mode = False
        
        # Initialize UI
        self._setup_ui()
        self._load_settings()
        self._refresh_history()
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        # Reset global session state on fresh login
        GlobalSessionManager().reset()
        logger.info("GlobalSessionManager reset on fresh app start")

        self._revocation_in_progress = False
        # QA Diagnostic Output
        logger.info("""
        ============= QA DIAGNOSTIC =============
        Config Path: {self.config_path}
        Active Dataset: [Lazy loaded by worker]
        Heartbeat Interval: 10000ms
        Session State: INITIALIZING
        =========================================""".format(self=self))
        logger.info("Enhanced AVAGuard Desktop started")

        # Auto-sync after 3 seconds — delayed to allow session validation first
        QTimer.singleShot(3000, self._sync_scans)
    
    def _setup_ui(self):
        """Setup the enhanced user interface."""
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Header
        # Get path to assets securely
        import os
        asset_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'assets')
        shield_path = os.path.join(asset_dir, 'shield.svg').replace('\\', '/')
        
        header = QLabel(f"<img src='{shield_path}' width='24' height='24' style='vertical-align: middle;'> AVAGuard - Azure CIS Compliance Scanner")
        header.setStyleSheet("""
            font-size: 24px; 
            font-weight: bold; 
            color: #1e40af;
            padding: 10px;
            border-bottom: 2px solid #3b82f6;
        """)
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(header)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self._create_dashboard_tab()
        self._create_scan_tab()
        self._create_results_tab()
        self._create_history_tab()
        self._create_settings_tab()
        
        main_layout.addWidget(self.tab_widget)
        
        # Setup menu bar
        self._setup_menu_bar()
        
        # Setup toolbar
        self._setup_toolbar()
    
    def _setup_menu_bar(self):
        """Setup the application menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_scan_action = QAction("New Scan", self)
        new_scan_action.triggered.connect(self._start_scan)
        file_menu.addAction(new_scan_action)
        
        export_action = QAction("Export Results", self)
        export_action.triggered.connect(self._export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu("View")
        
        toggle_dark_action = QAction("Toggle Dark Mode", self)
        toggle_dark_action.triggered.connect(self._toggle_dark_mode)
        view_menu.addAction(toggle_dark_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(lambda: self.tab_widget.setCurrentIndex(4))
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
    def _setup_toolbar(self):
        """Setup the main toolbar."""
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        
        # Scan button
        self.scan_action = QAction("Start Scan", self)
        self.scan_action.triggered.connect(self._start_scan)
        toolbar.addAction(self.scan_action)
        
        # Stop button
        self.stop_action = QAction("Stop", self)
        self.stop_action.triggered.connect(self._stop_scan)
        self.stop_action.setEnabled(False)
        toolbar.addAction(self.stop_action)
        
        toolbar.addSeparator()
        
        # Export button
        self.export_action = QAction("⬇ Export", self)
        self.export_action.triggered.connect(self._export_results)
        self.export_action.setEnabled(False)
        toolbar.addAction(self.export_action)
        
        # Refresh button
        refresh_action = QAction("🔄 Refresh", self)
        refresh_action.triggered.connect(self._refresh_history)
        toolbar.addAction(refresh_action)

        toolbar.addSeparator()

        # IMPACT: Sync Button (Requested Feature)
        sync_action = QAction("☁ Sync Now", self)
        sync_action.triggered.connect(self._sync_scans)
        toolbar.addAction(sync_action)

        # IMPACT: Open Web Portal (Requested Feature)
        portal_action = QAction("🌐 Open Web Portal", self)
        portal_action.triggered.connect(self._open_web_portal)
        toolbar.addAction(portal_action)
    
    def _open_web_portal(self):
        """Open the web portal device authorization page with the device token.
        
        If the user is already logged in, Django redirects straight to the
        device approval page.  If not, @login_required redirects to login
        with ?next=/auth/authorize-device/?token=… so the full chain
        (login → MFA → authorize) is preserved automatically.
        """
        # Generate a fresh token each time so expired ones are not reused
        self.device_token = 'auth_' + uuid.uuid4().hex[:12] + '_' + uuid.uuid4().hex[:8]
        
        auth_url = f"{self.portal_url}/auth/authorize-device/?token={self.device_token}"
        
        if AVADialog.confirm(
            "Connect to Web Portal",
            "This will open the web portal to authorize this device.\n"
            "If you are not logged in, you will be prompted to log in first.\n\n"
            "Proceed?",
            confirm_label="Proceed", cancel_label="Cancel",
            parent=self
        ):
            QDesktopServices.openUrl(QUrl(auth_url))
            self.statusBar().showMessage(f"Device token: {self.device_token[:16]}… — waiting for approval")
            
    def _sync_scans(self):
        """Sync unsynced scans to web portal (background worker)."""

        # ── Guard 1: Do not sync if revoked ──────────────────────────────────
        if GlobalSessionManager().is_revoked():
            logger.info("Sync skipped: session already revoked before sync start.")
            return

        # ── Guard 2: Network check ───────────────────────────────────────────
        if not check_internet():
            self.statusBar().showMessage("Sync skipped: no internet connection")
            return

        # ── Guard 3: Build/verify web client ─────────────────────────────────
        if not self.web_client:
            self.web_client = WebPortalClient(self.portal_url)
            if hasattr(self, 'access_token') and self.access_token:
                from web_client import AuthToken
                from datetime import datetime, timedelta
                self.web_client._token = AuthToken(
                    access_token=self.access_token,
                    refresh_token="",
                    expires_at=datetime.now() + timedelta(hours=1),
                    user_email=self.user_data.get('email', '') if hasattr(self, 'user_data') else '',
                    user_role=self.user_role if hasattr(self, 'user_role') else 'VIEWER',
                    organization_id=str(self.user_data.get('organization', 0)) if hasattr(self, 'user_data') else '0'
                )

        if not self.web_client.is_authenticated:
            self.statusBar().showMessage("Sync skipped: not authenticated")
            return

        # ── Guard 4: Startup session validation ──────────────────────────────
        # Before touching the queue, confirm the server considers this session valid.
        # NOTE: This is a SOFT check — startup 403 means we skip sync this cycle.
        # The heartbeat (every 10s) is the ONLY authority for hard shutdown.
        try:
            from web_client import SessionRevokedException
            self.statusBar().showMessage("Validating session before sync...")
            valid = self.web_client.validate_session()
            if not valid:
                logger.warning("Startup session validation returned False — skipping sync this cycle.")
                self.statusBar().showMessage("Sync skipped: session validation failed (will retry on next heartbeat)")
                return
        except SessionRevokedException as e:
            # Portal returned 403 'revoked' on the scan-list probe.
            # This can happen when the SERVER-SIDE session record is stale.
            # Do NOT hard-shutdown — that is the heartbeat's job.
            # Just skip sync for this cycle and let the heartbeat confirm.
            logger.warning(f"Startup sync validation got revocation response: {e}. "
                           f"Skipping sync — heartbeat will confirm within 10s.")
            self.statusBar().showMessage("Sync skipped: server session state pending (checking via heartbeat)")
            return
        except Exception as ex:
            logger.warning(f"Startup session validation failed with network error: {ex} — continuing optimistically")

        # ── Guard 5: Load queue ───────────────────────────────────────────────
        unsynced = self.db.get_unsynced_scans()
        if not unsynced:
            self.statusBar().showMessage("All scans synced")
            return

        logger.info(f"Starting sync of {len(unsynced)} unsynced scan(s)")
        self.statusBar().showMessage(f"Syncing {len(unsynced)} scan(s)...")

        # ── Create and start worker ───────────────────────────────────────────
        self.sync_worker = SyncWorker(self.db, self.web_client, unsynced)
        self.sync_worker.progress.connect(self._on_sync_progress)
        self.sync_worker.finished.connect(self._on_sync_finished)
        self.sync_worker.session_revoked.connect(self.handle_session_revoked)
        self.sync_worker.start()

    def _on_sync_progress(self, current, total, status):
        """Update progress on sync."""
        self.statusBar().showMessage(f"Syncing: {current}/{total} - {status}")

    def _on_sync_finished(self, synced_count, failed_count, errors):
        """Handle sync completion."""
        if GlobalSessionManager().is_revoked():
            return

        self._refresh_history()
        logger.info(f"Sync completed: {synced_count} synced, {failed_count} failed")

        if failed_count > 0:
            self.statusBar().showMessage(f"Sync: {synced_count} OK, {failed_count} failed")
            AVADialog.sync_failed(failed_count, errors, parent=self).exec()
        else:
            self.statusBar().showMessage(f"Sync successful: {synced_count} scan(s) uploaded")
    
    def _create_dashboard_tab(self):
        """Create the dashboard tab."""
        dashboard_widget = QWidget()
        layout = QVBoxLayout(dashboard_widget)
        
        # Welcome message
        welcome_label = QLabel("Welcome to AVAGuard Desktop")
        welcome_label.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        layout.addWidget(welcome_label)
        
        # Quick stats
        stats_group = QGroupBox("Quick Statistics")
        stats_layout = QHBoxLayout()
        
        self.total_scans_label = QLabel("Total Scans: 0")
        self.last_scan_label = QLabel("Last Scan: Never")
        self.avg_score_label = QLabel("Average Score: 0%")
        
        for label in [self.total_scans_label, self.last_scan_label, self.avg_score_label]:
            label.setStyleSheet("font-size: 14px; padding: 10px;")
            stats_layout.addWidget(label)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Recent scans table
        recent_label = QLabel("Recent Scans")
        recent_label.setStyleSheet("font-weight: bold; margin-top: 20px;")
        layout.addWidget(recent_label)
        
        self.recent_table = QTableWidget(5, 4)
        self.recent_table.setHorizontalHeaderLabels(["Date", "Score", "Passed", "Failed"])
        self.recent_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.recent_table)
        
        layout.addStretch()
        self.tab_widget.addTab(dashboard_widget, "Dashboard")
    


    def _create_scan_tab(self):
        """Create the scan configuration tab."""
        scan_widget = QWidget()
        layout = QVBoxLayout(scan_widget)
        
        # Scan configuration group
        config_group = QGroupBox("Scan Configuration")
        config_layout = QFormLayout()
        
        # Mode selection
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Mock Data", "Live Azure"])
        config_layout.addRow("Scan Mode:", self.mode_combo)
        
        # Tier selection
        self.tier_combo = QComboBox()
        self.tier_combo.addItems(["FREE", "PREMIUM"])
        self.tier_combo.currentTextChanged.connect(self._on_tier_changed)
        config_layout.addRow("License Tier:", self.tier_combo)
        
        # Check selection
        self.checks_list = QListWidget()
        
        # Build check_id → class mapping for both dict and list formats
        if isinstance(AVAILABLE_CHECKS, dict):
            checks_items = list(AVAILABLE_CHECKS.items())  # [(id, class), ...]
            premium_ids = set(PREMIUM_CHECKS.keys()) if isinstance(PREMIUM_CHECKS, dict) else set()
        else:
            checks_items = [(getattr(c, 'CHECK_ID', c.__name__), c) for c in AVAILABLE_CHECKS]
            premium_ids = set()

        for check_id, check_class in checks_items:
            title = getattr(check_class, 'TITLE', check_class.__name__)

            asset_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'assets')
            # Label with tier indicator
            if check_id in premium_ids:
                display_title = f"{title}"
                icon = QIcon(os.path.join(asset_dir, 'premium.svg'))
            else:
                display_title = f"{title}"
                icon = QIcon(os.path.join(asset_dir, 'free.svg'))
            
            item = QListWidgetItem(icon, display_title)
            
            # Store check_id as UserRole data for scan filtering
            item.setData(Qt.ItemDataRole.UserRole, check_id)
            # Store check_class in UserRole+1 for reference
            item.setData(Qt.ItemDataRole.UserRole + 1, check_class)
            
            item.setCheckState(Qt.CheckState.Checked)
            self.checks_list.addItem(item)
        
        config_layout.addRow("Select Checks:", self.checks_list)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Apply initial tier filter
        self._on_tier_changed(self.tier_combo.currentText())
        
        # Progress section
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_label = QLabel("Ready to scan")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_label)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Button row
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self._start_scan)
        self.start_button.setStyleSheet("background-color: #3b82f6; color: white; font-weight: bold; padding: 10px;")
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self._stop_scan)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("background-color: #ef4444; color: white; font-weight: bold; padding: 10px;")
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        self.tab_widget.addTab(scan_widget, "Scan")



    
    def _create_results_tab(self):
        """Create the results tab."""
        results_widget = QWidget()
        layout = QVBoxLayout(results_widget)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Status", "CIS ID", "Control", "Compliance", "Severity", "Duration"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.results_table)
        
        # Details panel (collapsible)
        self.details_group = QGroupBox("Details")
        self.details_group.setCheckable(True)
        self.details_group.setChecked(False)
        details_layout = QVBoxLayout()
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
        self.details_group.setLayout(details_layout)
        layout.addWidget(self.details_group)

        # FIX: Connect the signal ONLY ONCE here
        self.results_table.cellClicked.connect(self._show_result_details)
        
        self.tab_widget.addTab(results_widget, "Results")
    
    def _create_history_tab(self):
        """Create the history/audit tab."""
        history_widget = QWidget()
        layout = QVBoxLayout(history_widget)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        self.history_filter_combo = QComboBox()
        self.history_filter_combo.addItems(["All", "Last Week", "Last Month", "Last Year"])
        filter_layout.addWidget(QLabel("Filter:"))
        filter_layout.addWidget(self.history_filter_combo)
        filter_layout.addStretch()
        
        layout.addLayout(filter_layout)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(8)
        self.history_table.setHorizontalHeaderLabels([
            "Scan ID", "Date", "Mode", "Tier", "Total", "Passed", "Failed", "Score"
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.history_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self._show_history_context_menu)
        
        layout.addWidget(self.history_table)
        
        self.tab_widget.addTab(history_widget, "History")
    
    def _create_settings_tab(self):
        """Create the settings tab."""
        settings_widget = QWidget()
        layout = QVBoxLayout(settings_widget)
        
        # Settings in tabs
        settings_tabs = QTabWidget()
        
        # General settings
        general_widget = QWidget()
        general_layout = QFormLayout(general_widget)
        
        self.settings_user = QLineEdit()
        general_layout.addRow("User Name:", self.settings_user)
        
        self.settings_auto_save = QCheckBox("Auto-save results")
        general_layout.addRow(self.settings_auto_save)
        
        self.settings_notifications = QCheckBox("Enable notifications")
        general_layout.addRow(self.settings_notifications)
        
        # Mock Dataset File Picker
        mock_file_layout = QHBoxLayout()
        self.settings_mock_file = QLineEdit()
        self.settings_mock_file.setReadOnly(True)
        # self.settings_mock_file.setPlaceholderText("AVAMockData.json (default)")
        self.settings_mock_file.setPlaceholderText("mock_data/enterprise_dataset.json (default)")
        mock_browse_btn = QPushButton("Browse…")
        mock_browse_btn.clicked.connect(self._browse_mock_file)
        mock_file_layout.addWidget(self.settings_mock_file)
        mock_file_layout.addWidget(mock_browse_btn)
        mock_file_widget = QWidget()
        mock_file_widget.setLayout(mock_file_layout)
        general_layout.addRow("Mock Dataset File:", mock_file_widget)
        
        # Portal URL
        self.settings_portal_url = QLineEdit()
        self.settings_portal_url.setPlaceholderText("e.g. http://localhost:8000")
        self.settings_portal_url.setText(self.portal_url)
        general_layout.addRow("Web Portal URL:", self.settings_portal_url)
        
        settings_tabs.addTab(general_widget, "General")
        
        # Azure settings
        azure_widget = QWidget()
        azure_layout = QFormLayout(azure_widget)
        
        self.settings_tenant_id = QLineEdit()
        azure_layout.addRow("Tenant ID:", self.settings_tenant_id)
        
        self.settings_client_id = QLineEdit()
        azure_layout.addRow("Client ID:", self.settings_client_id)
        
        self.settings_client_secret = QLineEdit()
        self.settings_client_secret.setEchoMode(QLineEdit.EchoMode.Password)
        azure_layout.addRow("Client Secret:", self.settings_client_secret)
        
        settings_tabs.addTab(azure_widget, "Azure")
        
        # Check settings
        checks_widget = QWidget()
        checks_layout = QFormLayout(checks_widget)
        
        self.settings_inactivity_days = QSpinBox()
        self.settings_inactivity_days.setRange(1, 365)
        checks_layout.addRow("Inactivity Days:", self.settings_inactivity_days)
        
        self.settings_exclude_guests = QCheckBox("Exclude guest users")
        checks_layout.addRow(self.settings_exclude_guests)
        
        settings_tabs.addTab(checks_widget, "Checks")
        
        layout.addWidget(settings_tabs)
        
        # Save button
        save_button = QPushButton("💾 Save Settings")
        save_button.clicked.connect(self._save_settings)
        layout.addWidget(save_button, alignment=Qt.AlignmentFlag.AlignRight)
        
        layout.addStretch()
        self.tab_widget.addTab(settings_widget, "Settings")

    
    def _start_scan(self):
        """Start a compliance scan with selective check execution."""
        if self.worker and self.worker.isRunning():
            AVADialog.alert("Scan Running", "A scan is already in progress. Please wait for it to complete.", kind="warning", parent=self).exec()
            return
        
        # ── Collect only CHECKED items from the checks list ──
        enabled_check_ids = []
        for i in range(self.checks_list.count()):
            item = self.checks_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                check_id = item.data(Qt.ItemDataRole.UserRole)
                if check_id:
                    enabled_check_ids.append(check_id)
        
        if not enabled_check_ids:
            AVADialog.alert("No Checks Selected", "No scan checks selected. Please select at least one check.", kind="warning", parent=self).exec()
            return
        
        # Validate mock data file exists when in mock mode
        use_mock = self.mode_combo.currentText() == "Mock Data"
        if use_mock:
            mock_file = self.settings_mock_file.text().strip()
            if mock_file and not os.path.exists(mock_file):
                AVADialog.alert(
                    "Mock File Not Found",
                    f"The selected mock dataset file does not exist:\n{mock_file}\n\n"
                    "Please update the path in Settings → General.",
                    kind="warning", parent=self
                ).exec()
                return
        
        # Reset UI
        self.scan_results.clear()
        self.results_table.setRowCount(0)
        self.details_text.clear()
        self.progress_bar.setValue(0)
        total_selected = len(enabled_check_ids)
        skipped = self.checks_list.count() - total_selected
        self.progress_label.setText(f"Initializing… ({total_selected} checks selected, {skipped} skipped)")
        
        # Get configuration from UI
        tier_selection = self.tier_combo.currentText()  # "FREE" or "PREMIUM"
        
        # Write the enabled_checks list into config so the worker can read it
        config = configparser.ConfigParser()
        config.read(self.config_path)
        if 'Checks' not in config:
            config['Checks'] = {}
        config['Checks']['enabled_checks'] = ','.join(enabled_check_ids)
        
        # Persist mock file path too
        mock_path = self.settings_mock_file.text().strip()
        if mock_path:
            if 'General' not in config:
                config['General'] = {}
            config['General']['mock_data_file'] = mock_path
        
        with open(self.config_path, 'w') as f:
            config.write(f)
        
        self.worker = EnhancedScanWorker(
            use_mock=use_mock,
            config_path=self.config_path,
            tier=tier_selection,
            portal_url=self.portal_url,
            access_token=self.access_token
        )
        
        # Connect signals
        self.worker.log_message.connect(self._handle_log_message)
        self.worker.check_completed.connect(self._handle_check_completed)
        self.worker.scan_progress.connect(self._handle_scan_progress)
        self.worker.scan_finished.connect(self._handle_scan_finished)
        self.worker.performance_metrics.connect(self._handle_performance_metrics)
        self.worker.session_revoked.connect(self.handle_session_revoked)
        
        # Update UI state
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.scan_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        self.export_action.setEnabled(False)
        
        # Start worker
        self.worker.start()
        
        self.statusBar().showMessage(f"Scan started: {'Mock' if use_mock else 'Live'} mode — {total_selected} checks")
        logger.info(f"Scan started: mode={'mock' if use_mock else 'live'}, tier={tier_selection}, checks={enabled_check_ids}")



    
    def _stop_scan(self):
        """Stop the current scan."""
        if self.worker and self.worker.isRunning():
            if AVADialog.confirm(
                "Stop Scan",
                "Are you sure you want to cancel the current scan?",
                confirm_label="Stop Scan", cancel_label="Keep Running",
                danger=True, parent=self
            ):
                self.worker.stop()
                self.statusBar().showMessage("Scan stopping...")
    
    def _handle_log_message(self, message: str, level: str):
        """Handle log messages from worker."""
        colors = {
            "info": "#ffffff",
            "success": "#10b981",
            "warning": "#f59e0b",
            "error": "#ef4444"
        }
        
        color = colors.get(level, "#ffffff")
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Update status bar for important messages
        if level in ["error", "warning"]:
            self.statusBar().showMessage(message, 5000)
        
        # Log to file
        if level == "error":
            logger.error(message)
        elif level == "warning":
            logger.warning(message)
        else:
            logger.info(message)
    
    def _handle_check_completed(self, result: CheckResult):
        """Handle completed check results."""
        self.scan_results.append(result)
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Determine row colors
        if result.status == CheckStatus.PASS:
            bg_color = QColor("#dcfce7")
            fg_color = QColor("#166534")
        elif result.status == CheckStatus.FAIL:
            bg_color = QColor("#fee2e2")
            fg_color = QColor("#991b1b")
        elif result.status == CheckStatus.WARNING:
            bg_color = QColor("#fef3c7")
            fg_color = QColor("#92400e")
        else:
            bg_color = QColor("#e5e7eb")
            fg_color = QColor("#4b5563")

        # Status
        status_item = QTableWidgetItem(result.status.value)
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # CIS ID
        cis_id = getattr(result, 'cis_control_id', result.check_id)
        cis_item = QTableWidgetItem(cis_id)
        
        # Title
        title_item = QTableWidgetItem(result.title)
        
        # Compliance
        compliance = f"{result.compliant_count}/{result.total_count}"
        compliance_item = QTableWidgetItem(compliance)
        compliance_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Severity
        severity = getattr(result, 'cis_severity', CISSeverity.MEDIUM).value
        severity_item = QTableWidgetItem(severity)
        severity_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Duration
        duration = getattr(result, 'duration_seconds', 0.0)
        duration_item = QTableWidgetItem(f"{duration:.2f}s")
        duration_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Apply colors
        for item in [status_item, cis_item, title_item, compliance_item, severity_item, duration_item]:
            item.setBackground(bg_color)
            item.setForeground(fg_color)
        
        # Set items
        self.results_table.setItem(row, 0, status_item)
        self.results_table.setItem(row, 1, cis_item)
        self.results_table.setItem(row, 2, title_item)
        self.results_table.setItem(row, 3, compliance_item)
        self.results_table.setItem(row, 4, severity_item)
        self.results_table.setItem(row, 5, duration_item)
        
        # Connect row selection to details display
        # self.results_table.itemClicked.connect(lambda item, r=row: self._show_result_details(r))
    
    def _handle_scan_progress(self, percent: int, status: str):
        """Handle scan progress updates."""
        self.progress_bar.setValue(percent)
        self.progress_label.setText(status)
    
    def _handle_scan_finished(self, success: bool, metadata: ScanMetadata, results: List[CheckResult]):
        """Handle scan completion."""
        if GlobalSessionManager().is_revoked():
            return
            
        # Update UI state
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.scan_action.setEnabled(True)
        self.stop_action.setEnabled(False)
        self.export_action.setEnabled(True)
        
        if success:
            self.current_scan_metadata = metadata
            
            # Save to database
            try:
                scan_id = self.db.save_scan(metadata, results)
                self.statusBar().showMessage(f"Scan completed and saved (ID: {scan_id})", 5000)
                logger.info(f"Scan saved to database: {scan_id}")
                
                # Refresh history
                self._refresh_history()
                self._update_dashboard()
                
            except Exception as e:
                logger.error(f"Failed to save scan: {e}")
                self.statusBar().showMessage("Scan completed but save failed", 5000)
            
            # Show themed completion dialog
            msg = (
                f"Compliance scan completed successfully.\n\n"
                f"  Checks run:  {metadata.total_checks}\n"
                f"  Passed:      {metadata.passed_checks}\n"
                f"  Failed:      {metadata.failed_checks}\n"
                f"  Score:       {metadata.overall_score:.1f}%\n"
                f"  Duration:    {metadata.duration_seconds:.1f}s"
            )
            AVADialog.alert("Scan Complete", msg, kind="success", parent=self).exec()

            # Switch to results tab
            self.tab_widget.setCurrentIndex(2)

        else:
            self.statusBar().showMessage("Scan failed", 5000)
            AVADialog.alert(
                "Scan Failed",
                "The scan encountered errors during execution.\n"
                "Please check the Scan Log tab for details.",
                kind="error", parent=self
            ).exec()
    
    def _handle_performance_metrics(self, metrics: Dict[str, Any]):
        """Handle performance metrics."""
        logger.info(f"Performance metrics: {metrics}")
        # Could display these in a performance panel
    
    def _show_result_details(self, row, column=None):
        """Show details for a specific result."""
        if row < len(self.scan_results):
            result = self.scan_results[row]
            
            # Adaptive Theme Variables
            bg_main = "#f8fafc" if not self.dark_mode else "#1e293b"
            text_main = "#1e293b" if not self.dark_mode else "#f8fafc"
            bg_card = "#ffffff" if not self.dark_mode else "#334155"
            border_color = "#e2e8f0" if not self.dark_mode else "#475569"
            text_muted = "#64748b" if not self.dark_mode else "#94a3b8"
            
            # Status specific colors
            status_color = "#166534" if result.status == CheckStatus.PASS else "#991b1b" if result.status == CheckStatus.FAIL else "#92400e" if result.status == CheckStatus.WARNING else text_muted
            status_bg = "#dcfce7" if result.status == CheckStatus.PASS else "#fee2e2" if result.status == CheckStatus.FAIL else "#fef3c7" if result.status == CheckStatus.WARNING else border_color
            
            if self.dark_mode:
                status_color = "#4ade80" if result.status == CheckStatus.PASS else "#f87171" if result.status == CheckStatus.FAIL else "#fbbf24" if result.status == CheckStatus.WARNING else text_muted
                status_bg = "#14532d" if result.status == CheckStatus.PASS else "#7f1d1d" if result.status == CheckStatus.FAIL else "#78350f" if result.status == CheckStatus.WARNING else border_color
            
            details_html = result.details.replace('\n', '<br>')
            
            details_text = f"""
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 5px; color: {text_main};">
                <h2 style="color: {text_main}; border-bottom: 2px solid {border_color}; padding-bottom: 8px; margin-bottom: 15px; font-weight: 600;">
                    {result.check_id}: {result.title}
                </h2>
                
                <table width="100%" cellspacing="0" cellpadding="10" style="background-color: {bg_main}; border: 1px solid {border_color}; border-radius: 8px; margin-bottom: 25px; color: {text_main};">
                    <tr>
                        <td width="20%" style="color: {text_muted}; font-weight: bold; border-bottom: 1px solid {border_color};">Status:</td>
                        <td width="80%" style="border-bottom: 1px solid {border_color};">
                            <span style="background-color: {status_bg}; color: {status_color}; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 13px;">
                                {result.status.value}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <td style="color: {text_muted}; font-weight: bold; border-bottom: 1px solid {border_color};">Compliance:</td>
                        <td style="border-bottom: 1px solid {border_color}; font-weight: 500; color: {text_main};">
                            {result.compliant_count} / {result.total_count} ({result.compliance_percentage:.1f}%)
                        </td>
                    </tr>
            """
            
            if hasattr(result, 'cis_severity'):
                sev_val = result.cis_severity.value
                sev_color = "#b91c1c" if sev_val == "HIGH" else "#c2410c" if sev_val == "MEDIUM" else "#15803d"
                if self.dark_mode:
                    sev_color = "#f87171" if sev_val == "HIGH" else "#fb923c" if sev_val == "MEDIUM" else "#4ade80"
                    
                details_text += f"""
                    <tr>
                        <td style="color: {text_muted}; font-weight: bold;">Severity:</td>
                        <td><span style="color: {sev_color}; font-weight: bold;">{sev_val}</span></td>
                    </tr>
                """
                
            details_text += f"""
                </table>
                
                <h3 style="color: {text_muted}; margin-top: 20px; font-size: 16px; border-bottom: 1px solid {border_color}; padding-bottom: 5px;">Detailed Analysis</h3>
                <div style="background-color: {bg_card}; border: 1px solid {border_color}; border-left: 4px solid {status_color}; padding: 15px; margin-bottom: 20px; font-size: 14px; line-height: 1.6; color: {text_main}; border-radius: 4px;">
                    {details_html}
                </div>
            """
            
            if hasattr(result, 'remediation') and result.remediation:
                remediation_html = result.remediation.replace('\n', '<br>')
                remedy_bg = "#f0fdf4" if not self.dark_mode else "#14532d"
                remedy_border = "#bbf7d0" if not self.dark_mode else "#166534"
                remedy_text = "#166534" if not self.dark_mode else "#bbf7d0"
                
                details_text += f"""
                <h3 style="color: {text_muted}; margin-top: 20px; font-size: 16px; border-bottom: 1px solid {border_color}; padding-bottom: 5px;">Recommendations</h3>
                <div style="background-color: {remedy_bg}; border: 1px solid {remedy_border}; padding: 15px; margin-bottom: 20px; font-size: 13px; line-height: 1.6; color: {remedy_text}; border-radius: 4px;">
                    {remediation_html}
                </div>
                """
            
            if result.non_compliant_resources:
                warn_bg = "#fef2f2" if not self.dark_mode else "#7f1d1d"
                warn_border = "#fecaca" if not self.dark_mode else "#991b1b"
                warn_text = "#991b1b" if not self.dark_mode else "#fecaca"
                warn_strong = "#7f1d1d" if not self.dark_mode else "#f87171"
                
                details_text += f"""
                <h3 style="color: {text_muted}; margin-top: 20px; font-size: 16px; border-bottom: 1px solid {border_color}; padding-bottom: 5px;">Non-Compliant Resources</h3>
                <div style="background-color: {warn_bg}; border: 1px solid {warn_border}; padding: 15px; font-size: 13px; color: {warn_text}; border-radius: 4px;">
                    <ul style="margin: 0; padding-left: 20px; list-style-type: disc;">
                """
                for resource in result.non_compliant_resources[:10]:
                    name = resource.get('userPrincipalName') or resource.get('displayName') or resource.get('id', 'Unknown')
                    reason = resource.get('reason', 'Non-compliant')
                    details_text += f"<li style='margin-bottom: 8px;'><strong style='color: {warn_strong};'>{name}</strong><br><span style='color: {warn_strong};'>{reason}</span></li>"
                
                if len(result.non_compliant_resources) > 10:
                    details_text += f"<li style='margin-top: 10px; font-style: italic; color: {warn_strong};'>... and {len(result.non_compliant_resources) - 10} more</li>"
                    
                details_text += "</ul></div>"
                
            details_text += "</div>"
            
            self.details_text.setHtml(details_text)
            self.details_group.setChecked(True)
    
    def _export_results(self):
        """Export scan results."""
        if not self.scan_results or not self.current_scan_metadata:
            AVADialog.alert("No Results", "No scan results to export. Please run a scan first.", kind="info", parent=self).exec()
            return
        
        folder = QFileDialog.getExistingDirectory(self, "Select Export Folder")
        if not folder:
            return
        
        try:
            # Export to database format
            export_path = os.path.join(folder, f"scan_{self.current_scan_metadata.scan_id}.json")
            success = self.db.export_scan(self.current_scan_metadata.scan_id, export_path)
            
            if success:
                AVADialog.alert("Export Successful", f"Results exported to:\n{export_path}", kind="success", parent=self).exec()
                logger.info(f"Results exported: {export_path}")
            else:
                AVADialog.alert("Export Failed", "Could not export results. Check file permissions.", kind="error", parent=self).exec()
                
        except Exception as e:
            AVADialog.alert("Export Error", str(e), kind="error", parent=self).exec()
            logger.error(f"Export error: {e}")
    
    def _refresh_history(self):
        """Refresh scan history table."""
        try:
            scans = self.db.get_scans(limit=50)
            self.history_table.setRowCount(len(scans))
            
            for i, scan in enumerate(scans):
                # Scan ID
                self.history_table.setItem(i, 0, QTableWidgetItem(scan.get('scan_id', '')))
                
                # Date
                date_str = scan.get('timestamp', '')
                if len(date_str) > 19:
                    date_str = date_str[:19]
                self.history_table.setItem(i, 1, QTableWidgetItem(date_str))
                
                # Mode
                self.history_table.setItem(i, 2, QTableWidgetItem(scan.get('environment', '')))
                
                # Tier
                self.history_table.setItem(i, 3, QTableWidgetItem(scan.get('tier', '')))
                
                # Total
                self.history_table.setItem(i, 4, QTableWidgetItem(str(scan.get('total_checks', 0))))
                
                # Passed
                self.history_table.setItem(i, 5, QTableWidgetItem(str(scan.get('passed_checks', 0))))
                
                # Failed
                self.history_table.setItem(i, 6, QTableWidgetItem(str(scan.get('failed_checks', 0))))
                
                # Score
                score = scan.get('overall_score', 0)
                score_item = QTableWidgetItem(f"{score:.1f}%")
                score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                
                if score >= 80:
                    score_item.setForeground(QColor("#166534"))
                elif score >= 60:
                    score_item.setForeground(QColor("#b8860b"))
                else:
                    score_item.setForeground(QColor("#991b1b"))
                
                self.history_table.setItem(i, 7, score_item)
            
            # Update dashboard
            self._update_dashboard()
            
        except Exception as e:
            logger.error(f"Failed to refresh history: {e}")

    def handle_session_revoked(self, reason=""):
        """Handle session revocation from heartbeat, 401, or 403 response."""
        # ── Atomic guard: only process revocation once ───────────────────────
        if getattr(self, '_revocation_in_progress', False):
            logger.warning("handle_session_revoked called again — already in progress, ignoring.")
            return
        self._revocation_in_progress = True

        logger.error(f"SESSION REVOKED at {datetime.now().isoformat()} — reason: {reason}")

        # ── Set global token immediately so all threads see it ───────────────
        GlobalSessionManager().revoke()

        # ── Stop scan worker ─────────────────────────────────────────────────
        if self.worker and self.worker.isRunning():
            logger.info("Scan cancellation started")
            self.worker.stop()
            self.worker.wait(1500)
            logger.info("Scan cancellation ended")

        # ── Stop sync worker ─────────────────────────────────────────────────
        if hasattr(self, 'sync_worker') and self.sync_worker and self.sync_worker.isRunning():
            logger.info("Sync cancellation started")
            self.sync_worker.stop()
            self.sync_worker.wait(1500)
            logger.info("Sync cancellation ended")

        # ── Themed revocation dialog ─────────────────────────────────────────
        AVADialog.revoked(reason=reason, parent=self).exec()

        # ── Layered shutdown ─────────────────────────────────────────────────
        import os
        from PyQt6.QtWidgets import QApplication
        QApplication.quit()
        sys.exit(0)
        os._exit(0)  # final failsafe

    
    def _update_dashboard(self):
        """Update dashboard statistics."""
        try:
            scans = self.db.get_scans(limit=100)
            
            if scans:
                # Total scans
                self.total_scans_label.setText(f"Total Scans: {len(scans)}")
                
                # Last scan
                last_scan = scans[0]
                last_date = last_scan.get('timestamp', 'Never')
                if len(last_date) > 10:
                    last_date = last_date[:10]
                self.last_scan_label.setText(f"Last Scan: {last_date}")
                
                # Average score
                scores = [s.get('overall_score', 0) for s in scans if s.get('overall_score')]
                avg_score = sum(scores) / len(scores) if scores else 0
                self.avg_score_label.setText(f"Average Score: {avg_score:.1f}%")
                
                # Update recent table
                self.recent_table.setRowCount(min(5, len(scans)))
                for i in range(min(5, len(scans))):
                    scan = scans[i]
                    
                    # Date
                    date_str = scan.get('timestamp', '')
                    if len(date_str) > 10:
                        date_str = date_str[:10]
                    self.recent_table.setItem(i, 0, QTableWidgetItem(date_str))
                    
                    # Score
                    score = scan.get('overall_score', 0)
                    self.recent_table.setItem(i, 1, QTableWidgetItem(f"{score:.1f}%"))
                    
                    # Passed
                    self.recent_table.setItem(i, 2, QTableWidgetItem(str(scan.get('passed_checks', 0))))
                    
                    # Failed
                    self.recent_table.setItem(i, 3, QTableWidgetItem(str(scan.get('failed_checks', 0))))
        except Exception as e:
            logger.error(f"Failed to update dashboard: {e}")
    
    def _show_history_context_menu(self, position):
        """Show context menu for history table."""
        menu = QMenu()
        
        view_action = menu.addAction("View Details")
        export_action = menu.addAction("Export to JSON")
        delete_action = menu.addAction("Delete")
        
        action = menu.exec(self.history_table.mapToGlobal(position))
        
        selected_row = self.history_table.currentRow()
        if selected_row < 0:
            return
        
        scan_id = self.history_table.item(selected_row, 0).text()
        
        if action == view_action:
            self._view_scan_details(scan_id)
        elif action == export_action:
            self._export_single_scan(scan_id)
        elif action == delete_action:
            self._delete_scan(scan_id)
    
    def _view_scan_details(self, scan_id: str):
        """View details of a historical scan."""
        details = self.db.get_scan_details(scan_id)
        if not details:
            AVADialog.alert("Not Found", "Scan details not found in the database.", kind="warning", parent=self).exec()
            return
        
        # Create details dialog
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Scan Details - {scan_id}")
        dialog.setGeometry(100, 100, 800, 600)
        
        layout = QVBoxLayout(dialog)
        
        # Basic info
        info_text = f"""
        <h3>Scan Details</h3>
        <p><strong>Scan ID:</strong> {details.get('scan_id')}</p>
        <p><strong>Date:</strong> {details.get('timestamp')}</p>
        <p><strong>Environment:</strong> {details.get('environment')}</p>
        <p><strong>Tier:</strong> {details.get('tier')}</p>
        <p><strong>Score:</strong> {details.get('overall_score', 0):.1f}%</p>
        <p><strong>Duration:</strong> {details.get('duration_seconds', 0):.1f}s</p>
        """
        
        info_label = QLabel(info_text)
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Check results
        if 'checks' in details:
            checks_table = QTableWidget(len(details['checks']), 4)
            checks_table.setHorizontalHeaderLabels(["Check ID", "Status", "Compliance", "Severity"])
            
            for i, check in enumerate(details['checks']):
                checks_table.setItem(i, 0, QTableWidgetItem(check.get('check_id', '')))
                checks_table.setItem(i, 1, QTableWidgetItem(check.get('status', '')))
                compliance = f"{check.get('compliant_count', 0)}/{check.get('total_count', 0)}"
                checks_table.setItem(i, 2, QTableWidgetItem(compliance))
                checks_table.setItem(i, 3, QTableWidgetItem(check.get('severity', '')))
            
            layout.addWidget(checks_table)
        
        dialog.exec()
    
    def _export_single_scan(self, scan_id: str):
        """Export a single scan."""
        folder = QFileDialog.getExistingDirectory(self, "Select Export Folder")
        if not folder:
            return
        
        export_path = os.path.join(folder, f"scan_{scan_id}.json")
        success = self.db.export_scan(scan_id, export_path)
        
        if success:
            AVADialog.alert("Export Successful", f"Scan exported to:\n{export_path}", kind="success", parent=self).exec()
        else:
            AVADialog.alert("Export Failed", "Could not export the scan results.", kind="error", parent=self).exec()
    
    def _delete_scan(self, scan_id: str):
        """Delete a scan from history."""
        if AVADialog.confirm(
            "Confirm Delete",
            f"Are you sure you want to delete scan {scan_id}?",
            confirm_label="Delete", cancel_label="Cancel",
            danger=True, parent=self
        ):
            # Note: Actual deletion would be implemented in DatabaseManager
            AVADialog.alert("Not Implemented", "Delete functionality requires database implementation.", kind="info", parent=self).exec()
    
    def _browse_mock_file(self):
        """Open file dialog to select mock dataset JSON file."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Mock Dataset File",
            project_root,
            "JSON Files (*.json);;All Files (*)"
        )
        if path:
            self.settings_mock_file.setText(path)
    
    def _on_tier_changed(self, tier: str):
        """Auto-toggle check checkboxes based on selected license tier.
        
        FREE  → only FREE_TIER_CHECKS enabled
        PREMIUM → ALL checks enabled
        """
        free_ids = set(FREE_TIER_CHECKS.keys()) if isinstance(FREE_TIER_CHECKS, dict) else set()
        
        for i in range(self.checks_list.count()):
            item = self.checks_list.item(i)
            check_id = item.data(Qt.ItemDataRole.UserRole)
            
            if tier == 'PREMIUM':
                item.setCheckState(Qt.CheckState.Checked)
            else:  # FREE
                if check_id in free_ids:
                    item.setCheckState(Qt.CheckState.Checked)
                else:
                    item.setCheckState(Qt.CheckState.Unchecked)
    
    def _load_settings(self):
        """Load settings from configuration file."""
        try:
            config = configparser.ConfigParser()
            config.read(self.config_path)
            
            # General settings
            if 'General' in config:
                self.settings_user.setText(config.get('General', 'user', fallback=''))
                self.settings_auto_save.setChecked(config.getboolean('General', 'auto_save', fallback=True))
                self.settings_notifications.setChecked(config.getboolean('General', 'notifications', fallback=True))
                # Mock file path
                mock_path = config.get('General', 'mock_data_file', fallback='')
                if mock_path:
                    self.settings_mock_file.setText(mock_path)
                # Portal URL
                portal = config.get('General', 'portal_url', fallback='')
                if portal:
                    self.portal_url = portal
                    self.settings_portal_url.setText(portal)
                # Tier
                saved_tier = config.get('General', 'tier', fallback='')
                if saved_tier in ('FREE', 'PREMIUM'):
                    self.tier_combo.setCurrentText(saved_tier)
            
            # Azure settings
            if 'Azure' in config:
                self.settings_tenant_id.setText(config.get('Azure', 'tenant_id', fallback=''))
                self.settings_client_id.setText(config.get('Azure', 'client_id', fallback=''))
                self.settings_client_secret.setText(config.get('Azure', 'client_secret', fallback=''))
            
            # Check settings
            if 'Checks' in config:
                self.settings_inactivity_days.setValue(config.getint('Checks', 'inactivity_days', fallback=90))
                self.settings_exclude_guests.setChecked(config.getboolean('Checks', 'exclude_guests', fallback=False))
            
            logger.info("Settings loaded")
            
        except Exception as e:
            logger.error(f"Failed to load settings: {e}")
    
    def _save_settings(self):
        """Save settings to configuration file."""
        try:
            config = configparser.ConfigParser()
            
            # General
            general = {
                'user': self.settings_user.text(),
                'auto_save': str(self.settings_auto_save.isChecked()),
                'notifications': str(self.settings_notifications.isChecked()),
                'tier': self.tier_combo.currentText(),
            }
            mock_path = self.settings_mock_file.text().strip()
            if mock_path:
                general['mock_data_file'] = mock_path
            portal_url = self.settings_portal_url.text().strip()
            if portal_url:
                general['portal_url'] = portal_url
                self.portal_url = portal_url
            config['General'] = general
            
            # Azure
            config['Azure'] = {
                'tenant_id': self.settings_tenant_id.text(),
                'client_id': self.settings_client_id.text(),
                'client_secret': self.settings_client_secret.text()
            }
            
            # Checks
            config['Checks'] = {
                'inactivity_days': str(self.settings_inactivity_days.value()),
                'exclude_guests': str(self.settings_exclude_guests.isChecked())
            }
            
            with open(self.config_path, 'w') as f:
                config.write(f)
            
            AVADialog.alert("Settings Saved", "Configuration updated successfully.", kind="success", parent=self).exec()
            logger.info("Settings saved")
            
        except Exception as e:
            AVADialog.alert("Save Error", f"Could not save settings:\n{e}", kind="error", parent=self).exec()
            logger.error(f"Settings save error: {e}")
    
    def _toggle_dark_mode(self):
        """Toggle dark mode."""
        self.dark_mode = not self.dark_mode
        
        if self.dark_mode:
            # Enhanced dark theme matching Web Portal
            self.setStyleSheet("""
                QMainWindow, QDialog { background-color: #0f172a; }
                QWidget { background-color: #0f172a; color: #f1f5f9; font-family: Inter, -apple-system, sans-serif; }
                QPushButton { 
                    background-color: #3b82f6; 
                    color: white; 
                    border: none;
                    border-radius: 6px; 
                    padding: 8px 16px;
                    font-weight: 600;
                }
                QPushButton:hover { background-color: #2563eb; }
                QPushButton:disabled { background-color: #475569; color: #94a3b8; }
                QTableWidget { 
                    background-color: #1e293b; 
                    color: #f1f5f9;
                    gridline-color: #334155;
                    border: 1px solid #334155;
                    border-radius: 4px;
                }
                QTableWidget::item:selected { background-color: #3b82f6; color: white; }
                QHeaderView::section {
                    background-color: #1e293b;
                    color: #94a3b8;
                    font-weight: bold;
                    border: 1px solid #334155;
                    padding: 6px;
                }
                QTabWidget::pane { border: 1px solid #334155; border-radius: 4px; }
                QTabBar::tab { background: #1e293b; color: #94a3b8; padding: 10px 20px; border: 1px solid #334155; }
                QTabBar::tab:selected { background: #3b82f6; color: white; border-bottom-color: #3b82f6; }
                QGroupBox { border: 1px solid #334155; border-radius: 6px; margin-top: 15px; padding: 15px; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; color: #3b82f6; font-weight: bold; }
                QTextEdit { background-color: #1e293b; color: #f1f5f9; border: 1px solid #334155; border-radius: 4px; }
                QLineEdit, QComboBox, QSpinBox { background-color: #1e293b; border: 1px solid #334155; border-radius: 4px; padding: 6px; }
                QMessageBox { background-color: #0f172a; }
                QMessageBox QLabel { color: #f1f5f9; }
                QMenu { background-color: #1e293b; color: #f1f5f9; border: 1px solid #334155; }
                QMenu::item:selected { background-color: #3b82f6; }
            """)
        else:
            # Modern light theme matching Web Portal
            self.setStyleSheet("""
                QMainWindow, QDialog { background-color: #f8fafc; }
                QWidget { background-color: #f8fafc; color: #0f172a; font-family: Inter, -apple-system, sans-serif; }
                QPushButton { 
                    background-color: #3b82f6; 
                    color: white; 
                    border: none;
                    border-radius: 6px; 
                    padding: 8px 16px;
                    font-weight: 600;
                }
                QPushButton:hover { background-color: #2563eb; }
                QPushButton:disabled { background-color: #cbd5e1; color: #64748b; }
                QTableWidget { 
                    background-color: #ffffff; 
                    color: #334155;
                    gridline-color: #e2e8f0;
                    border: 1px solid #e2e8f0;
                    border-radius: 4px;
                }
                QTableWidget::item:selected { background-color: #eff6ff; color: #1e40af; }
                QHeaderView::section {
                    background-color: #f1f5f9;
                    color: #475569;
                    font-weight: bold;
                    border: 1px solid #e2e8f0;
                    padding: 6px;
                }
                QTabWidget::pane { border: 1px solid #e2e8f0; border-radius: 4px; background-color: #ffffff; }
                QTabBar::tab { background: #f1f5f9; color: #64748b; padding: 10px 20px; border: 1px solid #e2e8f0; border-bottom: none; }
                QTabBar::tab:selected { background: #ffffff; color: #2563eb; border-top: 2px solid #2563eb; font-weight: bold; }
                QGroupBox { border: 1px solid #e2e8f0; border-radius: 6px; margin-top: 15px; padding: 15px; background-color: white; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; color: #1e40af; font-weight: bold; }
                QTextEdit { background-color: #ffffff; color: #334155; border: 1px solid #e2e8f0; border-radius: 4px; }
                QLineEdit, QComboBox, QSpinBox { background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 4px; padding: 6px; }
                QMessageBox { background-color: #ffffff; }
                QMessageBox QLabel { color: #0f172a; }
                QMenu { background-color: #ffffff; color: #0f172a; border: 1px solid #e2e8f0; }
                QMenu::item:selected { background-color: #eff6ff; color: #1e40af; }
            """)
    
    def _show_about(self):
        """Show about dialog."""
        about_text = """
        <h3>AVAGuard Desktop v2.2</h3>
        <p>Azure CIS Compliance Scanner</p>
        <p>Version: 2.2.0</p>
        <p>SRS Compliant: Yes</p>
        <p>Developed for Foundation University</p>
        <p>© 2025 C3 Group - All rights reserved</p>
        """
        
        QMessageBox.about(self, "About AVAGuard", about_text)
    
    def closeEvent(self, event):
        """Handle window close event."""
        if self.worker and self.worker.isRunning():
            reply = QMessageBox.question(
                self, "Scan In Progress",
                "A scan is running. Exit anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.worker.stop()
                self.worker.wait(2000)  # Wait up to 2 seconds
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()
        
        logger.info("Application closed")

