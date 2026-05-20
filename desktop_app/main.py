"""AVAGuard Desktop - Application Entry Point"""

import sys
import os
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QDialog
import configparser
import logging

try:
    from avaguard_core.logging_config import setup_logging
    from avaguard_core.config_validator import validate_config
    setup_logging()
except ImportError:
    pass

logger = logging.getLogger(__name__)

from views.main_window_enhanced import EnhancedMainWindow

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from utils.dependency_check import validate_core_dependency

def main():
    """Launch the enhanced desktop application with tethered security."""
    print("\n" + "="*60)
    print("🛡️  AVAGuard Desktop - Enhanced Edition")
    print("="*60)

    try:
        # Create application
        app = QApplication(sys.argv)
        app.setApplicationName("AVAGuard")
        
        from avaguard_core.logging_config import configure_logging
        configure_logging(
            level="INFO",
            json_output=False,
            log_file=str(Path(project_root) / "output" / "logs" / "avaguard_desktop.log")
        )
        
        try:
            app_version = validate_core_dependency()
        except Exception as e:
            app_version = "0.1.0"
            
        app.setApplicationVersion(app_version)
    
        # Set application style
        app.setStyle('Fusion')
        
        # Enterprise Typography (Phase 1)
        from PyQt6.QtGui import QFont
        app_font = QFont("Segoe UI", 10)
        app_font.setStyleHint(QFont.StyleHint.SansSerif)
        app.setFont(app_font)
    
        # Configuration
        config_path = Path(project_root) / "config.ini"
    
        from avaguard_core.config_validator import validate_config, ValidationSeverity
        from utils.themed_dialog import AVADialog
        
        is_mock_forced = False
        report = validate_config(str(config_path))
        
        # 1. Missing File → Setup Dialog / Options
        if not report.is_valid_for_mock:
            AVADialog.alert(
                "Configuration Missing",
                "The configuration file is missing or critically corrupted.\n\n"
                "The application will launch in disconnected Mock Mode.",
                kind="error"
            ).exec()
            is_mock_forced = True

        # 2. Azure Errors → Show Warn, Run Mock
        elif report.has_errors():
            msg = "Azure credentials are not configured or invalid:\n\n"
            for err in report.get_errors():
                msg += f"  • {err.field}: {err.message}\n"
            msg += "\nThe application will run safely in Mock Mode.\nLive Azure data will not be available."
            AVADialog.alert("Running in Mock Mode", msg, kind="warning").exec()
            is_mock_forced = True

        # 3. Warnings Only → Show Warn, Continue
        elif report.has_warnings():
            msg = "Configuration Warnings detected:\n\n"
            for warn in report.get_warnings():
                msg += f"  • {warn.field}: {warn.message}\n"
            AVADialog.alert("Configuration Warning", msg, kind="warning").exec()
            
        portal_url = report.normalized_config.get('portal_url') or 'http://localhost:8000'
        portal_url = portal_url.rstrip('/')
    
        # ========================================
        # SECURITY GATEWAY - Must authenticate first
        # ========================================
        from ui.login_dialog import SecurityGatewayDialog
    
        print("🔒 Security Gateway: Device authorization required")
    
        gateway = SecurityGatewayDialog(portal_url=portal_url)
    
        if gateway.exec() != QDialog.DialogCode.Accepted:
            print("❌ Authorization cancelled. Exiting.")
            sys.exit(0)
    
        # Get credentials from gateway
        credentials = gateway.get_credentials()
        user_data = credentials.get('user', {})
        user_role = user_data.get('role', 'VIEWER')
        heartbeat_worker = gateway.get_heartbeat_worker()
    
        print(f"✅ Authorized as: {user_data.get('email', 'Unknown')} ({user_role})")
    
        # ========================================
        # Create Main Window with user context
        # ========================================
        window = EnhancedMainWindow(portal_url=portal_url)
    
        # Store user context in window
        window.user_data = user_data
        window.user_role = user_role
        window.access_token = credentials.get('access_token')
        window.device_token = credentials.get('device_token')
        window.portal_url = portal_url
    
        # Apply role-based restrictions
        if user_role == 'VIEWER':
            # Disable scan controls for viewers
            if hasattr(window, 'start_scan_btn'):
                window.start_scan_btn.setEnabled(False)
                window.start_scan_btn.setToolTip("Viewers cannot run scans")
            print("⚠️  Viewer mode: Scan controls disabled")
    
        # Handle session revocation
        if heartbeat_worker:
            heartbeat_worker.session_revoked.connect(window.handle_session_revoked)
    
        # Show main window
        window.show()
    
        # Update window title with user info
        window.setWindowTitle(f"AVAGuard Desktop - {user_data.get('email', 'User')} ({user_role})")
        
        # Update Window State and attach Persistent Banner
        if is_mock_forced:
            from PyQt6.QtWidgets import QLabel
            from PyQt6.QtCore import Qt
            window.mock_banner = QLabel("⚠️ RUNNING IN MOCK MODE — AZURE CREDENTIALS INVALID")
            window.mock_banner.setStyleSheet("background-color: #ff9800; color: white; padding: 5px; font-weight: bold;")
            window.mock_banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            # Get the central widget's layout, not the window's layout
            central = window.centralWidget()
            if central and central.layout():
                central.layout().insertWidget(0, window.mock_banner)
            else:
                # Fallback: add as status bar message
                window.statusBar().showMessage("⚠️ MOCK MODE — Azure credentials not configured", 0)
            window.is_mock_forced = True
    
        # Enter event loop
        print("✅ Application initialized successfully")
        print("🚀 Entering event loop...")
    
        result = app.exec()
    
        # Cleanup heartbeat on exit
        if heartbeat_worker:
            heartbeat_worker.stop()
            heartbeat_worker.wait(1000)
    
        sys.exit(result)
    
    except Exception as e:
        logger.critical(f"Application startup failed: {str(e)}", exc_info=True)
        print(f"❌ CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
