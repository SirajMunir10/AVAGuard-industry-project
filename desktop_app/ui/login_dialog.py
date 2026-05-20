"""
AVAGuard Desktop - Security Gateway Dialog

PyQt6 login dialog that enforces web portal authentication.
No direct login - user must authenticate via browser.
"""

import os
import sys
import socket
import logging
import webbrowser
from typing import Optional

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QApplication
)
from utils.themed_dialog import AVADialog
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont

from datetime import datetime
import requests
from utils.session_manager import GlobalSessionManager

logger = logging.getLogger(__name__)


class DevicePollingWorker(QThread):
    """
    Background thread that polls the web API for device authorization.
    
    Polls every 2 seconds until:
    - Device is APPROVED (emits authorized signal)
    - Device is EXPIRED/REVOKED (emits failed signal)
    - Token expires (5 minutes)
    - Manual stop
    """
    
    authorized = pyqtSignal(str, str, dict)  # access_token, refresh_token, user_data
    status_changed = pyqtSignal(str)  # status message for UI
    failed = pyqtSignal(str)  # error message
    
    POLL_INTERVAL_MS = 2000  # 2 seconds
    
    def __init__(self, base_url: str, device_token: str):
        super().__init__()
        self.base_url = base_url.rstrip('/')
        self.device_token = device_token
        self._stopped = False
    
    def run(self):
        poll_url = f"{self.base_url}/api/auth/device/status/{self.device_token}/"
        poll_count = 0
        max_polls = 150  # 5 minutes at 2-second intervals
        
        while not self._stopped and poll_count < max_polls:
            try:
                response = requests.get(poll_url, timeout=5)
                data = response.json()
                
                status = data.get('status', 'UNKNOWN')
                
                if status == 'APPROVED':
                    # Success! Get the JWT tokens
                    access_token = data.get('access', '')
                    refresh_token = data.get('refresh', '')
                    user_data = data.get('user', {})
                    
                    if access_token:
                        self.status_changed.emit("✅ Device authorized!")
                        self.authorized.emit(access_token, refresh_token, user_data)
                        return
                    else:
                        self.failed.emit("Authorization received but no token provided.")
                        return
                
                elif status == 'EXPIRED':
                    self.failed.emit("Token expired. Please try again.")
                    return
                
                elif status == 'REVOKED':
                    self.failed.emit("Session revoked by administrator.")
                    return
                
                elif status == 'PENDING':
                    poll_count += 1
                    self.status_changed.emit(f"Waiting for authorization... ({poll_count})")
                
                else:
                    self.status_changed.emit(f"Status: {status}")
                
            except requests.exceptions.ConnectionError:
                self.status_changed.emit("⚠️ Cannot connect to portal...")
            except requests.exceptions.Timeout:
                self.status_changed.emit("⚠️ Connection timeout...")
            except Exception as e:
                logger.error(f"Polling error: {e}")
                self.status_changed.emit(f"Error: {str(e)[:30]}")
            
            # Wait before next poll
            self.msleep(self.POLL_INTERVAL_MS)
        
        if not self._stopped:
            self.failed.emit("Authorization timeout. Please try again.")
    
    def stop(self):
        self._stopped = True


class HeartbeatWorker(QThread):
    """
    Background thread that sends heartbeat to server every 5 minutes.
    Detects session revocation.
    """
    
    session_revoked = pyqtSignal(str)  # reason
    heartbeat_sent = pyqtSignal()
    HEARTBEAT_INTERVAL_MS = 10000  # 10 seconds
    
    def __init__(self, base_url: str, device_token: str, access_token: str):
        super().__init__()
        self.base_url = base_url.rstrip('/')
        self.device_token = device_token
        self.access_token = access_token
        self._active = True
    
    def run(self):
        heartbeat_url = f"{self.base_url}/api/auth/heartbeat/"
        
        while self._active:
            try:
                response = requests.post(
                    heartbeat_url,
                    json={"device_token": self.device_token},
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    timeout=10
                )
                
                if response.status_code == 401:
                    # Session revoked!
                    GlobalSessionManager().revoke()
                    logger.error(f"Session revoked detected at {datetime.now().isoformat()}")
                    data = response.json()
                    reason = data.get('error', 'Session revoked')
                    self.session_revoked.emit(reason)
                    return
                
                elif response.status_code == 200:
                    logger.info(f"Heartbeat success at {datetime.now().isoformat()}")
                    self.heartbeat_sent.emit()
                    logger.debug("Heartbeat sent successfully")
                
            except Exception as e:
                logger.warning(f"Heartbeat error: {e}")
            
            # Wait for next heartbeat
            self.msleep(self.HEARTBEAT_INTERVAL_MS)
    
    def stop(self):
        self._active = False


class SecurityGatewayDialog(QDialog):
    """
    Security Gateway - The locked state of the desktop app.
    
    Shows "Device Not Authorized" and forces user to authenticate
    via the web portal. No direct login is possible.
    
    Signals:
        authorized: Emitted with (access_token, refresh_token, user_data) on success
    """
    
    authorized = pyqtSignal(str, str, dict)
    
    STYLE = """
        QDialog {
            background-color: #1a1a2e;
        }
        QLabel {
            color: #e8e8e8;
        }
        QLabel#title {
            color: #00d4ff;
            font-size: 28px;
            font-weight: bold;
        }
        QLabel#status_icon {
            font-size: 64px;
        }
        QLabel#status_text {
            color: #ff6b6b;
            font-size: 18px;
            font-weight: bold;
        }
        QLabel#subtitle {
            color: #888888;
            font-size: 13px;
        }
        QLabel#poll_status {
            color: #888888;
            font-size: 12px;
        }
        QPushButton#connectBtn {
            background-color: #00d4ff;
            color: #1a1a2e;
            border: none;
            border-radius: 8px;
            padding: 16px 32px;
            font-size: 15px;
            font-weight: bold;
        }
        QPushButton#connectBtn:hover {
            background-color: #00b8e6;
        }
        QPushButton#connectBtn:pressed {
            background-color: #0099cc;
        }
        QPushButton#connectBtn:disabled {
            background-color: #333333;
            color: #666666;
        }
        QPushButton#cancelBtn {
            background: transparent;
            color: #888888;
            border: 1px solid #333333;
            border-radius: 8px;
            padding: 12px 24px;
            font-size: 13px;
        }
        QPushButton#cancelBtn:hover {
            border-color: #ff6b6b;
            color: #ff6b6b;
        }
        QFrame#separator {
            background-color: #333333;
        }
    """
    
    def __init__(
        self,
        parent=None,
        portal_url: str = "http://localhost:8000"
    ):
        super().__init__(parent)
        
        self.portal_url = portal_url.rstrip('/')
        self.device_token: Optional[str] = None
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.user_data: dict = {}
        
        self._polling_worker: Optional[DevicePollingWorker] = None
        self._heartbeat_worker: Optional[HeartbeatWorker] = None
        
        self._setup_ui()
        self._connect_signals()
    
    def _setup_ui(self):
        """Setup the Security Gateway UI."""
        self.setWindowTitle("AVAGuard - Security Gateway")
        self.setFixedSize(500, 480)
        self.setStyleSheet(self.STYLE)
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.WindowCloseButtonHint
        )
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(50, 40, 50, 40)
        layout.setSpacing(16)
        
        # Title
        title = QLabel("🛡️ AVAGuard")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        layout.addSpacing(20)
        
        # Status icon
        self.status_icon = QLabel("⛔")
        self.status_icon.setObjectName("status_icon")
        self.status_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_icon)
        
        # Status text
        self.status_text = QLabel("Device Not Authorized")
        self.status_text.setObjectName("status_text")
        self.status_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_text)
        
        # Subtitle
        subtitle = QLabel("Please authenticate via the Web Portal to continue.")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)
        
        layout.addSpacing(30)
        
        # Connect button
        self.connect_btn = QPushButton("🌐 Connect to Portal")
        self.connect_btn.setObjectName("connectBtn")
        self.connect_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        layout.addWidget(self.connect_btn)
        
        # Retry button (Hidden initially)
        self.retry_btn = QPushButton("🔄 Reopen Portal Page")
        self.retry_btn.setObjectName("retryBtn")
        self.retry_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.retry_btn.setVisible(False)
        self.retry_btn.setStyleSheet("background: transparent; border: 1px solid #3366ff; color: #3366ff; padding: 10px; border-radius: 5px;")
        layout.addWidget(self.retry_btn)
        
        # Polling status
        self.poll_status = QLabel("")
        self.poll_status.setObjectName("poll_status")
        self.poll_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.poll_status)
        
        layout.addStretch()
        
        # Separator
        separator = QFrame()
        separator.setObjectName("separator")
        separator.setFixedHeight(1)
        layout.addWidget(separator)
        
        layout.addSpacing(10)
        
        # Portal URL info
        portal_info = QLabel(f"Portal: {self.portal_url}")
        portal_info.setStyleSheet("color: #555555; font-size: 10px;")
        portal_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(portal_info)
        
        # Cancel button
        self.cancel_btn = QPushButton("Exit")
        self.cancel_btn.setObjectName("cancelBtn")
        self.cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        layout.addWidget(self.cancel_btn)
    
    def _connect_signals(self):
        """Connect UI signals."""
        self.connect_btn.clicked.connect(self._on_connect_clicked)
        self.retry_btn.clicked.connect(self._on_retry_clicked)
        self.cancel_btn.clicked.connect(self.reject)
    
    def _generate_device_token(self) -> str:
        """Generate a unique device token."""
        import secrets
        hostname = socket.gethostname()[:10]
        random_part = secrets.token_hex(8)
        return f"auth_{hostname}_{random_part}"
    
    def _on_connect_clicked(self):
        """Handle Connect button click."""
        # Disable button during process
        self.connect_btn.setEnabled(False)
        self.connect_btn.setText("Connecting...")
        self.poll_status.setText("Registering device...")
        
        try:
            # Step 1: Generate device token
            self.device_token = self._generate_device_token()
            
            # Step 2: Register with web API
            register_url = f"{self.portal_url}/api/auth/device/register/"
            response = requests.post(
                register_url,
                json={
                    "device_token": self.device_token,
                    "device_name": socket.gethostname()
                },
                timeout=10
            )
            
            if response.status_code not in (200, 201):
                raise Exception(f"Registration failed: {response.text}")
            
            data = response.json()
            authorize_url = data.get('authorize_url', f"/auth/authorize-device/?token={self.device_token}")
            self.authorize_full_url = f"{self.portal_url}{authorize_url}"
            
            # Step 3: Open browser to authorization page
            self.poll_status.setText("Opening browser...")
            webbrowser.open(self.authorize_full_url)
            
            # Show retry button
            self.retry_btn.setVisible(True)
            self.connect_btn.setText("Waiting for approval...")
            
            # Step 4: Start polling for approval
            self._start_polling()
            
        except requests.exceptions.ConnectionError:
            self._show_error("Cannot connect to web portal. Is it running?")
            self._reset_ui()
        except Exception as e:
            logger.error(f"Connect error: {e}")
            self._show_error(f"Connection error: {str(e)}")
            self._reset_ui()

    def _on_retry_clicked(self):
        """Reopen the browser page."""
        if hasattr(self, 'authorize_full_url') and self.authorize_full_url:
             webbrowser.open(self.authorize_full_url)
             self.poll_status.setText("re-opened browser page...")
        else:
             self._on_connect_clicked()
    
    def _start_polling(self):
        """Start the device authorization polling worker."""
        self.connect_btn.setText("Waiting for approval...")
        self.status_icon.setText("⏳")
        self.status_text.setText("Awaiting Authorization")
        self.status_text.setStyleSheet("color: #ffd93d;")
        
        self._polling_worker = DevicePollingWorker(self.portal_url, self.device_token)
        self._polling_worker.status_changed.connect(self._on_poll_status)
        self._polling_worker.authorized.connect(self._on_authorized)
        self._polling_worker.failed.connect(self._on_poll_failed)
        self._polling_worker.start()
    
    def _on_poll_status(self, status: str):
        """Update polling status display."""
        self.poll_status.setText(status)
    
    def _on_authorized(self, access_token: str, refresh_token: str, user_data: dict):
        """Handle successful authorization."""
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.user_data = user_data
        
        # Update UI
        self.status_icon.setText("✅")
        self.status_text.setText("Authorized!")
        self.status_text.setStyleSheet("color: #00ff88;")
        self.poll_status.setText(f"Welcome, {user_data.get('name', user_data.get('email', 'User'))}!")
        
        # Start heartbeat worker
        self._heartbeat_worker = HeartbeatWorker(
            self.portal_url, 
            self.device_token, 
            self.access_token
        )
        self._heartbeat_worker.session_revoked.connect(self._on_session_revoked)
        self._heartbeat_worker.start()
        
        # Emit success signal and close dialog after a brief delay
        QTimer.singleShot(1000, lambda: self._complete_authorization())
    
    def _complete_authorization(self):
        """Complete the authorization and close dialog."""
        self.authorized.emit(self.access_token, self.refresh_token, self.user_data)
        self.accept()
    
    def _on_poll_failed(self, error: str):
        """Handle polling failure."""
        self._show_error(error)
        self._reset_ui()
    
    def _on_session_revoked(self, reason: str):
        """Handle session revocation from heartbeat."""
        AVADialog.alert(
            "Session Revoked",
            f"Your session has been revoked.\n\nReason: {reason}\n\nPlease re-authenticate.",
            kind="warning", parent=self
        ).exec()
        self._reset_ui()
        # This will be handled by the main app to show the gateway again
    
    def _show_error(self, message: str):
        """Show error message."""
        AVADialog.alert("Connection Error", message, kind="error", parent=self).exec()
    
    def _reset_ui(self):
        """Reset UI to initial state."""
        self.connect_btn.setEnabled(True)
        self.connect_btn.setText("🌐 Connect to Portal")
        self.status_icon.setText("⛔")
        self.status_text.setText("Device Not Authorized")
        self.status_text.setStyleSheet("color: #ff6b6b;")
        self.poll_status.setText("")
        self.retry_btn.setVisible(False)
        
        if self._polling_worker:
            self._polling_worker.stop()
            self._polling_worker = None
    
    def get_credentials(self) -> dict:
        """Get the authorization credentials."""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "device_token": self.device_token,
            "user": self.user_data
        }
    
    def get_heartbeat_worker(self) -> Optional[HeartbeatWorker]:
        """Get the heartbeat worker for the main app to manage."""
        return self._heartbeat_worker
    
    def closeEvent(self, event):
        """Clean up workers on close."""
        if self._polling_worker:
            self._polling_worker.stop()
            self._polling_worker.wait(1000)
        if self._heartbeat_worker:
            self._heartbeat_worker.stop()
            self._heartbeat_worker.wait(1000)
        super().closeEvent(event)


# For standalone testing
if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    dialog = SecurityGatewayDialog(portal_url="http://localhost:8000")
    
    def on_authorized(access, refresh, user):
        print(f"Authorized! User: {user}")
        print(f"Access Token: {access[:50]}...")
    
    dialog.authorized.connect(on_authorized)
    
    if dialog.exec() == QDialog.DialogCode.Accepted:
        print("Login successful!")
        print(dialog.get_credentials())
    else:
        print("Login cancelled")
    
    sys.exit()
