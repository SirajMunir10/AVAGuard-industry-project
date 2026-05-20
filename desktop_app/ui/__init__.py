# AVAGuard Desktop - UI Package
from .login_dialog import SecurityGatewayDialog, DevicePollingWorker, HeartbeatWorker

# Backward compatibility alias
LoginDialog = SecurityGatewayDialog

__all__ = ['SecurityGatewayDialog', 'LoginDialog', 'DevicePollingWorker', 'HeartbeatWorker']

