import sys
from packaging.version import Version

MIN_CORE_VERSION = "0.1.0"

def validate_core_dependency():
    """Validate avaguard-core presence and version."""
    try:
        from avaguard_core import __version__ as core_version
    except ImportError:
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.critical(
            None,
            "Missing Dependency",
            "avaguard-core is not installed.\n\nFix: Run 'pip install -e ./avaguard-core'"
        )
        sys.exit(1)

    if Version(core_version) < Version(MIN_CORE_VERSION):
        from PyQt6.QtWidgets import QMessageBox
        QMessageBox.critical(
            None,
            "Version Mismatch",
            f"avaguard-core version mismatch.\n\n"
            f"Required : >= {MIN_CORE_VERSION}\n"
            f"Installed: {core_version}\n\n"
            f"Fix: Run 'pip install --upgrade avaguard-core'"
        )
        sys.exit(1)

    return core_version
