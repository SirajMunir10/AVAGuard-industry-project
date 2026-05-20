"""
AVAGuard Desktop - Themed Dialog Utility

Professional, theme-aware dialogs that integrate with the AVAGuard desktop UI.
Supports both dark and light mode. Replaces all raw QMessageBox calls.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QWidget, QFrame, QApplication, QSizeGrip
)
from PyQt6.QtCore import Qt, QPoint
from PyQt6.QtGui import QFont, QColor, QMouseEvent

# ─── Theme Palettes ──────────────────────────────────────────────────────────

_DARK = {
    "bg":           "#1e2130",
    "card":         "#252840",
    "title_bar":    "#181b2e",
    "border":       "#3a3f5c",
    "text":         "#e8eaf6",
    "text_muted":   "#9e9eb8",
    "btn_primary":  "#4a5cc0",
    "btn_primary_h":"#5c70d4",
    "btn_danger":   "#c0392b",
    "btn_danger_h": "#d44332",
    "btn_secondary":"#2d3152",
    "btn_secondary_h":"#363b5e",
    "btn_text":     "#ffffff",
    "close_hover":  "#c0392b",
}

_LIGHT = {
    "bg":           "#f4f5fb",
    "card":         "#ffffff",
    "title_bar":    "#e8eaf6",
    "border":       "#c5cae9",
    "text":         "#1a1c2e",
    "text_muted":   "#5c5f80",
    "btn_primary":  "#3f51b5",
    "btn_primary_h":"#5c6bc0",
    "btn_danger":   "#c62828",
    "btn_danger_h": "#d32f2f",
    "btn_secondary":"#e8eaf6",
    "btn_secondary_h":"#c5cae9",
    "btn_text":     "#ffffff",
    "close_hover":  "#c62828",
}

_ACCENT_COLORS = {
    "error":    "#c0392b",
    "warning":  "#e67e22",
    "info":     "#2980b9",
    "success":  "#27ae60",
    "revoked":  "#8e24aa",
    "question": "#3f51b5",
}


def _get_palette():
    """Detect current app dark/light mode and return matching palette."""
    app = QApplication.instance()
    if app:
        bg = app.palette().window().color()
        if bg.lightness() < 128:
            return _DARK
    return _LIGHT


class AVADialog(QDialog):
    """
    Professional, theme-aware dialog for AVAGuard Desktop.

    Usage:
        AVADialog.alert("Title", "Message", kind="error", parent=window).exec()
        ok = AVADialog.confirm("Delete?", "Cannot be undone.", danger=True, parent=window)
        AVADialog.revoked(reason="...", parent=window).exec()
        AVADialog.sync_failed(2, errors, parent=window).exec()
    """

    ACCEPTED = QDialog.DialogCode.Accepted
    REJECTED = QDialog.DialogCode.Rejected

    def __init__(self, title: str, message: str, kind: str = "info",
                 buttons=None, parent=None):
        super().__init__(parent, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.setMinimumWidth(440)

        p = _get_palette()
        accent = _ACCENT_COLORS.get(kind, _ACCENT_COLORS["info"])

        if buttons is None:
            buttons = [("OK", "primary", self.ACCEPTED)]

        self._drag_pos: QPoint | None = None

        # ── Stylesheet ───────────────────────────────────────────────────────
        self.setStyleSheet(f"""
            QFrame#main_frame {{
                background-color: {p['bg']};
                border: 1px solid {p['border']};
                border-radius: 10px;
            }}
            QLabel {{
                background: transparent;
                color: {p['text']};
            }}
            QPushButton {{
                border: none;
                border-radius: 5px;
                padding: 7px 20px;
                font-size: 12px;
                font-weight: 600;
                min-width: 80px;
            }}
            QPushButton#primary_btn {{
                background-color: {p['btn_primary']};
                color: {p['btn_text']};
            }}
            QPushButton#primary_btn:hover {{
                background-color: {p['btn_primary_h']};
            }}
            QPushButton#danger_btn {{
                background-color: {p['btn_danger']};
                color: {p['btn_text']};
            }}
            QPushButton#danger_btn:hover {{
                background-color: {p['btn_danger_h']};
            }}
            QPushButton#secondary_btn {{
                background-color: {p['btn_secondary']};
                color: {p['text']};
                border: 1px solid {p['border']};
            }}
            QPushButton#secondary_btn:hover {{
                background-color: {p['btn_secondary_h']};
            }}
            QPushButton#close_btn {{
                background-color: transparent;
                color: {p['text_muted']};
                border: none;
                border-radius: 12px;
                min-width: 24px;
                max-width: 24px;
                min-height: 24px;
                max-height: 24px;
                font-size: 14px;
                padding: 0;
            }}
            QPushButton#close_btn:hover {{
                background-color: {p['close_hover']};
                color: #ffffff;
            }}
        """)

        # Main wrapper frame to properly draw translucent background
        main_frame = QFrame(self)
        main_frame.setObjectName("main_frame")
        
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(main_frame)

        root = QVBoxLayout(main_frame)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Accent top bar ───────────────────────────────────────────────────
        top_bar = QFrame()
        top_bar.setFixedHeight(4)
        top_bar.setStyleSheet(f"background-color: {accent}; border-radius: 9px;")
        root.addWidget(top_bar)

        # ── Title bar ────────────────────────────────────────────────────────
        title_bar = QWidget()
        title_bar.setStyleSheet(f"background-color: {p['title_bar']};")
        title_bar.setFixedHeight(40)
        tbl = QHBoxLayout(title_bar)
        tbl.setContentsMargins(18, 0, 10, 0)
        tbl.setSpacing(8)

        # Title
        title_lbl = QLabel(title)
        title_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {p['text']};")
        tbl.addWidget(title_lbl, 1)

        # Close button
        close_btn = QPushButton("✕")
        close_btn.setObjectName("close_btn")
        close_btn.clicked.connect(self.reject)
        tbl.addWidget(close_btn)

        root.addWidget(title_bar)

        # ── Separator ────────────────────────────────────────────────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {p['border']};")
        sep.setFixedHeight(1)
        root.addWidget(sep)

        # ── Body ─────────────────────────────────────────────────────────────
        body = QVBoxLayout()
        body.setContentsMargins(24, 20, 24, 8)
        body.setSpacing(10)

        msg_lbl = QLabel(message)
        msg_lbl.setWordWrap(True)
        msg_lbl.setFont(QFont("Segoe UI", 10))
        msg_lbl.setStyleSheet(f"color: {p['text_muted']}; line-height: 1.6;")
        msg_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        body.addWidget(msg_lbl)
        root.addLayout(body)

        # ── Button row ───────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(24, 10, 24, 20)
        btn_row.addStretch()

        for btn_label, btn_style, btn_result in buttons:
            btn = QPushButton(btn_label)
            obj_name = f"{btn_style}_btn"
            btn.setObjectName(obj_name)
            result = btn_result

            def _clicked(checked=False, r=result):
                self._result_code = r
                if r == self.ACCEPTED:
                    self.accept()
                else:
                    self.reject()

            btn.clicked.connect(_clicked)
            btn_row.addWidget(btn)

        root.addLayout(btn_row)
        self.adjustSize()

    # ── Draggable frameless window ────────────────────────────────────────────
    def mousePressEvent(self, ev: QMouseEvent):
        if ev.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = ev.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, ev: QMouseEvent):
        if self._drag_pos and ev.buttons() & Qt.MouseButton.LeftButton:
            self.move(ev.globalPosition().toPoint() - self._drag_pos)

    def mouseReleaseEvent(self, ev: QMouseEvent):
        self._drag_pos = None

    # ── Convenience factories ─────────────────────────────────────────────────

    @classmethod
    def alert(cls, title: str, message: str, kind: str = "info", parent=None) -> "AVADialog":
        return cls(title, message, kind=kind,
                   buttons=[("OK", "primary", cls.ACCEPTED)], parent=parent)

    @classmethod
    def confirm(cls, title: str, message: str, confirm_label: str = "Confirm",
                cancel_label: str = "Cancel", danger: bool = False,
                parent=None) -> bool:
        btn_style = "danger" if danger else "primary"
        dlg = cls(title, message,
                  kind="warning" if danger else "question",
                  buttons=[
                      (cancel_label, "secondary", cls.REJECTED),
                      (confirm_label, btn_style, cls.ACCEPTED),
                  ], parent=parent)
        return dlg.exec() == cls.ACCEPTED

    @classmethod
    def revoked(cls, reason: str = "", parent=None) -> "AVADialog":
        msg = ("Your session has been revoked by an administrator.\n"
               "The application will now close securely.")
        if reason:
            clean_reason = reason.replace("Session has been revoked (403): ", "")
            msg += f"\n\nReason: {clean_reason}"
        return cls("Session Revoked", msg, kind="revoked",
                   buttons=[("Close Application", "danger", cls.ACCEPTED)],
                   parent=parent)

    @classmethod
    def sync_failed(cls, failed_count: int, errors: list, parent=None) -> "AVADialog":
        shown = errors[:4]
        msg = f"{failed_count} scan(s) could not be synced with the portal:\n\n"
        msg += "\n".join(f"  • {e}" for e in shown)
        if len(errors) > 4:
            msg += f"\n  …and {len(errors) - 4} more."
        return cls("Sync Incomplete", msg, kind="warning",
                   buttons=[("Dismiss", "secondary", cls.ACCEPTED)], parent=parent)
