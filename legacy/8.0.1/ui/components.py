from PySide6.QtWidgets import QPushButton, QAbstractButton, QWidget, QHBoxLayout, QLabel
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPainter, QColor, QPen

class VectorTitleButton(QPushButton):
    def __init__(self, btn_type, parent=None):
        super().__init__(parent)
        self.btn_type = btn_type
        self.setFixedSize(36, 28)
        self.is_maximized = False
        self._hovered = False

    def enterEvent(self, event):
        self._hovered = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hovered = False
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, event):
        painter = QPainter()
        if painter.begin(self):
            try:
                painter.setRenderHint(QPainter.Antialiasing)
                if self._hovered:
                    bg_color = QColor("#EF4444") if self.btn_type == 'close' else QColor(255, 255, 255, 25)
                    painter.fillRect(self.rect(), bg_color)
                pen_color = QColor("#FFFFFF" if self._hovered and self.btn_type == 'close' else "#CBD5E1")
                pen = QPen(pen_color, 1.2)
                painter.setPen(pen)
                cx = self.width() / 2.0
                cy = self.height() / 2.0
                
                if self.btn_type == 'min':
                    painter.drawLine(cx - 5.0, cy, cx + 5.0, cy)
                elif self.btn_type == 'max':
                    if self.is_maximized:
                        painter.drawRect(cx - 3.0, cy - 5.0, 7.0, 7.0)
                        painter.drawRect(cx - 5.0, cy - 3.0, 7.0, 7.0)
                    else:
                        painter.drawRect(cx - 4.5, cy - 4.5, 9.0, 9.0)
                elif self.btn_type == 'close':
                    painter.drawLine(cx - 4.5, cy - 4.5, cx + 4.5, cy + 4.5)
                    painter.drawLine(cx + 4.5, cy - 4.5, cx - 4.5, cy + 4.5)
            finally:
                painter.end()

class CustomSwitch(QAbstractButton):
    def __init__(self, is_danger=False, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setFixedSize(40, 22)
        self.is_danger = is_danger

    def paintEvent(self, event):
        painter = QPainter()
        if painter.begin(self):
            try:
                painter.setRenderHint(QPainter.Antialiasing)
                if not self.isEnabled():
                    painter.setOpacity(0.4)
                if self.isChecked():
                    track_color = "#DC2626" if self.is_danger else "#4F46E5"
                else:
                    track_color = "rgba(255, 255, 255, 0.15)"
                painter.setBrush(QColor(track_color))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawRoundedRect(0, 0, self.width(), self.height(), self.height() / 2, self.height() / 2)
                painter.setBrush(QColor("#FFFFFF"))
                cx = self.width() - self.height() + 2 if self.isChecked() else 2
                painter.drawEllipse(cx, 2, self.height() - 4, self.height() - 4)
            finally:
                painter.end()

class CustomSwitchRow(QWidget):
    def __init__(self, text, is_danger=False, parent=None):
        super().__init__(parent)
        self.is_danger = is_danger
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        self.label = QLabel(text)
        self.switch = CustomSwitch(is_danger=self.is_danger)
        layout.addWidget(self.label)
        layout.addStretch()
        layout.addWidget(self.switch)
        
    def isChecked(self):
        return self.switch.isChecked()
        
    def setChecked(self, checked):
        self.switch.setChecked(checked)



class DropArea(QLabel):
    files_dropped = Signal(list)
    def __init__(self, text, object_name="DropZone", parent=None):
        super().__init__(text, parent)
        self.setObjectName(object_name)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setAcceptDrops(True)
        
    def dragEnterEvent(self, ev):
        if ev.mimeData().hasUrls():
            ev.acceptProposedAction()
            
    def dropEvent(self, ev):
        ev.acceptProposedAction()
        paths = [u.toLocalFile() for u in ev.mimeData().urls() if u.toLocalFile()]
        if paths:
            self.files_dropped.emit(paths)

