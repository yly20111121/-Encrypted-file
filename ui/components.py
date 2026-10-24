import os
from PySide6.QtWidgets import (
    QPushButton, QAbstractButton, QWidget, QHBoxLayout, QLabel, 
    QStyledItemDelegate, QStyle
)
from PySide6.QtCore import Qt, Signal, QRect, QSize
from PySide6.QtGui import QPainter, QColor, QPen, QFont, QBrush
from core.utils import format_size

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
                    bg_color = QColor("#EF4444") if self.btn_type == 'close' else QColor(255, 255, 255, 30)
                    painter.fillRect(self.rect(), bg_color)
                pen_color = QColor("#FFFFFF" if self._hovered and self.btn_type == 'close' else "#94A3B8")
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

class TaskCardDelegate(QStyledItemDelegate):
    """
    9.0.1 富卡片任务列表委托：绘制文件图标徽标、格式化大小、状态胶囊与高亮边框
    """
    def __init__(self, parent=None):
        super().__init__(parent)

    def sizeHint(self, option, index):
        return QSize(option.rect.width(), 44)

    def paint(self, painter, option, index):
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        
        rect = option.rect.adjusted(4, 2, -4, -2)
        is_selected = bool(option.state & QStyle.State_Selected)
        is_hover = bool(option.state & QStyle.State_MouseOver)
        
        # 1. 背景卡片
        if is_selected:
            bg_color = QColor(79, 70, 229, 60)
            border_color = QColor(99, 102, 241, 160)
        elif is_hover:
            bg_color = QColor(255, 255, 255, 18)
            border_color = QColor(255, 255, 255, 40)
        else:
            bg_color = QColor(255, 255, 255, 10)
            border_color = QColor(255, 255, 255, 18)
            
        painter.setBrush(QBrush(bg_color))
        painter.setPen(QPen(border_color, 1))
        painter.drawRoundedRect(rect, 6, 6)
        
        # 2. 提取文本与元数据并智能解析
        raw_text = index.data(Qt.DisplayRole) or ""
        
        # 识别动态状态与着色
        if raw_text.startswith("[处理中] ") or raw_text.startswith("[▶] "):
            status_text = "处理中"
            pill_text_color = QColor("#818CF8")
            pill_bg_color = QColor(99, 102, 241, 40)
            pill_border_color = QColor(99, 102, 241, 110)
            raw_clean = raw_text.split("] ", 1)[-1]
        elif raw_text.startswith("[成功] ") or raw_text.startswith("[✔] "):
            status_text = "成功"
            pill_text_color = QColor("#34D399")
            pill_bg_color = QColor(16, 185, 129, 35)
            pill_border_color = QColor(16, 185, 129, 90)
            raw_clean = raw_text.split("] ", 1)[-1]
        elif raw_text.startswith("[失败] ") or raw_text.startswith("[✘] "):
            status_text = "失败"
            pill_text_color = QColor("#F87171")
            pill_bg_color = QColor(239, 68, 68, 35)
            pill_border_color = QColor(239, 68, 68, 90)
            raw_clean = raw_text.split("] ", 1)[-1]
        elif raw_text.startswith("[跳过] ") or raw_text.startswith("[⏭] "):
            status_text = "跳过"
            pill_text_color = QColor("#94A3B8")
            pill_bg_color = QColor(148, 163, 184, 30)
            pill_border_color = QColor(148, 163, 184, 70)
            raw_clean = raw_text.split("] ", 1)[-1]
        else:
            status_text = "就绪"
            pill_text_color = QColor("#34D399")
            pill_bg_color = QColor(16, 185, 129, 25)
            pill_border_color = QColor(16, 185, 129, 70)
            raw_clean = raw_text

        # 剥离大小并精准提取真实扩展名
        fname = raw_clean
        size_part = ""
        if " (" in raw_clean and raw_clean.endswith(")"):
            fname, size_part = raw_clean.rsplit(" (", 1)
            size_part = size_part.rstrip(")")

        ext = os.path.splitext(fname)[1].replace('.', '').upper()[:4] or "FILE"
        
        # 3. 绘制左侧扩展名徽标
        badge_rect = QRect(rect.left() + 8, rect.top() + (rect.height() - 22) // 2, 38, 22)
        painter.setBrush(QBrush(QColor(99, 102, 241, 40)))
        painter.setPen(QPen(QColor(99, 102, 241, 100), 1))
        painter.drawRoundedRect(badge_rect, 4, 4)
        
        font = painter.font()
        font.setPointSize(9)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QColor("#A5B4FC"))
        painter.drawText(badge_rect, Qt.AlignCenter, ext)
        
        # 4. 绘制文件名与大小信息
        text_rect = QRect(badge_rect.right() + 10, rect.top() + 4, rect.width() - 130, rect.height() - 8)
        font.setPointSize(10)
        font.setBold(False)
        painter.setFont(font)
        painter.setPen(QColor("#F1F5F9"))
        disp_text = f"{fname} ({size_part})" if size_part else fname
        elided = painter.fontMetrics().elidedText(disp_text, Qt.ElideMiddle, text_rect.width())
        painter.drawText(text_rect, Qt.AlignVCenter | Qt.AlignLeft, elided)
        
        # 5. 右侧动态状态胶囊
        pill_rect = QRect(rect.right() - 68, rect.top() + (rect.height() - 20) // 2, 60, 20)
        painter.setBrush(QBrush(pill_bg_color))
        painter.setPen(QPen(pill_border_color, 1))
        painter.drawRoundedRect(pill_rect, 10, 10)
        font.setPointSize(8)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(pill_text_color)
        painter.drawText(pill_rect, Qt.AlignCenter, status_text)
        
        painter.restore()
