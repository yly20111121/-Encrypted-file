from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QGridLayout, QProgressBar
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from core.utils import format_speed, format_eta

class WorkerCard(QFrame):
    """
    单个 Worker 的现代化卡槽卡片：大卡槽、高可读性、状态胶囊与平滑进度条
    """
    def __init__(self, worker_id, parent=None):
        super().__init__(parent)
        self.worker_id = worker_id
        self.setObjectName("WorkerCard")
        self.setMinimumHeight(68)
        self.setStyleSheet("""
            QFrame#WorkerCard {
                background-color: rgba(255, 255, 255, 0.04);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 8px;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        # 顶部行：Worker 标识徽标 + 状态百分比
        header_h = QHBoxLayout()
        header_h.setContentsMargins(0, 0, 0, 0)
        self.lbl_id = QLabel(f"⚡ Worker #{worker_id+1}")
        self.lbl_id.setStyleSheet("font-size: 12px; font-weight: 600; color: #818CF8;")
        header_h.addWidget(self.lbl_id)

        header_h.addStretch()
        self.lbl_pct = QLabel("空闲")
        self.lbl_pct.setStyleSheet("font-size: 11px; font-weight: bold; color: #94A3B8;")
        header_h.addWidget(self.lbl_pct)
        layout.addLayout(header_h)

        # 中部行：当前处理文件名
        self.lbl_file = QLabel("等待任务分派...")
        self.lbl_file.setStyleSheet("font-size: 12px; color: #E2E8F0; font-weight: 500;")
        layout.addWidget(self.lbl_file)

        # 底部行：高可读性圆角彩色进度条 (8px)
        self.prog = QProgressBar()
        self.prog.setFixedHeight(8)
        self.prog.setTextVisible(False)
        self.prog.setValue(0)
        self.prog.setStyleSheet("""
            QProgressBar {
                background-color: rgba(255, 255, 255, 0.08);
                border: none;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #6366F1, stop:1 #38BDF8);
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.prog)

    def set_status(self, file_name, pct):
        if file_name and file_name != "空闲":
            self.lbl_pct.setText(f"{pct}%")
            self.lbl_pct.setStyleSheet("font-size: 11px; font-weight: bold; color: #34D399;")
            disp = file_name if len(file_name) <= 28 else file_name[:14] + "..." + file_name[-11:]
            self.lbl_file.setText(disp)
            self.lbl_file.setToolTip(file_name)
            self.prog.setValue(pct)
            self.setStyleSheet("""
                QFrame#WorkerCard {
                    background-color: rgba(99, 102, 241, 0.08);
                    border: 1px solid rgba(99, 102, 241, 0.4);
                    border-radius: 8px;
                }
            """)
        else:
            self.lbl_pct.setText("空闲")
            self.lbl_pct.setStyleSheet("font-size: 11px; font-weight: bold; color: #94A3B8;")
            self.lbl_file.setText("等待任务分派...")
            self.lbl_file.setToolTip("")
            self.prog.setValue(0)
            self.setStyleSheet("""
                QFrame#WorkerCard {
                    background-color: rgba(255, 255, 255, 0.04);
                    border: 1px solid rgba(255, 255, 255, 0.08);
                    border-radius: 8px;
                }
            """)

class PerformanceDashboard(QFrame):
    """
    9.0.1 性能与多 Worker 吞吐监控面板
    动态展示多核心流水线 Worker 咬合矩阵、全局吞吐测速仪表与智能 ETA 预测
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(8)
        
        # 顶部指标栏
        top_h = QHBoxLayout()
        self.lbl_title = QLabel("⚡ 并发多核流水线矩阵")
        self.lbl_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #818CF8; letter-spacing: 0.5px;")
        top_h.addWidget(self.lbl_title)
        
        top_h.addStretch()
        self.lbl_active = QLabel("活跃核心: 0/4")
        self.lbl_active.setStyleSheet("color: #94A3B8; font-size: 12px; margin-right: 14px;")
        top_h.addWidget(self.lbl_active)

        self.lbl_speed = QLabel("速率: 0.00 MB/s")
        self.lbl_speed.setStyleSheet("color: #38BDF8; font-weight: 700; font-size: 12px;")
        top_h.addWidget(self.lbl_speed)
        
        self.lbl_eta = QLabel("预估剩余: --:--")
        self.lbl_eta.setStyleSheet("color: #E2E8F0; font-weight: 600; font-size: 12px; margin-left: 14px;")
        top_h.addWidget(self.lbl_eta)
        layout.addLayout(top_h)
        
        # 动态 Worker 矩阵卡槽容器
        self.worker_container = QWidget()
        self.grid_layout = QGridLayout(self.worker_container)
        self.grid_layout.setContentsMargins(0, 0, 0, 0)
        self.grid_layout.setSpacing(10)
        
        self.worker_cards = []
        for i in range(8):
            card = WorkerCard(i, self.worker_container)
            card.hide()
            self.worker_cards.append(card)

        # 默认展现 4 个大卡槽
        self.set_worker_count(4)
        layout.addWidget(self.worker_container)

    def set_worker_count(self, count):
        """根据当前配置动态调整卡槽数量与排布"""
        count = max(1, min(8, count))
        for card in self.worker_cards:
            card.hide()
        for i in reversed(range(self.grid_layout.count())):
            self.grid_layout.takeAt(i)
                
        if count <= 4:
            self.setFixedHeight(135)
            for i in range(count):
                self.grid_layout.addWidget(self.worker_cards[i], 0, i)
                self.worker_cards[i].show()
        else:
            self.setFixedHeight(210)
            for i in range(count):
                row = i // 4
                col = i % 4
                self.grid_layout.addWidget(self.worker_cards[i], row, col)
                self.worker_cards[i].show()

        self.update_active_count()

    def update_metrics(self, speed_bytes_sec, eta_sec):
        self.lbl_speed.setText(f"速率: {format_speed(speed_bytes_sec)}")
        self.lbl_eta.setText(f"预估剩余: {format_eta(eta_sec)}")

    def update_worker_status(self, worker_id, file_name, progress_pct):
        if 0 <= worker_id < len(self.worker_cards):
            self.worker_cards[worker_id].set_status(file_name, progress_pct)
            self.update_active_count()

    def update_active_count(self):
        active = sum(1 for c in self.worker_cards if c.isVisible() and c.lbl_pct.text() != "空闲")
        total = sum(1 for c in self.worker_cards if c.isVisible())
        self.lbl_active.setText(f"活跃核心: {active}/{total}")

    def reset_workers(self):
        for card in self.worker_cards:
            card.set_status("空闲", 0)
        self.lbl_speed.setText("速率: 0.00 MB/s")
        self.lbl_eta.setText("预估剩余: --:--")
        self.update_active_count()
