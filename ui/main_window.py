import os
import sys
import time
import json
import base64
import atexit
import ctypes
from ctypes import wintypes
import gc

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QProgressBar, QPlainTextEdit, QMessageBox, QFileDialog,
    QComboBox, QDialog, QTabWidget, QListWidget, QStackedWidget, QFrame,
    QListWidgetItem, QCheckBox, QSplitter, QSlider, QApplication, QScrollArea,
    QSizeGrip
)
from PySide6.QtCore import Qt, Signal, QTimer, QPoint, QSize, QRectF
from PySide6.QtGui import QPainter, QColor, QPen, QPixmap, QPainterPath, QCursor

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption,
    load_pem_private_key, load_pem_public_key
)

from core.config import (
    CHUNK_SIZE, IO_BUFFER_SIZE, MAX_CHUNK_PLAIN_LEN, MAX_CHUNK_CIPHER_LEN,
    MAGIC_SFK_V1, MAGIC_ECC_V1, MAGIC_CHACHA_V1, MAGIC_V4, MAGIC_V3, MAGIC_V2,
    MAGIC_V1, CACHE_TIMEOUT_SECS, KEYFILE_MAX_SIZE, VOLATILE_EXTENSIONS, LOG_PATH,
    APP_DIR, logger
)
from core.memory import MemoryShield, zero_bytes
from core.utils import safe_remove, get_safe_win_path, compute_file_blake2b, force_replace
from core.settings import ConfigManager
from core.vault import CredentialVault, global_vault
from core.worker import KeyfileHasherWorker, CryptoWorker, FileScannerWorker
from ui.styles import ThemeManager
from ui.components import VectorTitleButton, CustomSwitchRow, DropArea, TaskCardDelegate
from ui.monitor_panel import PerformanceDashboard
from ui.dialogs import HardwareKeyBindingDialog
from core.compression import StreamCompression
from core.hardware import HardwareTokenManager
from ui.dialogs import (
    V0FilenameDialog, SafePasswordInputDialog, SinglePasswordConfirmDialog,
    PasswordVerifyDialog
)

class MainWindow(QMainWindow):
    def __init__(self, initial_files=None):
        super().__init__()
        self.setWindowTitle("Core Vault V9.0.1 (Enterprise Mica & Stream Compression)")
        self.setMinimumSize(1080, 750)
        self.resize(1180, 800)
        
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self._corner_radius = 12

        self.cfg = ConfigManager.load()
        self.bg_pixmap = None
        # Windows 11 原生 Mica 毛玻璃效果接入
        try:
            from ctypes import wintypes
            dwm = ctypes.windll.dwmapi
            dark_val = ctypes.c_int(1)
            dwm.DwmSetWindowAttribute(wintypes.HWND(int(self.winId())), 20, ctypes.byref(dark_val), ctypes.sizeof(dark_val))
            backdrop_val = ctypes.c_int(2) # DWMSBT_MAINWINDOW (Mica)
            dwm.DwmSetWindowAttribute(wintypes.HWND(int(self.winId())), 38, ctypes.byref(backdrop_val), ctypes.sizeof(backdrop_val))
        except Exception:
            pass
        self._cached_scaled_bg = None
        self._cached_bg_size = None
        self._cached_bg_dpr = None
        self._load_bg_pixmap()

        self._drag_pos = QPoint()
        
        self.worker = None
        self.scanner = None
        self.hasher_worker = None
        self._hasher_token = 0
        self._pending_keyfile = None
        self.active_dialog = None
        self.vault = global_vault
        
        self.task_groups = {'plain': [], 'sfk': [], 'saes': [], 'ecc': []}
        self.seen_paths = set()
        self.task_map = {}
        
        self.current_keyfile = None
        self.cached_keyfile_meta = None
        self.cached_keyfile_hash = None
        
        self.local_ecc_privkey = None
        self.local_ecc_privkey_path = None
        
        self.g_proc_bytes = 0
        self.g_total_bytes = 0
        self.g_start_time = 0
        self.is_aborting = False
        self._is_executing = False
        self._current_running_grp = None
        
        self._init_ui()
        self.setStyleSheet(ThemeManager.WINUI_QSS)
        
        self.heartbeat_timer = QTimer(self)
        self.heartbeat_timer.timeout.connect(self._heartbeat_ui)
        self.heartbeat_timer.start(1000)
        
        self._auto_load_local_ecc_keys()
        if initial_files:
            self._start_scan(initial_files)

    def _load_bg_pixmap(self):
        bg_path = self.cfg.get("bg_image", "")
        if bg_path and os.path.exists(bg_path):
            self.bg_pixmap = QPixmap(bg_path)
        else:
            self.bg_pixmap = None
        # Windows 11 原生 Mica 毛玻璃效果接入
        try:
            from ctypes import wintypes
            dwm = ctypes.windll.dwmapi
            dark_val = ctypes.c_int(1)
            dwm.DwmSetWindowAttribute(wintypes.HWND(int(self.winId())), 20, ctypes.byref(dark_val), ctypes.sizeof(dark_val))
            backdrop_val = ctypes.c_int(2) # DWMSBT_MAINWINDOW (Mica)
            dwm.DwmSetWindowAttribute(wintypes.HWND(int(self.winId())), 38, ctypes.byref(backdrop_val), ctypes.sizeof(backdrop_val))
        except Exception:
            pass
        self._cached_scaled_bg = None
        self._cached_bg_size = None
        self._cached_bg_dpr = None

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)  
        rect = self.rect()
        dpr = self.devicePixelRatioF()
        
        path = QPainterPath()
        if self.isMaximized() or self.isFullScreen():
            path.addRect(QRectF(rect))
        else:
            path.addRoundedRect(QRectF(rect), self._corner_radius, self._corner_radius)
        painter.setClipPath(path)
        if self.bg_pixmap and not self.bg_pixmap.isNull():
            cur_size = rect.size()
            if self._cached_scaled_bg is None or self._cached_bg_size != cur_size or self._cached_bg_dpr != dpr:
                phys_w = int(cur_size.width() * dpr)
                phys_h = int(cur_size.height() * dpr)
                scaled = self.bg_pixmap.scaled(
                    QSize(phys_w, phys_h), 
                    Qt.AspectRatioMode.KeepAspectRatioByExpanding, 
                    Qt.TransformationMode.SmoothTransformation
                )
                sx = (scaled.width() - phys_w) // 2
                sy = (scaled.height() - phys_h) // 2
                cropped = scaled.copy(sx, sy, phys_w, phys_h)
                cropped.setDevicePixelRatio(dpr)
                self._cached_scaled_bg = cropped
                self._cached_bg_size = cur_size
                self._cached_bg_dpr = dpr
                
            painter.drawPixmap(0, 0, self._cached_scaled_bg)
            
            try:
                op_val = float(self.cfg.get("bg_opacity", 0.45))
            except (ValueError, TypeError):
                op_val = 0.45
            dim_val = int(255 * max(0.0, min(1.0, op_val)))
            painter.fillRect(rect, QColor(11, 15, 25, dim_val))
        else:
            painter.fillRect(rect, QColor("#0B132B"))

    def nativeEvent(self, event_type, message):
        try:
            msg = wintypes.MSG.from_address(int(message))
            if msg.message == 0x0084 and not self.isMaximized():  # WM_NCHITTEST
                pos = self.mapFromGlobal(QCursor.pos())
                px, py = pos.x(), pos.y()
                w, h = self.width(), self.height()
                b = 8  # 边框感应像素宽度
                
                # 四角检测
                if px < b and py < b:
                    return True, 13  # HTTOPLEFT
                if px > w - b and py < b:
                    return True, 14  # HTTOPRIGHT
                if px < b and py > h - b:
                    return True, 16  # HTBOTTOMLEFT
                if px > w - b and py > h - b:
                    return True, 17  # HTBOTTOMRIGHT
                
                # 四边检测
                if px < b:
                    return True, 10  # HTLEFT
                if px > w - b:
                    return True, 11  # HTRIGHT
                if py < b:
                    return True, 12  # HTTOP
                if py > h - b:
                    return True, 15  # HTBOTTOM
        except Exception:
            pass
        return super().nativeEvent(event_type, message)

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.LeftButton and ev.position().y() < 48:
            self._drag_pos = ev.globalPosition().toPoint() - self.frameGeometry().topLeft()
            ev.accept()

    def mouseMoveEvent(self, ev):
        if ev.buttons() == Qt.MouseButton.LeftButton and not self._drag_pos.isNull():
            if self.isMaximized():
                cur_global_pos = ev.globalPosition().toPoint()
                max_w = self.width()
                mouse_ratio = ev.position().x() / max_w if max_w > 0 else 0.5
                self.showNormal()
                self.btn_max.is_maximized = False
                self.btn_max.update()
                normal_w = self.width()
                new_top_left_x = int(cur_global_pos.x() - normal_w * mouse_ratio)
                new_top_left_y = max(0, cur_global_pos.y() - 18)
                self.move(new_top_left_x, new_top_left_y)
                self._drag_pos = cur_global_pos - self.frameGeometry().topLeft()
            else:
                self.move(ev.globalPosition().toPoint() - self._drag_pos)
            ev.accept()

    def mouseReleaseEvent(self, ev):
        self._drag_pos = QPoint()

    def mouseDoubleClickEvent(self, ev):
        if ev.position().y() < 48:
            self._toggle_maximize()

    def _toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
            self.btn_max.is_maximized = False
        else:
            self.showMaximized()
            self.btn_max.is_maximized = True
        self.btn_max.update()

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(200)
        side_ly = QVBoxLayout(sidebar)
        side_ly.setContentsMargins(12, 16, 12, 16)
        side_ly.setSpacing(8)

        logo_h = QHBoxLayout()
        lbl_badge = QLabel("CV")
        lbl_badge.setObjectName("LogoBadge")
        lbl_badge.setFixedSize(36, 36)
        lbl_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_title = QLabel("Core Vault\n9.0.1")
        lbl_title.setStyleSheet("font-weight: 700; font-size: 13px; color: #FFFFFF;")
        logo_h.addWidget(lbl_badge)
        logo_h.addWidget(lbl_title)
        logo_h.addStretch()
        side_ly.addLayout(logo_h)
        side_ly.addSpacing(16)

        self.nav_home = QPushButton("🏠  主工作台")
        self.nav_home.setObjectName("NavBtn")
        self.nav_home.setCheckable(True)
        self.nav_home.setChecked(True)
        self.nav_home.clicked.connect(lambda: self._switch_nav(0))
        side_ly.addWidget(self.nav_home)

        self.nav_settings = QPushButton("⚙️  个性化设置")
        self.nav_settings.setObjectName("NavBtn")
        self.nav_settings.setCheckable(True)
        self.nav_settings.clicked.connect(lambda: self._switch_nav(1))
        side_ly.addWidget(self.nav_settings)

        side_ly.addStretch(1)

        self.lbl_side_user = QLabel("生产套件已就绪")
        self.lbl_side_user.setStyleSheet("color: #64748B; font-size: 11px;")
        side_ly.addWidget(self.lbl_side_user)
        main_layout.addWidget(sidebar)

        content_pane = QWidget()
        content_ly = QVBoxLayout(content_pane)
        content_ly.setContentsMargins(16, 8, 16, 16)
        content_ly.setSpacing(10)

        titlebar = QWidget()
        titlebar.setObjectName("TitleBar")
        titlebar.setFixedHeight(36)
        tb_ly = QHBoxLayout(titlebar)
        tb_ly.setContentsMargins(0, 0, 0, 0)
        tb_ly.setSpacing(4)
        
        self.lbl_view_title = QLabel("安全加解密控制中心")
        self.lbl_view_title.setStyleSheet("font-size: 14px; font-weight: 600; color: #E2E8F0;")
        tb_ly.addWidget(self.lbl_view_title)
        tb_ly.addStretch()

        self.btn_min = VectorTitleButton('min', self)
        self.btn_min.clicked.connect(self.showMinimized)
        self.btn_max = VectorTitleButton('max', self)
        self.btn_max.clicked.connect(self._toggle_maximize)
        self.btn_close = VectorTitleButton('close', self)
        self.btn_close.clicked.connect(self.close)

        tb_ly.addWidget(self.btn_min)
        tb_ly.addWidget(self.btn_max)
        tb_ly.addWidget(self.btn_close)
        content_ly.addWidget(titlebar)

        self.stack_pages = QStackedWidget()
        
        page_main = QWidget()
        page_main_ly = QVBoxLayout(page_main)
        page_main_ly.setContentsMargins(0, 0, 0, 0)
        page_main_ly.setSpacing(10)

        top_ctrl = QHBoxLayout()
        self.combo_mode = QComboBox()
        self.combo_mode.addItems(["🔒 封印加密模式 (Encrypt)", "🔓 解除封印模式 (Decrypt)"])
        self.combo_mode.currentIndexChanged.connect(self._on_mode_switched)
        self.combo_mode.setFixedHeight(36)
        top_ctrl.addWidget(QLabel("工作模式:"), 0)
        top_ctrl.addWidget(self.combo_mode, 1)
        top_ctrl.addStretch()
        page_main_ly.addLayout(top_ctrl)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: rgba(255, 255, 255, 0.05); }")

        left_card = QFrame()
        left_card.setObjectName("Card")
        left_ly = QVBoxLayout(left_card)
        left_ly.setContentsMargins(14, 14, 14, 14)
        left_ly.setSpacing(8)

        self.drop_payload = DropArea("拖入待处理文件/目录至此 (载荷投递舱)\n后台自动多线程枚举与安全分流", "DropZone")
        self.drop_payload.setFixedHeight(85)
        self.drop_payload.files_dropped.connect(self._start_scan)
        left_ly.addWidget(self.drop_payload)

        left_ly.addWidget(QLabel("任务分流队列 (同一批次内请保证对应凭据一致):"))
        self.tab_tasks = QTabWidget()
        self.list_plain = QListWidget()
        self.list_sfk = QListWidget()
        self.list_saes = QListWidget()
        self.list_ecc = QListWidget()

        self.task_card_delegate = TaskCardDelegate(self)
        self.list_plain.setItemDelegate(self.task_card_delegate)
        self.list_sfk.setItemDelegate(self.task_card_delegate)
        self.list_saes.setItemDelegate(self.task_card_delegate)
        self.list_ecc.setItemDelegate(self.task_card_delegate)

        self.tab_tasks.addTab(self.list_plain, "待加密明文 (0)")
        self.tab_tasks.addTab(self.list_sfk, "文件锁密文 (0)")
        self.tab_tasks.addTab(self.list_saes, "口令密文 (0)")
        self.tab_tasks.addTab(self.list_ecc, "非对称密文 (0)")
        self.tab_tasks.currentChanged.connect(self._on_task_tab_changed)
        left_ly.addWidget(self.tab_tasks, 1)

        queue_btns = QHBoxLayout()
        self.btn_clear_finished = QPushButton("清理已结束项")
        self.btn_clear_finished.setObjectName("BtnSecondary")
        self.btn_clear_finished.clicked.connect(self._clear_finished_tasks)
        self.btn_clear_q = QPushButton("清空当前队列")
        self.btn_clear_q.setObjectName("BtnSecondary")
        self.btn_clear_q.clicked.connect(self._clear_current_tab_queue)
        queue_btns.addWidget(self.btn_clear_finished)
        queue_btns.addWidget(self.btn_clear_q)
        left_ly.addLayout(queue_btns)
        splitter.addWidget(left_card)

        right_card = QFrame()
        right_card.setObjectName("Card")
        right_ly = QVBoxLayout(right_card)
        right_ly.setContentsMargins(14, 14, 14, 14)
        right_ly.setSpacing(8)

        right_ly.addWidget(QLabel("认证配置与凭据工作台"))
        self.stack_auth = QStackedWidget()

        self.page_auth_pwd = QWidget()
        ly_p = QVBoxLayout(self.page_auth_pwd)
        ly_p.setContentsMargins(0, 0, 0, 0)
        ly_p.setSpacing(8)
        ly_p.addWidget(QLabel("主控密码口令:"))
        self.inp_pwd = QLineEdit()
        self.inp_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.inp_pwd.setPlaceholderText("请输入密码口令")
        ly_p.addWidget(self.inp_pwd)
        pwd_tools = QHBoxLayout()
        self.btn_eye = QPushButton("透视")
        self.btn_eye.setObjectName("BtnSecondary")
        self.btn_kill_pwd = QPushButton("销毁内存凭据")
        self.btn_kill_pwd.setObjectName("BtnLock")
        pwd_tools.addWidget(self.btn_eye)
        pwd_tools.addWidget(self.btn_kill_pwd)
        ly_p.addLayout(pwd_tools)
        self.lbl_vault_state = QLabel("密码状态：未载入")
        self.lbl_vault_state.setObjectName("StatusCard")
        ly_p.addWidget(self.lbl_vault_state)
        ly_p.addStretch(1)
        self.btn_eye.clicked.connect(self._toggle_pwd)
        self.btn_kill_pwd.clicked.connect(self._manual_lock_pwd)

        self.page_auth_filekey = QWidget()
        ly_f = QVBoxLayout(self.page_auth_filekey)
        ly_f.setContentsMargins(0, 0, 0, 0)
        ly_f.setSpacing(8)

        self.drop_keyfile = DropArea("拖入文件锁至此 (上限 500MB)\n文件内容等同密钥，若内容泄露则加密失效", "KeyTargetZone")
        self.drop_keyfile.setMinimumHeight(90)
        self.drop_keyfile.files_dropped.connect(self._on_keyfile_dropped)
        ly_f.addWidget(self.drop_keyfile)

        self.lbl_keyfile_info = QLabel("当前锁：未指定")
        self.lbl_keyfile_info.setObjectName("StatusCard")
        ly_f.addWidget(self.lbl_keyfile_info)

        self.chk_backdoor = QCheckBox("启用主恢复私钥救援后门 (仅限 SFK 文件锁应急解密)")
        self.chk_backdoor.toggled.connect(self._on_backdoor_toggled)
        ly_f.addWidget(self.chk_backdoor)

        bd_h = QHBoxLayout()
        self.inp_master_pub = QLineEdit()
        self.inp_master_pub.setPlaceholderText("填入 X25519 主公钥 (PEM / Hex / Base64)")
        self.inp_master_pub.setEnabled(False)
        self.btn_paste_local_pub = QPushButton("载入本地公钥")
        self.btn_paste_local_pub.setObjectName("BtnSecondary")
        self.btn_paste_local_pub.setEnabled(False)
        self.btn_paste_local_pub.clicked.connect(self._paste_local_master_pub)
        bd_h.addWidget(self.inp_master_pub, 1)
        bd_h.addWidget(self.btn_paste_local_pub)
        ly_f.addLayout(bd_h)

        self.drop_rescue_privkey = DropArea("锁丢失？拖入主恢复私钥 (.key/.pem) 强行解密", "DropZone")
        self.drop_rescue_privkey.setFixedHeight(55)
        self.drop_rescue_privkey.files_dropped.connect(self._on_rescue_privkey_dropped)
        ly_f.addWidget(self.drop_rescue_privkey)

        self.lbl_rescue_state = QLabel("应急主私钥状态：未挂载")
        self.lbl_rescue_state.setObjectName("StatusCard")
        ly_f.addWidget(self.lbl_rescue_state)
        ly_f.addStretch(1)

        self.page_auth_ecc = QWidget()
        ly_e = QVBoxLayout(self.page_auth_ecc)
        ly_e.setContentsMargins(0, 0, 0, 0)
        ly_e.setSpacing(8)

        ecc_state_h = QHBoxLayout()
        self.lbl_ecc_state = QLabel("本地主私钥：探测中...")
        self.lbl_ecc_state.setObjectName("StatusCard")
        self.btn_mount_local_ecc = QPushButton("解密挂载")
        self.btn_mount_local_ecc.setFixedWidth(90)
        self.btn_mount_local_ecc.setVisible(False)
        self.btn_mount_local_ecc.clicked.connect(self._manual_unlock_local_ecc_key)
        ecc_state_h.addWidget(self.lbl_ecc_state, 1)
        ecc_state_h.addWidget(self.btn_mount_local_ecc)
        ly_e.addLayout(ecc_state_h)

        self.drop_ecc_key = DropArea("可拖入外部私钥/公钥文件替换", "DropZone")
        self.drop_ecc_key.setFixedHeight(75)
        self.drop_ecc_key.files_dropped.connect(self._on_ecc_key_dropped)
        ly_e.addWidget(self.drop_ecc_key)
        self.inp_peer_pub = QLineEdit()
        self.inp_peer_pub.setPlaceholderText("加密时：在此粘贴接收方公钥 (PEM / Hex / Base64)")
        ly_e.addWidget(self.inp_peer_pub)
        self.btn_gen_ecc = QPushButton("生成全新 ECC 密钥对并安全导出")
        self.btn_gen_ecc.setObjectName("BtnSecondary")
        self.btn_gen_ecc.clicked.connect(self._generate_and_export_ecc_keys)
        ly_e.addWidget(self.btn_gen_ecc)
        ly_e.addStretch(1)

        self.stack_auth.addWidget(self.page_auth_pwd)
        self.stack_auth.addWidget(self.page_auth_filekey)
        self.stack_auth.addWidget(self.page_auth_ecc)
        right_ly.addWidget(self.stack_auth, 1)

        right_ly.addWidget(QLabel("执行策略:"))
        self.chk_shred = CustomSwitchRow("物理写零粉碎原文件", is_danger=True)
        self.chk_v0 = CustomSwitchRow("兼容遗留 V0 格式")
        right_ly.addWidget(self.chk_shred)
        right_ly.addWidget(self.chk_v0)

        opt_h = QHBoxLayout()
        self.combo_strat = QComboBox()
        self.combo_strat.addItems(["更名", "覆盖", "跳过"])
        self.combo_enc_type = QComboBox()
        self.combo_enc_type.addItems(["纯文件锁 (SFK V1)", "ECC 非对称 (X25519)", "口令 V4 (AES-GCM 极速)", "口令 V4 (ChaCha20-Poly1305 高能效)", "口令 V3 (默认)"])
        self.combo_enc_type.currentIndexChanged.connect(self._on_enc_type_changed)

        opt_h.addWidget(QLabel("冲突:"))
        opt_h.addWidget(self.combo_strat)
        self.lbl_algo_label = QLabel("算法:")
        opt_h.addWidget(self.lbl_algo_label)
        opt_h.addWidget(self.combo_enc_type)
        right_ly.addLayout(opt_h)

        worker_h = QHBoxLayout()
        worker_h.addWidget(QLabel("并发:"))
        self.combo_workers = QComboBox()
        self.combo_workers.addItems(["自适应多核并发 (推荐)", "单线程 (低资源)", "2 线程并行", "4 线程并行", "8 线程强力并行"])
        self.combo_workers.currentIndexChanged.connect(self._on_workers_changed)
        worker_h.addWidget(self.combo_workers)
        self.lbl_shield_pill = QLabel("内存盾: VirtualLock")
        self.lbl_shield_pill.setStyleSheet("color: #34D399; font-size: 11px; padding: 2px 6px; background: rgba(52, 211, 153, 0.1); border-radius: 4px;")
        worker_h.addWidget(self.lbl_shield_pill)

        self.btn_hw_pill = QPushButton("🔑 硬件锁: 未绑定")
        self.btn_hw_pill.setObjectName("BtnSecondary")
        self.btn_hw_pill.setFixedHeight(26)
        self.btn_hw_pill.setStyleSheet("font-size: 11px; padding: 2px 8px;")
        self.btn_hw_pill.clicked.connect(self._open_hw_binding_dialog)
        worker_h.addWidget(self.btn_hw_pill)
        right_ly.addLayout(worker_h)

        self.btn_execute = QPushButton("立即开始处理当前分组任务")
        self.btn_execute.setFixedHeight(38)
        self.btn_execute.clicked.connect(self._execute_batch)
        self.btn_abort = QPushButton("紧急制动 (Abort)")
        self.btn_abort.setObjectName("BtnAbort")
        self.btn_abort.setFixedHeight(34)
        self.btn_abort.setEnabled(False)
        self.btn_abort.clicked.connect(self._abort_batch)
        right_ly.addWidget(self.btn_execute)
        right_ly.addWidget(self.btn_abort)

        right_scroll = QScrollArea()
        right_scroll.setWidgetResizable(True)
        right_scroll.setFrameShape(QFrame.Shape.NoFrame)
        right_scroll.setStyleSheet("background: transparent;")
        right_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        right_scroll.setWidget(right_card)
        splitter.addWidget(right_scroll)
        splitter.setSizes([540, 460])

        bot_card = QFrame()
        bot_card.setObjectName("Card")
        bot_ly = QVBoxLayout(bot_card)
        bot_ly.setContentsMargins(12, 10, 12, 10)
        bot_ly.setSpacing(8)

        self.perf_dashboard = PerformanceDashboard(self)
        bot_ly.addWidget(self.perf_dashboard)

        self.prog_bar = QProgressBar()
        self.prog_bar.setTextVisible(False)
        self.prog_bar.setFixedHeight(8)
        self.prog_bar.setStyleSheet("""
            QProgressBar {
                background-color: rgba(255, 255, 255, 0.08);
                border: none;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #4F46E5, stop:1 #06B6D4);
                border-radius: 4px;
            }
        """)
        bot_ly.addWidget(self.prog_bar)

        self.lbl_telemetry = QLabel("遥测监控：就绪 | 速率: 0.00 MB/s | ETA: 00:00")
        self.lbl_telemetry.setStyleSheet("color: #94A3B8; font-size: 11px;")
        self.lbl_telemetry.setVisible(False)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(500)
        self.log_view.setMinimumHeight(65)
        bot_ly.addWidget(self.log_view, 1)

        grip_layout = QHBoxLayout()
        grip_layout.setContentsMargins(0, 0, 0, 0)
        grip_layout.addStretch()
        self.size_grip = QSizeGrip(self)
        self.size_grip.setFixedSize(14, 14)
        self.size_grip.setStyleSheet("background: transparent;")
        grip_layout.addWidget(self.size_grip)
        bot_ly.addLayout(grip_layout)

        self.v_splitter = QSplitter(Qt.Orientation.Vertical)
        self.v_splitter.setStyleSheet("""
            QSplitter::handle:vertical {
                background-color: rgba(255, 255, 255, 0.08);
                height: 5px;
                border-radius: 2px;
                margin: 2px 0px;
            }
            QSplitter::handle:vertical:hover {
                background-color: #6366F1;
            }
        """)
        self.v_splitter.addWidget(splitter)
        self.v_splitter.addWidget(bot_card)
        self.v_splitter.setStretchFactor(0, 5)
        self.v_splitter.setStretchFactor(1, 4)
        self.v_splitter.setCollapsible(0, False)
        self.v_splitter.setCollapsible(1, False)
        page_main_ly.addWidget(self.v_splitter, 1)
        self.stack_pages.addWidget(page_main)

        page_settings = QWidget()
        page_set_ly = QVBoxLayout(page_settings)
        page_set_ly.setContentsMargins(10, 10, 10, 10)
        page_set_ly.setSpacing(14)

        set_card = QFrame()
        set_card.setObjectName("Card")
        sc_ly = QVBoxLayout(set_card)
        sc_ly.setContentsMargins(20, 20, 20, 20)
        sc_ly.setSpacing(14)

        lbl_s_head = QLabel("视觉与个性化外观设置")
        lbl_s_head.setStyleSheet("font-size: 16px; font-weight: bold; color: #FFFFFF;")
        sc_ly.addWidget(lbl_s_head)

        sc_ly.addWidget(QLabel("自定义窗口背景图 (支持 JPG / PNG / WEBP / BMP):"))
        bg_sel_h = QHBoxLayout()
        self.inp_bg_path = QLineEdit()
        self.inp_bg_path.setReadOnly(True)
        self.inp_bg_path.setPlaceholderText("留空则使用默认 WinUI 3 极深云母底色")
        self.inp_bg_path.setText(self.cfg.get("bg_image", ""))
        self.btn_browse_bg = QPushButton("浏览本地图片...")
        self.btn_browse_bg.setObjectName("BtnSecondary")
        self.btn_browse_bg.clicked.connect(self._select_bg_image)
        self.btn_clear_bg = QPushButton("清除图片")
        self.btn_clear_bg.setObjectName("BtnSecondary")
        self.btn_clear_bg.clicked.connect(self._clear_bg_image)
        bg_sel_h.addWidget(self.inp_bg_path, 1)
        bg_sel_h.addWidget(self.btn_browse_bg)
        bg_sel_h.addWidget(self.btn_clear_bg)
        sc_ly.addLayout(bg_sel_h)

        sc_ly.addSpacing(6)
        cur_op = int(self.cfg.get('bg_opacity', 0.45) * 100)
        self.lbl_opacity_desc = QLabel(f"背景暗化遮罩深度: {cur_op}% (数值越大文字对比度越高)")
        sc_ly.addWidget(self.lbl_opacity_desc)
        self.slider_opacity = QSlider(Qt.Orientation.Horizontal)
        self.slider_opacity.setRange(10, 90)
        self.slider_opacity.setValue(cur_op)
        self.slider_opacity.valueChanged.connect(self._on_opacity_slider_changed)
        self.slider_opacity.sliderReleased.connect(self._on_opacity_slider_released)
        sc_ly.addWidget(self.slider_opacity)

        sc_ly.addSpacing(16)
        lbl_hw_head = QLabel("🔑 物理硬件锁 (Hardware Token USB 绑定钥匙)")
        lbl_hw_head.setStyleSheet("font-size: 15px; font-weight: bold; color: #F59E0B;")
        sc_ly.addWidget(lbl_hw_head)

        self.lbl_hw_desc = QLabel("将特定物理 U 盘作为硬件钥匙。绑定后，加解密必须插入该设备，其只读物理序列号将注入派生密钥。")
        self.lbl_hw_desc.setStyleSheet("color: #94A3B8; font-size: 12px;")
        sc_ly.addWidget(self.lbl_hw_desc)

        self.lbl_hw_status = QLabel("当前状态: 未绑定硬件钥匙 (纯密码模式)")
        self.lbl_hw_status.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: 500;")
        sc_ly.addWidget(self.lbl_hw_status)

        hw_btn_h = QHBoxLayout()
        self.btn_bind_hw = QPushButton("绑定 / 切换物理 U 盘钥匙...")
        self.btn_bind_hw.setObjectName("BtnPrimary")
        self.btn_bind_hw.clicked.connect(self._open_hw_binding_dialog)
        self.btn_unbind_hw = QPushButton("解除硬件绑定")
        self.btn_unbind_hw.setObjectName("BtnSecondary")
        self.btn_unbind_hw.clicked.connect(self._unbind_hw_token)
        hw_btn_h.addWidget(self.btn_bind_hw)
        hw_btn_h.addWidget(self.btn_unbind_hw)
        hw_btn_h.addStretch(1)
        sc_ly.addLayout(hw_btn_h)

        sc_ly.addStretch(1)
        page_set_ly.addWidget(set_card)
        self.stack_pages.addWidget(page_settings)

        content_ly.addWidget(self.stack_pages, 1)
        main_layout.addWidget(content_pane, 1)

        self._refresh_settings_ui()
        self._on_mode_switched(0)

    def _switch_nav(self, idx):
        self.stack_pages.setCurrentIndex(idx)
        if idx == 0:
            self.nav_home.setChecked(True)
            self.nav_settings.setChecked(False)
            self.lbl_view_title.setText("安全加解密控制中心")
        else:
            self.nav_home.setChecked(False)
            self.nav_settings.setChecked(True)
            self.lbl_view_title.setText("全局系统配置与个性化")
            self._refresh_settings_ui()

    def _refresh_settings_ui(self):
        has_bg = bool(self.bg_pixmap and not self.bg_pixmap.isNull())
        self.slider_opacity.setEnabled(has_bg)
        cur_op = int(self.cfg.get('bg_opacity', 0.45) * 100)
        
        self.slider_opacity.blockSignals(True)
        self.slider_opacity.setValue(cur_op)
        self.slider_opacity.blockSignals(False)
        
        if has_bg:
            self.lbl_opacity_desc.setText(f"背景暗化遮罩深度: {cur_op}% (数值越大文字对比度越高)")
            self.lbl_opacity_desc.setStyleSheet("color: #FFFFFF;")
        else:
            self.lbl_opacity_desc.setText(f"背景暗化遮罩深度: {cur_op}% (未启用背景图，当前使用纯色底色)")
            self.lbl_opacity_desc.setStyleSheet("color: #64748B;")
        self._refresh_hw_status_ui()

    def _refresh_hw_status_ui(self):
        hw_serial = self.cfg.get("hw_token_serial", "")
        if hw_serial:
            is_present, d = HardwareTokenManager.verify_token_present(hw_serial)
            if is_present:
                status_txt = f"已绑定: [{d['drive']}] {d['label']} [{d['type_desc']}] (序列号: {hw_serial})"
                pill_txt = f"🔑 硬件锁: 已就绪 ({d['drive']} {d['label'][:6]})"
                color = "#10B981"
            else:
                status_txt = f"已绑定 (当前未插入): 序列号 {hw_serial}"
                pill_txt = f"🔑 硬件锁: 未插入"
                color = "#EF4444"
            self.lbl_hw_status.setText(f"当前状态: {status_txt}")
            self.lbl_hw_status.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: 500;")
            self.btn_hw_pill.setText(pill_txt)
            self.btn_hw_pill.setStyleSheet(f"font-size: 11px; padding: 1px 6px; color: {color}; font-weight: bold;")
        else:
            self.lbl_hw_status.setText("当前状态: 未绑定硬件钥匙 (纯密码模式)")
            self.lbl_hw_status.setStyleSheet("color: #94A3B8; font-size: 12px;")
            self.btn_hw_pill.setText("🔑 硬件锁: 未绑定")
            self.btn_hw_pill.setStyleSheet("font-size: 11px; padding: 1px 6px; color: #94A3B8;")

    def _open_hw_binding_dialog(self):
        cur_serial = self.cfg.get("hw_token_serial", "")
        dlg = HardwareKeyBindingDialog(current_serial=cur_serial, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            new_serial = dlg.selected_serial
            self.cfg["hw_token_serial"] = new_serial
            disk_cfg = ConfigManager.load()
            disk_cfg["hw_token_serial"] = new_serial
            ConfigManager.save(disk_cfg)
            self._refresh_hw_status_ui()
            if new_serial:
                is_p, d = HardwareTokenManager.verify_token_present(new_serial)
                dev_desc = f"[{d['drive']}] {d['label']}" if is_p else new_serial
                QMessageBox.information(self, "绑定成功", f"物理硬件钥匙已成功绑定！\n设备: {dev_desc}\n硬件序列号: {new_serial}\n\n使用硬件锁加密的文件将直接锁死到该设备。\n解密时必须插上此设备，否则直接报错阻断。")
                self._log(f"[*] 成功绑定物理硬件钥匙: {dev_desc} (序列号: {new_serial})")
            else:
                QMessageBox.information(self, "解绑成功", "已解除硬件锁绑定，恢复为标准模式。")
                self._log("[*] 已解除物理硬件钥匙绑定。")

    def _unbind_hw_token(self):
        if not self.cfg.get("hw_token_serial"):
            QMessageBox.information(self, "提示", "当前尚未绑定任何硬件钥匙。")
            return
        reply = QMessageBox.question(
            self, "解除绑定确认", 
            "是否解除当前绑定的物理 U 盘钥匙？\n解绑后将仅依靠主口令保护。", 
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.cfg["hw_token_serial"] = ""
            disk_cfg = ConfigManager.load()
            disk_cfg["hw_token_serial"] = ""
            ConfigManager.save(disk_cfg)
            self._refresh_hw_status_ui()
            QMessageBox.information(self, "成功", "已解除硬件绑定。")
            self._log("[*] 已解除物理硬件钥匙绑定。")

    def _select_bg_image(self):
        fp, _ = QFileDialog.getOpenFileName(self, "选择自定义背景壁纸", "", "图片文件 (*.png *.jpg *.jpeg *.bmp *.webp)")
        if fp:
            self.inp_bg_path.setText(fp)
            disk_cfg = ConfigManager.load()
            disk_cfg["bg_image"] = fp
            ConfigManager.save(disk_cfg)
            self.cfg["bg_image"] = fp
            self._load_bg_pixmap()
            self._refresh_settings_ui()
            self.update()

    def _clear_bg_image(self):
        self.inp_bg_path.clear()
        disk_cfg = ConfigManager.load()
        disk_cfg["bg_image"] = ""
        ConfigManager.save(disk_cfg)
        self.cfg["bg_image"] = ""
        self._load_bg_pixmap()
        self._refresh_settings_ui()
        self.update()

    def _on_opacity_slider_changed(self, val):
        self.cfg["bg_opacity"] = val / 100.0
        if self.bg_pixmap and not self.bg_pixmap.isNull():
            self.lbl_opacity_desc.setText(f"背景暗化遮罩深度: {val}% (数值越大文字对比度越高)")
        self.update()

    def _on_opacity_slider_released(self):
        val = self.slider_opacity.value() / 100.0
        disk_cfg = ConfigManager.load()
        disk_cfg["bg_opacity"] = val
        ConfigManager.save(disk_cfg)
        self.cfg["bg_opacity"] = val

    def _manual_unlock_local_ecc_key(self):
        if not self.local_ecc_privkey_path or not os.path.exists(self.local_ecc_privkey_path):
            QMessageBox.warning(self, "提示", "未找到本地私钥文件。")
            return
        dlg = SafePasswordInputDialog("解锁本地私钥", "请输入 master_private.key 的保护口令：", self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        pwd = dlg.get_and_clear_pwd()
        try:
            with open(self.local_ecc_privkey_path, 'rb') as f:
                content = f.read()
            priv = load_pem_private_key(content, password=bytes(pwd))
            if isinstance(priv, x25519.X25519PrivateKey):
                self.local_ecc_privkey = priv
                self.lbl_ecc_state.setText("本地私钥：已解密挂载 (master_private.key)")
                self.lbl_rescue_state.setText("应急主私钥：已就绪 (master_private.key)")
                self.btn_mount_local_ecc.setVisible(False)
                self._log("[*] 本地私钥口令验证成功，已激活挂载。")
            else:
                QMessageBox.warning(self, "格式错误", "非 X25519 类型的私钥。")
        except (MemoryError, PermissionError, OSError) as sys_err:
            QMessageBox.critical(self, "读取失败", f"系统 I/O 或权限错误: {str(sys_err)}")
        except Exception as e:
            QMessageBox.critical(self, "解锁失败", f"私钥保护口令错误或密钥文件损坏: {str(e)}")
        finally:
            zero_bytes(pwd)

    def _on_rescue_privkey_dropped(self, paths):
        if not paths: return
        kp = paths[0]
        if self.local_ecc_privkey:
            res = QMessageBox.question(self, "覆盖确认", f"当前已挂载私钥，确认替换为 {os.path.basename(kp)} 吗？")
            if res != QMessageBox.StandardButton.Yes:
                return
        try:
            with open(kp, 'rb') as f:
                content = f.read()
            priv = None
            try:
                priv = load_pem_private_key(content, password=None)
            except TypeError:
                dlg = SafePasswordInputDialog("私钥密码保护", f"{os.path.basename(kp)} 已加密，请输入口令：", self)
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    pwd = dlg.get_and_clear_pwd()
                    try:
                        priv = load_pem_private_key(content, password=bytes(pwd))
                    finally:
                        zero_bytes(pwd)
            except ValueError:
                priv = None
            if isinstance(priv, x25519.X25519PrivateKey):
                self.local_ecc_privkey = priv
                self.lbl_rescue_state.setText(f"应急主私钥：已装载 ({os.path.basename(kp)})")
                self.lbl_ecc_state.setText(f"本地私钥：已装载 ({os.path.basename(kp)})")
                self.btn_mount_local_ecc.setVisible(False)
                self._log(f"[*] 成功挂载应急主私钥: {os.path.basename(kp)}")
                return
            QMessageBox.warning(self, "格式错误", "该文件不是有效的 X25519 私钥。")
        except (MemoryError, PermissionError, OSError) as sys_err:
            QMessageBox.critical(self, "读取失败", f"系统 I/O 错误: {str(sys_err)}")
        except Exception as e:
            QMessageBox.critical(self, "加载失败", str(e))

    def _paste_local_master_pub(self):
        pub_path = os.path.join(APP_DIR, "master_public.key")
        if os.path.exists(pub_path):
            try:
                with open(pub_path, 'rb') as f:
                    pub = load_pem_public_key(f.read())
                if isinstance(pub, x25519.X25519PublicKey):
                    self.inp_master_pub.setText(pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
                    self._log("[*] 已载入本地 master_public.key 至主恢复公钥框。")
                    return
            except Exception:
                pass
        QMessageBox.information(self, "提示", "未找到有效的 master_public.key，请先在 ECC 选项卡中生成。")

    def _on_backdoor_toggled(self, checked):
        self.inp_master_pub.setEnabled(checked)
        self.btn_paste_local_pub.setEnabled(checked)

    def _on_mode_switched(self, idx):
        if idx == 0:
            self.tab_tasks.setTabEnabled(0, True)
            self.tab_tasks.setTabText(0, f"待加密明文 ({self.list_plain.count()})")
            self.tab_tasks.setCurrentIndex(0)
            self.lbl_algo_label.setVisible(True)
            self.combo_enc_type.setVisible(True)
        elif idx == 1:
            self.tab_tasks.setTabEnabled(0, False)
            self.tab_tasks.setTabText(0, f"待加密明文 [仅加密] ({self.list_plain.count()})")
            self.lbl_algo_label.setVisible(False)
            self.combo_enc_type.setVisible(False)
            selected = False
            for i, k in enumerate(['plain', 'sfk', 'saes', 'ecc']):
                if k != 'plain' and len(self.task_groups[k]) > 0:
                    self.tab_tasks.setCurrentIndex(i)
                    selected = True
                    break
            if not selected:
                self.tab_tasks.setCurrentIndex(1)
        self._refresh_auth_view()
        self._update_execute_button_state()

    def _on_task_tab_changed(self, idx):
        self._refresh_auth_view()
        self._update_execute_button_state()

    def _on_enc_type_changed(self, idx):
        if self.combo_mode.currentIndex() == 0:
            self._refresh_auth_view()

    def _on_workers_changed(self, idx):
        worker_map = {
            0: min(8, max(2, (os.cpu_count() or 4))),
            1: 1,
            2: 2,
            3: 4,
            4: 8
        }
        cnt = worker_map.get(idx, 4)
        if hasattr(self, 'perf_dashboard'):
            self.perf_dashboard.set_worker_count(cnt)

    def _update_execute_button_state(self):
        is_running = self._is_executing or (self.worker is not None and self.worker.isRunning())
        if is_running:
            return
        mode_idx = self.combo_mode.currentIndex()
        tab_idx = self.tab_tasks.currentIndex()
        if mode_idx == 0:
            if tab_idx != 0:
                self.btn_execute.setEnabled(False)
                self.btn_execute.setText("模式不匹配：请切换至解密模式处理此密文")
            else:
                self.btn_execute.setEnabled(True)
                self.btn_execute.setText("立即开始处理当前分组任务")
        else:
            if tab_idx == 0:
                self.btn_execute.setEnabled(False)
                self.btn_execute.setText("模式不匹配：请切换至加密模式处理明文")
            else:
                self.btn_execute.setEnabled(True)
                self.btn_execute.setText("立即开始处理当前分组任务")

    def _refresh_auth_view(self):
        mode_idx = self.combo_mode.currentIndex()
        if mode_idx == 0:
            enc_choice = self.combo_enc_type.currentIndex()
            if enc_choice == 0:
                self.stack_auth.setCurrentWidget(self.page_auth_filekey)
                self.drop_rescue_privkey.setVisible(False)
                self.lbl_rescue_state.setVisible(False)
                self.chk_backdoor.setVisible(True)
                self.inp_master_pub.setVisible(True)
                self.btn_paste_local_pub.setVisible(True)
            elif enc_choice == 1:
                self.stack_auth.setCurrentWidget(self.page_auth_ecc)
                self.lbl_ecc_state.setVisible(False)
                self.btn_mount_local_ecc.setVisible(False)
                self.inp_peer_pub.setVisible(True)
            else:
                self.stack_auth.setCurrentWidget(self.page_auth_pwd)
        elif mode_idx == 1:
            tab_idx = self.tab_tasks.currentIndex()
            if tab_idx == 1:
                self.stack_auth.setCurrentWidget(self.page_auth_filekey)
                self.drop_rescue_privkey.setVisible(True)
                self.lbl_rescue_state.setVisible(True)
                self.chk_backdoor.setVisible(False)
                self.inp_master_pub.setVisible(False)
                self.btn_paste_local_pub.setVisible(False)
            elif tab_idx == 2:
                self.stack_auth.setCurrentWidget(self.page_auth_pwd)
            elif tab_idx == 3:
                self.stack_auth.setCurrentWidget(self.page_auth_ecc)
                self.lbl_ecc_state.setVisible(True)
                self.btn_mount_local_ecc.setVisible(True)
                self.inp_peer_pub.setVisible(False)
            else:
                self.stack_auth.setCurrentWidget(self.page_auth_pwd)

    def _on_hasher_finished(self, worker):
        if self.hasher_worker is worker:
            self.hasher_worker = None
        try:
            worker.deleteLater()
        except RuntimeError:
            pass

        if self._pending_keyfile:
            pending_path, pending_token, pending_sz = self._pending_keyfile
            self._pending_keyfile = None
            self._start_hasher_worker(pending_path, pending_token, pending_sz)

    def _start_hasher_worker(self, path, token, sz):
        self.lbl_keyfile_info.setText(f"已选锁: {os.path.basename(path)} ({sz/(1024*1024):.2f} MB) [正在后台计算摘要...]")
        self._log(f"[*] 启动后台文件锁摘要计算 (令牌: {token}): {os.path.basename(path)}")
        worker = KeyfileHasherWorker(path, token)
        self.hasher_worker = worker
        worker.finished.connect(lambda w=worker: self._on_hasher_finished(w))
        worker.hash_ready_sig.connect(self._on_keyfile_hash_ready)
        worker.error_sig.connect(self._on_keyfile_hash_error)
        worker.start()

    def _on_keyfile_dropped(self, paths):
        if not paths: return
        kf = paths[0]
        try:
            safe_p = get_safe_win_path(kf)
            st = os.stat(safe_p)
            sz = st.st_size
            
            with open(safe_p, 'rb') as f_test:
                f_test.read(1)
                
            if sz > KEYFILE_MAX_SIZE:
                QMessageBox.critical(self, "错误", f"所选文件锁超过安全上限 (500MB)，当前为: {sz/(1024*1024):.2f} MB")
                return
            ext = os.path.splitext(kf)[1].lower()
            if ext in VOLATILE_EXTENSIONS:
                QMessageBox.warning(self, "安全警告", "选中的文件属于易变/文本配置文件，任何微小改动均会导致解密失败！建议使用静态二进制文件。")
            
            norm_new = os.path.normcase(os.path.abspath(kf))
            cur_meta = (norm_new, st.st_mtime_ns, sz)

            if self.cached_keyfile_meta == cur_meta and self.cached_keyfile_hash is not None:
                if self.hasher_worker and self.hasher_worker.isRunning():
                    self._log(f"[*] 文件锁 {os.path.basename(kf)} 正在计算摘要中，已忽略重复操作。")
                    return
                self._log(f"[*] 文件锁 {os.path.basename(kf)} 指纹与摘要完全匹配，直接命中缓存。")
                return

            self._hasher_token += 1
            cur_token = self._hasher_token
            self.current_keyfile = kf
            self.cached_keyfile_meta = None
            self.cached_keyfile_hash = None

            if self.hasher_worker and self.hasher_worker.isRunning():
                self._pending_keyfile = (kf, cur_token, sz)
                self.lbl_keyfile_info.setText(f"已选锁: {os.path.basename(kf)} [排队等待前序计算释放...]")
                self._log(f"[*] 磁盘 I/O 占用中，已将 {os.path.basename(kf)} 挂入排队队列...")
                try:
                    self.hasher_worker.hash_ready_sig.disconnect()
                    self.hasher_worker.error_sig.disconnect()
                except Exception:
                    pass
                self.hasher_worker.abort()
            else:
                self._pending_keyfile = None
                self._start_hasher_worker(kf, cur_token, sz)
        except (PermissionError, OSError) as perm_err:
            QMessageBox.critical(self, "权限拒绝", f"无法读取文件锁 (文件正被占用或无权限): {str(perm_err)}")
        except Exception as e:
            QMessageBox.critical(self, "读取失败", f"文件不可读或无权限: {str(e)}")

    def _on_keyfile_hash_ready(self, token, path, h_bytes, sz):
        if token != self._hasher_token:
            return
        try:
            safe_p = get_safe_win_path(path)
            st = os.stat(safe_p)
            self.cached_keyfile_meta = (os.path.normcase(os.path.abspath(path)), st.st_mtime_ns, st.st_size)
        except Exception:
            self.cached_keyfile_meta = (os.path.normcase(os.path.abspath(path)), 0, sz)
            
        self.current_keyfile = path
        self.cached_keyfile_hash = h_bytes
        self.lbl_keyfile_info.setText(f"已装载锁: {os.path.basename(path)} ({sz/(1024*1024):.2f} MB) [已就绪]")
        self._log(f"[*] 文件锁摘要计算完成: {os.path.basename(path)}")

    def _on_keyfile_hash_error(self, token, path, err_str):
        if token != self._hasher_token:
            return
        self.current_keyfile = None
        self.cached_keyfile_meta = None
        self.cached_keyfile_hash = None
        self.lbl_keyfile_info.setText("当前锁：读取异常")
        self._log(f"[-] 文件锁计算失败: {err_str}")
        QMessageBox.critical(self, "哈希计算失败", f"无法读取文件锁: {err_str}")

    def _on_ecc_key_dropped(self, paths):
        if not paths: return
        kp = paths[0]
        if self.local_ecc_privkey:
            res = QMessageBox.question(self, "覆盖确认", f"检测到已装载本地密钥，确认替换为 {os.path.basename(kp)} 吗？")
            if res != QMessageBox.StandardButton.Yes:
                return
        try:
            with open(kp, 'rb') as f:
                content = f.read()
            priv = None
            try:
                priv = load_pem_private_key(content, password=None)
            except TypeError:
                dlg = SafePasswordInputDialog("私钥密码保护", f"{os.path.basename(kp)} 已加密，请输入口令：", self)
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    pwd = dlg.get_and_clear_pwd()
                    try:
                        priv = load_pem_private_key(content, password=bytes(pwd))
                    finally:
                        zero_bytes(pwd)
            except ValueError:
                priv = None
            if isinstance(priv, x25519.X25519PrivateKey):
                self.local_ecc_privkey = priv
                self.lbl_ecc_state.setText(f"本地私钥：已装载 ({os.path.basename(kp)})")
                self.lbl_rescue_state.setText(f"应急主私钥：已装载 ({os.path.basename(kp)})")
                self.btn_mount_local_ecc.setVisible(False)
                self._log(f"[*] 导入本地 X25519 私钥: {os.path.basename(kp)}")
                return
            pub = load_pem_public_key(content)
            if isinstance(pub, x25519.X25519PublicKey):
                self.inp_peer_pub.setText(pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
                self._log(f"[*] 导入目标 X25519 公钥: {os.path.basename(kp)}")
                return
            QMessageBox.warning(self, "格式错误", "未在文件中解析出有效的 X25519 密钥。")
        except Exception as e:
            QMessageBox.critical(self, "加载失败", str(e))

    def _auto_load_local_ecc_keys(self):
        priv_path = os.path.join(APP_DIR, "master_private.key")
        self.local_ecc_privkey_path = priv_path
        if os.path.exists(priv_path):
            try:
                with open(priv_path, 'rb') as f:
                    content = f.read()
                try:
                    priv = load_pem_private_key(content, password=None)
                    if isinstance(priv, x25519.X25519PrivateKey):
                        self.local_ecc_privkey = priv
                        self.lbl_ecc_state.setText("本地私钥：已自动挂载 (master_private.key)")
                        self.lbl_rescue_state.setText("应急主私钥：已就绪 (master_private.key)")
                        self.btn_mount_local_ecc.setVisible(False)
                        self._log("[*] 自动挂载同级 master_private.key 作为本地/后门私钥")
                        return
                except TypeError:
                    self.local_ecc_privkey = None
                    self.lbl_ecc_state.setText("本地私钥：master_private.key (已加密)")
                    self.lbl_rescue_state.setText("应急主私钥：加密锁定中 (待解锁)")
                    self.btn_mount_local_ecc.setVisible(True)
                    self._log("[*] 检测到同级加密 master_private.key，支持按需解密挂载")
                    return
            except Exception:
                pass
        self.lbl_ecc_state.setText("本地私钥：未检测到 master_private.key")
        self.lbl_rescue_state.setText("应急主私钥：未挂载")
        self.btn_mount_local_ecc.setVisible(False)

    def _generate_and_export_ecc_keys(self):
        priv_path = os.path.join(APP_DIR, "master_private.key")
        pub_path = os.path.join(APP_DIR, "master_public.key")
        
        if os.path.exists(priv_path) or os.path.exists(pub_path):
            res = QMessageBox.warning(
                self, "覆盖警告", 
                "检测到同级目录下已存在主密钥文件！\n重新生成将备份旧密钥。是否继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if res != QMessageBox.StandardButton.Yes:
                return
            bak_suffix = f"{time.strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}.bak"
            if os.path.exists(priv_path):
                force_replace(priv_path, f"{priv_path}.{bak_suffix}")
            if os.path.exists(pub_path):
                force_replace(pub_path, f"{pub_path}.{bak_suffix}")

        dlg = QMessageBox(self)
        dlg.setWindowTitle("私钥安全导出选项")
        dlg.setText("是否为新生成的私钥设置保护口令？")
        b_pwd = dlg.addButton("设置口令保护 (推荐)", QMessageBox.ButtonRole.AcceptRole)
        b_plain = dlg.addButton("明文导出", QMessageBox.ButtonRole.DestructiveRole)
        dlg.addButton("取消", QMessageBox.ButtonRole.RejectRole)
        dlg.exec()
        
        clicked = dlg.clickedButton()
        if clicked == b_pwd:
            pwd_diag = PasswordVerifyDialog(self)
            if pwd_diag.exec() != QDialog.DialogCode.Accepted:
                return
            enc_algo = BestAvailableEncryption(pwd_diag.verified_password.encode('utf-8'))
        elif clicked == b_plain:
            c_res = QMessageBox.critical(
                self, "高危警告",
                "您选择明文导出私钥文件！任何接触到该文件的人都可以直接解密您的密文！确认继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if c_res != QMessageBox.StandardButton.Yes:
                return
            enc_algo = NoEncryption()
        else:
            return

        priv = x25519.X25519PrivateKey.generate()
        pub = priv.public_key()
        
        with open(priv_path, 'wb') as f:
            f.write(priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc_algo))
        with open(pub_path, 'wb') as f:
            f.write(pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
            
        self.local_ecc_privkey = priv
        self.local_ecc_privkey_path = priv_path
        self.lbl_ecc_state.setText("本地私钥：已就绪 (已生成至程序目录)")
        self.lbl_rescue_state.setText("应急主私钥：已就绪 (master_private.key)")
        self.btn_mount_local_ecc.setVisible(False)
        
        if not self.inp_master_pub.text().strip():
            self.inp_master_pub.setText(pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
            
        self._log("[*] 生成全新 X25519 密钥对并完成安全落盘。")
        QMessageBox.information(self, "成功", f"密钥对已生成至目录：\n{priv_path}\n{pub_path}")

    def _start_scan(self, paths):
        if self.scanner:
            self._log("[*] 正在扫描中，忽略二次重复扫描请求。")
            return
        self.scanner = FileScannerWorker(paths, allow_v0=self.chk_v0.isChecked())
        self.scanner.batch_found_sig.connect(self._on_scan_batch)
        self.scanner.log_sig.connect(self._log)
        self.scanner.finished.connect(self._on_scanner_finished)
        self.scanner.start()

    def _on_scanner_finished(self):
        if self.scanner:
            self.scanner.deleteLater()
            self.scanner = None

    def _on_scan_batch(self, batch):
        for path, sz, grp in batch:
            norm_p = os.path.normcase(path)
            if norm_p in self.seen_paths:
                continue
            self.seen_paths.add(norm_p)
            t_obj = {'path': path, 'size': sz, 'status': 'pending'}
            self.task_groups[grp].append(t_obj)
            
            item = QListWidgetItem(f"{os.path.basename(path)} ({sz/(1024*1024):.2f} MB)")
            item.setToolTip(path)
            item.setData(Qt.ItemDataRole.UserRole, path)
            
            if grp == 'plain': self.list_plain.addItem(item)
            elif grp == 'sfk': self.list_sfk.addItem(item)
            elif grp == 'saes': self.list_saes.addItem(item)
            elif grp == 'ecc': self.list_ecc.addItem(item)
            
            self.task_map[norm_p] = {"group": grp, "item": item, "task": t_obj}
            
        self.tab_tasks.setTabText(0, f"待加密明文 ({self.list_plain.count()})")
        self.tab_tasks.setTabText(1, f"文件锁密文 ({self.list_sfk.count()})")
        self.tab_tasks.setTabText(2, f"口令密文 ({self.list_saes.count()})")
        self.tab_tasks.setTabText(3, f"非对称密文 ({self.list_ecc.count()})")
        self._update_execute_button_state()

    def _clear_current_tab_queue(self):
        idx = self.tab_tasks.currentIndex()
        key_map = {0: 'plain', 1: 'sfk', 2: 'saes', 3: 'ecc'}
        grp_k = key_map[idx]
        for t in self.task_groups[grp_k]:
            norm_p = os.path.normcase(t['path'])
            self.seen_paths.discard(norm_p)
            self.task_map.pop(norm_p, None)
        self.task_groups[grp_k].clear()
        
        list_map = {0: self.list_plain, 1: self.list_sfk, 2: self.list_saes, 3: self.list_ecc}
        list_map[idx].clear()
        titles = ["待加密明文", "文件锁密文", "口令密文", "非对称密文"]
        self.tab_tasks.setTabText(idx, f"{titles[idx]} (0)")

    def _clear_finished_tasks(self):
        idx = self.tab_tasks.currentIndex()
        key_map = {0: 'plain', 1: 'sfk', 2: 'saes', 3: 'ecc'}
        grp_k = key_map[idx]
        list_map = {0: self.list_plain, 1: self.list_sfk, 2: self.list_saes, 3: self.list_ecc}
        cur_list = list_map[idx]
        titles = ["待加密明文", "文件锁密文", "口令密文", "非对称密文"]

        retained = []
        for t in self.task_groups[grp_k]:
            norm_p = os.path.normcase(t['path'])
            if t['status'] in ('success', 'skip'):
                self.seen_paths.discard(norm_p)
                self.task_map.pop(norm_p, None)
            else:
                retained.append(t)
        self.task_groups[grp_k] = retained

        for row in range(cur_list.count() - 1, -1, -1):
            item = cur_list.item(row)
            p = item.data(Qt.ItemDataRole.UserRole)
            if not any(t['path'] == p for t in retained):
                cur_list.takeItem(row)

        self.tab_tasks.setTabText(idx, f"{titles[idx]} ({cur_list.count()})")
        self._log(f"[*] 已清理标签页 [{titles[idx]}] 中的已完成/已跳过项目。")

    def _execute_batch(self):
        mode_idx = self.combo_mode.currentIndex()
        mode_str = 'encrypt' if mode_idx == 0 else 'decrypt'
        tab_idx = self.tab_tasks.currentIndex()
        key_map = {0: 'plain', 1: 'sfk', 2: 'saes', 3: 'ecc'}
        current_grp = key_map[tab_idx]
        
        current_tasks = self.task_groups[current_grp]
        eligible_tasks = [t for t in current_tasks if t['status'] in ('pending', 'error')]
        
        if not eligible_tasks:
            if current_tasks:
                QMessageBox.information(self, "提示", "当前标签页中所有任务均已成功或跳过，无需重复执行。\n如需重新处理，请清理已结束项后重新导入。")
            else:
                QMessageBox.information(self, "提示", "当前标签页队列为空。")
            return
            
        queue = [(t['path'], t['size']) for t in eligible_tasks]
        enc_type = 'saes'
        enc_ver = 3
        peer_pub = None
        master_pub = None

        # 9.0.1 物理硬件钥匙核验与阻断拦截
        hw_serial = self.cfg.get("hw_token_serial", "")
        if mode_str == 'encrypt' and hw_serial:
            is_present, drive_info = HardwareTokenManager.verify_token_present(hw_serial)
            if not is_present:
                QMessageBox.critical(
                    self, "物理硬件锁拦截",
                    f"【操作已被物理阻断】\n当前系统已绑定物理硬件钥匙 (序列号: {hw_serial})，但未检测到该 U 盘 / 移动硬盘插入！\n\n请将绑定的物理设备插入电脑后再继续执行加密，或在设置中解除硬件绑定。"
                )
                return
            self._log(f"[*] 物理硬件钥匙核验通过: [{drive_info['drive']}] {drive_info['label']} (序列号: {hw_serial})")
        
        if mode_str == 'encrypt':
            opt = self.combo_enc_type.currentIndex()
            if opt == 0:
                enc_type = 'filekey'
                if not self.current_keyfile:
                    QMessageBox.warning(self, "警告", "请先放入有效的文件锁！")
                    return
                if not self.cached_keyfile_hash:
                    QMessageBox.warning(self, "警告", "文件锁摘要正在后台异步计算中，请稍候片刻再执行！")
                    return
                if self.chk_backdoor.isChecked():
                    pub_str = self.inp_master_pub.text().strip()
                    if not pub_str:
                        QMessageBox.warning(self, "警告", "已勾选后门救援，但未填入主恢复公钥！")
                        return
                    try:
                        master_pub = self._parse_pubkey(pub_str)
                    except Exception as e:
                        QMessageBox.warning(self, "解析失败", f"主恢复公钥格式错误: {str(e)}")
                        return
            elif opt == 1:
                enc_type = 'ecc'
                pub_str = self.inp_peer_pub.text().strip()
                if not pub_str:
                    QMessageBox.warning(self, "警告", "非对称加密必须提供接收方 ECC 公钥！")
                    return
                try:
                    peer_pub = self._parse_pubkey(pub_str)
                except Exception as e:
                    QMessageBox.warning(self, "解析失败", f"公钥格式错误: {str(e)}")
                    return
            elif opt == 2:
                enc_type = 'saes'
                enc_ver = 4
            elif opt == 3:
                enc_type = 'chacha'
                enc_ver = 4
            else:
                enc_type = 'saes'
                enc_ver = 3
        elif mode_str == 'decrypt':
            if current_grp == 'sfk':
                enc_type = 'filekey'
                if not self.local_ecc_privkey and self.local_ecc_privkey_path and os.path.exists(self.local_ecc_privkey_path):
                    self._manual_unlock_local_ecc_key()
                if not self.current_keyfile and not self.local_ecc_privkey:
                    QMessageBox.warning(self, "警告", "请提供对应文件锁，或载入应急主私钥！")
                    return
            elif current_grp == 'ecc':
                enc_type = 'ecc'
                if not self.local_ecc_privkey and self.local_ecc_privkey_path and os.path.exists(self.local_ecc_privkey_path):
                    self._manual_unlock_local_ecc_key()
                if not self.local_ecc_privkey:
                    QMessageBox.warning(self, "警告", "解密非对称组必须挂载本地私钥！")
                    return
            else:
                enc_type = 'saes'

        if enc_type in ('saes', 'chacha'):
            if mode_str == 'encrypt':
                inp_val = self.inp_pwd.text()
                if inp_val:
                    dlg = SinglePasswordConfirmDialog(inp_val, self)
                    if dlg.exec() != QDialog.DialogCode.Accepted or not dlg.is_matched:
                        return
                    self.vault.unlock(inp_val, hw_token=hw_serial)
                    self.inp_pwd.clear()
                elif not self.vault.is_locked():
                    ttl_m, ttl_s = divmod(self.vault.get_ttl(), 60)
                    msg_box = QMessageBox(self)
                    msg_box.setWindowTitle("口令凭据复用确认")
                    msg_box.setText(f"检测到内存中存在有效的历史口令凭据（剩余有效时间: {ttl_m:02d}:{ttl_s:02d}）。\n是否继续使用该口令执行加密？")
                    b_reuse = msg_box.addButton("继续使用缓存口令", QMessageBox.ButtonRole.AcceptRole)
                    b_new = msg_box.addButton("设置新口令", QMessageBox.ButtonRole.ActionRole)
                    msg_box.addButton("取消", QMessageBox.ButtonRole.RejectRole)
                    msg_box.exec()
                    clicked = msg_box.clickedButton()
                    if clicked == b_new:
                        dlg = PasswordVerifyDialog(self)
                        if dlg.exec() != QDialog.DialogCode.Accepted:
                            return
                        self.vault.unlock(dlg.verified_password, hw_token=hw_serial)
                    elif clicked != b_reuse:
                        return
                else:
                    dlg = PasswordVerifyDialog(self)
                    if dlg.exec() != QDialog.DialogCode.Accepted:
                        return
                    self.vault.unlock(dlg.verified_password, hw_token=hw_serial)
            else:
                inp_val = self.inp_pwd.text()
                if inp_val:
                    self.vault.unlock(inp_val, hw_token=hw_serial)
                    self.inp_pwd.clear()
                elif self.vault.is_locked():
                    QMessageBox.warning(self, "提示", "请提供解密口令！")
                    return

        strat_map = {0: 'rename', 1: 'overwrite', 2: 'skip'}
        strat = strat_map[self.combo_strat.currentIndex()]
        
        self.g_total_bytes = sum(sz for _, sz in queue) * (2 if self.chk_shred.isChecked() and mode_str == 'encrypt' else 1)
        self.g_proc_bytes = 0
        self.g_start_time = time.monotonic()
        self.is_aborting = False
        self._is_executing = True
        self._current_running_grp = current_grp
        self.prog_bar.setValue(0)
        
        w_idx = self.combo_workers.currentIndex()
        if w_idx == 0:
            worker_count = min(8, max(2, (os.cpu_count() or 4)))
        elif w_idx == 1:
            worker_count = 1
        elif w_idx == 2:
            worker_count = 2
        elif w_idx == 3:
            worker_count = 4
        elif w_idx == 4:
            worker_count = 8
        else:
            worker_count = 2

        self.perf_dashboard.set_worker_count(min(worker_count, len(queue)))

        self.worker = CryptoWorker(
            mode=mode_str,
            enc_type=enc_type,
            enc_ver=enc_ver,
            queue=queue,
            vault=self.vault,
            shred=self.chk_shred.isChecked(),
            overwrite_strat=strat,
            allow_v0=self.chk_v0.isChecked(),
            keyfile_path=self.current_keyfile,
            peer_public_key=peer_pub,
            my_private_key=self.local_ecc_privkey if mode_str == 'decrypt' else None,
            enable_backdoor=self.chk_backdoor.isChecked() if (mode_str == 'encrypt' and enc_type == 'filekey') else False,
            master_pubkey=master_pub,
            master_privkey=self.local_ecc_privkey if mode_str == 'decrypt' else None,
            precomputed_lock_hash=self.cached_keyfile_hash,
            max_workers=worker_count,
            hw_serial=hw_serial if mode_str == 'encrypt' else None
        )
        
        self.worker.worker_status_sig.connect(self.perf_dashboard.update_worker_status)
        self.worker.throughput_sig.connect(self.perf_dashboard.update_metrics)
        self.worker.file_start_sig.connect(self._on_file_started)
        self.worker.log_sig.connect(self._log)
        self.worker.progress_sig.connect(self._on_worker_prog)
        self.worker.file_done_sig.connect(self._on_file_done)
        self.worker.ask_overwrite_sig.connect(self._on_ask_overwrite)
        self.worker.ask_filename_sig.connect(self._on_ask_filename)
        self.worker.heartbeat_sig.connect(self._on_worker_heartbeat)
        self.worker.finished.connect(self._on_batch_finished)
        
        self._set_ui_busy(True)
        self._log(f"[*] 启动批处理任务流水线：{len(queue)} 项 [算法模型: {enc_type}]")
        self.worker.start()

    def _parse_pubkey(self, text):
        clean_text = text.strip()
        if clean_text.startswith("0x") or clean_text.startswith("0X"):
            clean_text = clean_text[2:]
        pub = None
        if clean_text.startswith("-----BEGIN"):
            try:
                candidate = load_pem_public_key(clean_text.encode('utf-8'))
                if isinstance(candidate, x25519.X25519PublicKey):
                    pub = candidate
            except Exception:
                pass
        if not pub:
            try:
                b = bytes.fromhex(clean_text)
                if len(b) == 32:
                    pub = x25519.X25519PublicKey.from_public_bytes(b)
            except Exception:
                pass
        if not pub:
            try:
                padded = clean_text + "=" * ((4 - len(clean_text) % 4) % 4)
                b = base64.b64decode(padded, validate=True)
                if len(b) == 32:
                    pub = x25519.X25519PublicKey.from_public_bytes(b)
            except Exception:
                pass
        if not pub:
            raise ValueError("无效公钥格式，仅支持标准 PEM、64位Hex 或 32字节 Base64 编码")
            
        try:
            dummy_priv = x25519.X25519PrivateKey.generate()
            dummy_priv.exchange(pub)
        except Exception as e:
            raise ValueError(f"公钥曲线点校验失败 (低阶点或非有效点): {str(e)}")
            
        return pub

    def _on_worker_heartbeat(self):
        self.vault.heartbeat()
        hw_serial = getattr(self.worker, 'hw_serial', None) or self.cfg.get("hw_token_serial", "")
        if hw_serial:
            is_present, _ = HardwareTokenManager.verify_token_present(hw_serial)
            if not is_present:
                self.vault.lock()
                self._log("[!] 【硬件物理安全警报】检测到绑定的硬件钥匙设备已被拔出！已即刻销毁内存密钥并紧急制动！")
                if self.worker:
                    self.worker.abort()

    def _on_worker_prog(self, inc):
        self.g_proc_bytes += inc
        elapsed = time.monotonic() - self.g_start_time
        speed = self.g_proc_bytes / elapsed if elapsed > 0 else 0
        if self.g_total_bytes > 0:
            pct = min(100, max(0, int((self.g_proc_bytes * 100) // self.g_total_bytes)))
            if self.prog_bar.value() != pct:
                self.prog_bar.setValue(pct)
            rem = max(0, self.g_total_bytes - self.g_proc_bytes)
            eta = rem / speed if speed > 0 else 0
            self.lbl_telemetry.setText(f"速率: {speed/(1024*1024):.2f} MB/s | ETA: {int(eta//60):02d}:{int(eta%60):02d} | 进度: {pct}%")
            self.perf_dashboard.update_metrics(speed, int(eta))

    def _update_item_ui_fast(self, entry, status):
        status_decor = {
            "running": ("[处理中] ", "#818CF8"),
            "success": ("[成功] ", "#34D399"),
            "skip": ("[跳过] ", "#94A3B8"),
            "error": ("[失败] ", "#F87171"),
            "pending": ("", "#E2E8F0")
        }
        prefix, color_hex = status_decor.get(status, ("", "#E2E8F0"))
        item = entry["item"]
        base_name = os.path.basename(entry["task"]["path"])
        item.setText(f"{prefix}{base_name}")
        item.setForeground(QColor(color_hex))

    def _on_file_started(self, path):
        entry = self.task_map.get(os.path.normcase(path))
        if entry:
            entry["task"]["status"] = 'running'
            self._update_item_ui_fast(entry, 'running')

    def _on_file_done(self, path, status, work_tuple):
        expected_work, reported_work = work_tuple
        remaining_work = expected_work - reported_work
        if remaining_work > 0:
            self._on_worker_prog(remaining_work)

        entry = self.task_map.get(os.path.normcase(path))
        if entry:
            entry["task"]["status"] = status
            self._update_item_ui_fast(entry, status)

    def _on_batch_finished(self):
        self._is_executing = False
        self._set_ui_busy(False)
        self.perf_dashboard.reset_workers()
        
        target_grp = self._current_running_grp
        current_tasks = self.task_groups.get(target_grp, []) if target_grp else []
        
        for t in current_tasks:
            if t['status'] == 'running':
                t['status'] = 'error'
                entry = self.task_map.get(os.path.normcase(t['path']))
                if entry:
                    self._update_item_ui_fast(entry, 'error')

        has_abnormal = any(t['status'] in ('error', 'pending') for t in current_tasks)

        if not self.is_aborting:
            if has_abnormal:
                self.lbl_telemetry.setText("遥测监控：批处理因异常中断/存在未完项目")
                self._log("[-] 当前批次处理中断，存在失败或未完成任务。")
                if self.combo_mode.currentIndex() == 1:
                    self.vault.lock()
                    self._log("[*] 解密未全部成功，已安全重置口令缓存，避免错误凭据影响后续重试。")
            else:
                self.prog_bar.setValue(100)
                self.lbl_telemetry.setText("遥测监控：批处理完结")
                self._log("[*] 当前批次全部处理完毕。")
        else:
            self.lbl_telemetry.setText("遥测监控：任务已紧急中止")
            self._log("[!] 任务批处理已在制动后退出。")
            
        self.g_proc_bytes = 0
        self.g_total_bytes = 0
        self._current_running_grp = None
        
        if self.worker:
            self.worker.deleteLater()
            self.worker = None
        self._update_execute_button_state()

    def _abort_batch(self):
        if self.is_aborting:
            return
        self.is_aborting = True
        self.btn_abort.setEnabled(False)
        self._pending_keyfile = None
        self._log("[!] 触发系统紧急制动信号...")
        
        if self.scanner:
            self.scanner.abort()
            self.scanner.wait(1000)
            
        if self.hasher_worker and self.hasher_worker.isRunning():
            self.hasher_worker.abort()
            
        if self.worker:
            self.worker._is_running = False
            self.worker.overwrite_event.set()
            self.worker.filename_event.set()
            
        if self.active_dialog:
            dlg = self.active_dialog
            self.active_dialog = None
            try:
                dlg.reject()
                dlg.deleteLater()
            except Exception:
                pass

    def _on_ask_overwrite(self, path, inplace):
        w = self.worker
        if not w or not w._is_running:
            return
        dialog = QMessageBox(self)
        self.active_dialog = dialog
        dialog.setWindowTitle("目标文件冲突")
        dialog.setText(f"目标文件已存在：\n{os.path.basename(path)}")
        b_over = dialog.addButton("覆盖", QMessageBox.ButtonRole.AcceptRole)
        b_ren = dialog.addButton("更名", QMessageBox.ButtonRole.AcceptRole)
        b_skip = dialog.addButton("跳过", QMessageBox.ButtonRole.RejectRole)
        dialog.exec()
        clicked = dialog.clickedButton()
        if self.active_dialog is dialog:
            self.active_dialog = None
        dialog.deleteLater()
        
        if w and w is self.worker and w._is_running:
            res = clicked
            w.overwrite_decision = True if res == b_over else ('rename' if res == b_ren else False)
            w.overwrite_event.set()

    def _on_ask_filename(self, path):
        w = self.worker
        if not w or not w._is_running:
            return
        dlg = V0FilenameDialog(self, path)
        self.active_dialog = dlg
        dlg.exec()
        val = dlg.result_val
        if self.active_dialog is dlg:
            self.active_dialog = None
        dlg.deleteLater()
        
        if w and w is self.worker and w._is_running:
            w.filename_decision = val
            w.filename_event.set()

    def _set_ui_busy(self, busy):
        self.btn_execute.setEnabled(not busy)
        self.btn_abort.setEnabled(busy)
        self.combo_mode.setEnabled(not busy)
        self.tab_tasks.setEnabled(not busy)
        self.drop_payload.setEnabled(not busy)
        self.btn_clear_q.setEnabled(not busy)
        self.btn_clear_finished.setEnabled(not busy)
        self.chk_shred.setEnabled(not busy)
        self.chk_v0.setEnabled(not busy)
        self.combo_strat.setEnabled(not busy)
        self.combo_enc_type.setEnabled(not busy)
        self.combo_workers.setEnabled(not busy)
        self.drop_keyfile.setEnabled(not busy)
        self.drop_ecc_key.setEnabled(not busy)
        self.btn_gen_ecc.setEnabled(not busy)
        self.inp_pwd.setEnabled(not busy)
        self.btn_eye.setEnabled(not busy)
        self.btn_kill_pwd.setEnabled(not busy)
        self.chk_backdoor.setEnabled(not busy)
        self.drop_rescue_privkey.setEnabled(not busy)
        self.inp_peer_pub.setEnabled(not busy)
        self.btn_mount_local_ecc.setEnabled(not busy)
        if busy:
            self.inp_master_pub.setEnabled(False)
            self.btn_paste_local_pub.setEnabled(False)
        else:
            self.inp_master_pub.setEnabled(self.chk_backdoor.isChecked())
            self.btn_paste_local_pub.setEnabled(self.chk_backdoor.isChecked())
            self._update_execute_button_state()

    def _manual_lock_pwd(self):
        self.vault.lock()
        self.lbl_vault_state.setText("密码状态：已销毁")
        self._log("[!] 内存中的主控口令已被彻底擦除。")

    def _toggle_pwd(self):
        if self.inp_pwd.echoMode() == QLineEdit.EchoMode.Password:
            self.inp_pwd.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_eye.setText("掩蔽")
        else:
            self.inp_pwd.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_eye.setText("透视")

    def _heartbeat_ui(self):
        try:
            if self.vault.is_locked():
                self.lbl_vault_state.setText("密码状态：已锁定")
            else:
                m, s = divmod(self.vault.get_ttl(), 60)
                self.lbl_vault_state.setText(f"密码状态：活跃中 ({m:02d}:{s:02d})")
        except Exception:
            pass

    def _log(self, txt):
        ts = time.strftime('%H:%M:%S')
        log_line = f"[{ts}] {txt}"
        logger.info(txt)
        self.log_view.appendPlainText(log_line)

    def closeEvent(self, ev):
        is_crypto_running = bool(self.worker and self.worker.isRunning())
        is_scanner_running = bool(self.scanner and self.scanner.isRunning())
        is_hasher_running = bool(self.hasher_worker and self.hasher_worker.isRunning())

        if is_crypto_running or is_scanner_running or is_hasher_running:
            reply = QMessageBox.question(
                self,
                "退出确认",
                "当前后台有正在执行的任务（加解密、目录扫描或文件锁哈希计算）。\n关闭窗口将中止所有正在进行的任务，是否确认退出？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                ev.ignore()
                return

        self.vault.lock()
        self._pending_keyfile = None

        if self.active_dialog:
            dlg = self.active_dialog
            self.active_dialog = None
            try:
                dlg.reject()
                dlg.deleteLater()
            except Exception:
                pass

        if self.scanner:
            self.scanner.abort()
            self.scanner.wait(2000)

        if self.hasher_worker and self.hasher_worker.isRunning():
            self.hasher_worker.abort()
            if not self.hasher_worker.wait(1000):
                try:
                    self.hasher_worker.hash_ready_sig.disconnect()
                    self.hasher_worker.error_sig.disconnect()
                except Exception:
                    pass
                self.hasher_worker.terminate()
                self.hasher_worker.wait(500)

        if self.worker and self.worker.isRunning():
            self.worker._is_running = False
            self.worker.overwrite_event.set()
            self.worker.filename_event.set()
            if not self.worker.wait(3000):
                force_reply = QMessageBox.question(
                    self,
                    "强制终止确认",
                    "后台加密工作线程未能及时响应停止信号（可能处于底层 I/O 阻塞）。\n强制终止可能造成文件损坏或残留未粉碎碎片，是否强制退出？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if force_reply == QMessageBox.StandardButton.Yes:
                    self.worker.terminate()
                    self.worker.wait(1000)
                else:
                    ev.ignore()
                    return

        ev.accept()

