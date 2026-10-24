import os
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, 
    QMessageBox, QComboBox, QListWidget, QListWidgetItem
)
from core.memory import zero_bytes
from core.hardware import HardwareTokenManager

class V0FilenameDialog(QDialog):
    def __init__(self, parent, path):
        super().__init__(parent)
        self.setWindowTitle("V0 协议溯源")
        self.setFixedSize(450, 160)
        self.result_val = None
        layout = QVBoxLayout(self)
        display_name = os.path.basename(path.replace('\\\\?\\', ''))
        suggested = display_name[:-4] if display_name.lower().endswith('.enc') else display_name + ".dec"
        layout.addWidget(QLabel(f"V0 协议文件缺乏元数据：\n{display_name}\n请输入导出文件名："))
        self.line_edit = QLineEdit(suggested)
        layout.addWidget(self.line_edit)
        btn_layout = QHBoxLayout()
        btn_ok = QPushButton("确认导出")
        btn_skip = QPushButton("跳过此文件")
        btn_abort = QPushButton("中止批处理")
        btn_abort.setObjectName("BtnAbort")
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_skip)
        btn_layout.addWidget(btn_abort)
        layout.addLayout(btn_layout)
        btn_ok.clicked.connect(self.on_ok)
        btn_skip.clicked.connect(self.reject)
        btn_abort.clicked.connect(self.on_abort)
        
    def on_ok(self):
        self.result_val = self.line_edit.text().strip()
        self.accept()

    def on_abort(self):
        self.result_val = "__SYS_ABORT__"
        self.accept()

class SafePasswordInputDialog(QDialog):
    def __init__(self, title, label_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(380, 140)
        self.pwd_bytes = bytearray()
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(label_text))
        self.inp = QLineEdit()
        self.inp.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.inp)
        
        btn_box = QHBoxLayout()
        btn_ok = QPushButton("确认")
        btn_cancel = QPushButton("取消")
        btn_cancel.setObjectName("BtnSecondary")
        btn_box.addWidget(btn_ok)
        btn_box.addWidget(btn_cancel)
        layout.addLayout(btn_box)
        
        btn_ok.clicked.connect(self.on_ok)
        btn_cancel.clicked.connect(self.reject)

    def on_ok(self):
        text = self.inp.text()
        self.pwd_bytes.extend(text.encode('utf-8'))
        self.inp.clear()
        self.accept()
        
    def get_and_clear_pwd(self):
        res = bytearray(self.pwd_bytes)
        zero_bytes(self.pwd_bytes)
        self.pwd_bytes.clear()
        return res

class SinglePasswordConfirmDialog(QDialog):
    def __init__(self, expected_pwd, parent=None):
        super().__init__(parent)
        self.setWindowTitle("主口令二次核对")
        self.setFixedSize(380, 140)
        self.expected_pwd = expected_pwd
        self.is_matched = False
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("为防止误输导致粉碎丢件，请再次输入主口令核对："))
        self.inp_confirm = QLineEdit()
        self.inp_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.inp_confirm)
        
        btn_box = QHBoxLayout()
        btn_ok = QPushButton("确认激活")
        btn_cancel = QPushButton("取消")
        btn_cancel.setObjectName("BtnSecondary")
        btn_box.addWidget(btn_ok)
        btn_box.addWidget(btn_cancel)
        layout.addLayout(btn_box)
        
        btn_ok.clicked.connect(self.on_ok)
        btn_cancel.clicked.connect(self.reject)

    def on_ok(self):
        entered = self.inp_confirm.text()
        if entered != self.expected_pwd:
            QMessageBox.critical(self, "核对失败", "二次输入的口令与原口令不一致，请重新核对！")
            self.inp_confirm.clear()
            self.inp_confirm.setFocus()
            return
        self.is_matched = True
        self.accept()

class PasswordVerifyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("口令二次核对确认")
        self.setFixedSize(380, 180)
        self.verified_password = None
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("请输入批处理主口令："))
        self.inp1 = QLineEdit()
        self.inp1.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.inp1)
        
        layout.addWidget(QLabel("请再次核对口令："))
        self.inp2 = QLineEdit()
        self.inp2.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.inp2)
        
        btn_box = QHBoxLayout()
        btn_ok = QPushButton("确认激活")
        btn_cancel = QPushButton("取消")
        btn_cancel.setObjectName("BtnSecondary")
        btn_box.addWidget(btn_ok)
        btn_box.addWidget(btn_cancel)
        layout.addLayout(btn_box)
        
        btn_ok.clicked.connect(self.on_ok)
        btn_cancel.clicked.connect(self.reject)

    def on_ok(self):
        p1 = self.inp1.text()
        p2 = self.inp2.text()
        if not p1:
            QMessageBox.warning(self, "警告", "口令不能为空！")
            return
        if p1 != p2:
            QMessageBox.critical(self, "核对失败", "两次输入的口令不一致，请重新输入！")
            self.inp2.clear()
            self.inp2.setFocus()
            return
        self.verified_password = p1
        self.accept()

class HardwareKeyBindingDialog(QDialog):
    """
    9.0.1 硬件物理钥匙绑定对话框 (支持 U 盘 / USB 移动硬盘 / 移动固态)
    """
    def __init__(self, current_serial="", parent=None):
        super().__init__(parent)
        self.setWindowTitle("绑定物理硬件锁 (U 盘 / 移动硬盘)")
        self.setFixedSize(520, 270)
        self.selected_serial = current_serial
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("请选择接入的物理 U 盘 / 移动硬盘：\n(绑定后，加密文件将锁死到该设备。解密时必须插上此设备，否则直接报错阻断)"))
        
        self.combo_drives = QComboBox()
        self.lbl_status = QLabel("")
        self.lbl_status.setStyleSheet("color: #10B981; font-weight: 500; font-size: 12px;")
        
        self._refresh_drives()
        layout.addWidget(self.combo_drives)
        layout.addWidget(self.lbl_status)
        
        btn_h = QHBoxLayout()
        btn_refresh = QPushButton("重新扫描驱动器")
        btn_refresh.setObjectName("BtnSecondary")
        btn_unbind = QPushButton("解除硬件绑定")
        btn_unbind.setObjectName("BtnSecondary")
        btn_ok = QPushButton("确认绑定")
        btn_ok.setObjectName("BtnPrimary")
        
        btn_h.addWidget(btn_refresh)
        btn_h.addWidget(btn_unbind)
        btn_h.addStretch()
        btn_h.addWidget(btn_ok)
        layout.addLayout(btn_h)
        
        btn_refresh.clicked.connect(self._refresh_drives)
        btn_unbind.clicked.connect(self._on_unbind)
        btn_ok.clicked.connect(self._on_ok)

    def _refresh_drives(self):
        self.combo_drives.clear()
        drives = HardwareTokenManager.get_removable_drives()
        if not drives:
            self.combo_drives.addItem("未检测到有效存储设备，请插入 U 盘或移动硬盘后重试", "")
            self.lbl_status.setText("提示：未发现外接存储设备")
            self.lbl_status.setStyleSheet("color: #EF4444; font-size: 12px;")
            return
        
        matched_idx = -1
        for idx, d in enumerate(drives):
            text = f"[{d['drive']}] {d['label']} [{d['type_desc']}] (序列号: {d['serial']})"
            self.combo_drives.addItem(text, d['serial'])
            if d['serial'] == self.selected_serial:
                matched_idx = idx
                
        if matched_idx >= 0:
            self.combo_drives.setCurrentIndex(matched_idx)
            self.lbl_status.setText(f"✓ 当前已绑定: {self.combo_drives.currentText()}")
            self.lbl_status.setStyleSheet("color: #10B981; font-weight: 500; font-size: 12px;")
        else:
            if self.selected_serial:
                self.lbl_status.setText(f"⚠ 原绑定的设备 (序列号: {self.selected_serial}) 当前未插入！")
                self.lbl_status.setStyleSheet("color: #F59E0B; font-size: 12px;")
            else:
                self.lbl_status.setText("当前未绑定硬件锁，请在上方列表中选择设备后点击确认")
                self.lbl_status.setStyleSheet("color: #94A3B8; font-size: 12px;")

    def _on_unbind(self):
        self.selected_serial = ""
        self.accept()

    def _on_ok(self):
        data = self.combo_drives.currentData()
        if not data:
            QMessageBox.warning(self, "提示", "请选择有效的物理存储设备！")
            return
        self.selected_serial = data
        self.accept()
