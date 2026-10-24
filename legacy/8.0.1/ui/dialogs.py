import os
from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from core.memory import zero_bytes

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

