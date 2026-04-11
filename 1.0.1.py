import os
import struct
import threading
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                               QProgressBar, QPlainTextEdit, QMessageBox, QFileDialog)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

# ================= 核心常量配置 =================
CHUNK_SIZE = 4 * 1024 * 1024
MAGIC_NUMBER = b"SAES\x02"  # 升级魔数版本，与旧版不兼容（因头部结构改变）
SALT_SIZE = 16
BASE_NONCE_SIZE = 8

# ================= QSS 样式表 =================
DARK_QSS = """
QMainWindow { background-color: #1e1e1e; }
QWidget { color: #cccccc; font-family: "Segoe UI", "Microsoft YaHei", sans-serif; }
QLabel { font-size: 13px; }
QLineEdit {
    background-color: #2d2d2d; border: 1px solid #3d3d3d; 
    border-radius: 4px; padding: 8px; color: #ffffff; font-size: 13px;
}
QLineEdit:focus { border: 1px solid #007acc; }
QPushButton {
    background-color: #0e639c; color: white; border: none; 
    border-radius: 4px; padding: 8px 16px; font-weight: bold; font-size: 13px;
}
QPushButton:hover { background-color: #1177bb; }
QPushButton:pressed { background-color: #094771; }
QPushButton:disabled { background-color: #3d3d3d; color: #888888; }
QProgressBar {
    border: 1px solid #3d3d3d; border-radius: 4px; text-align: center; 
    background-color: #2d2d2d; color: white; height: 16px;
}
QProgressBar::chunk { background-color: #007acc; border-radius: 3px; }
QPlainTextEdit {
    background-color: #1a1a1a; border: 1px solid #2d2d2d; 
    border-radius: 4px; color: #4af626; font-family: "Consolas", monospace; font-size: 12px;
}
#DropZone {
    border: 2px dashed #3d3d3d; border-radius: 8px; background-color: #252526;
}
#DropZone[active="true"] { border: 2px dashed #007acc; background-color: #2d2d30; }
"""

# ================= 异步工作线程 =================
class CryptoWorker(QThread):
    log_sig = Signal(str)
    # 进度信号：传递 (当前字节, 总字节)
    progress_sig = Signal(int, int)
    finished_sig = Signal()
    error_sig = Signal(str)
    ask_overwrite_sig = Signal(str)

    def __init__(self, mode, file_path, password):
        super().__init__()
        self.mode = mode
        self.file_path = file_path
        self.password = password
        
        self.overwrite_event = threading.Event()
        self.overwrite_decision = False
        self._is_running = True

    def run(self):
        try:
            if self.mode == 'encrypt':
                self._encrypt()
            elif self.mode == 'decrypt':
                self._decrypt()
        except Exception as e:
            self.error_sig.emit(f"致命异常: {str(e)}")
        finally:
            self.finished_sig.emit()

    def get_key(self, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return kdf.derive(self.password.encode('utf-8'))

    def _encrypt(self):
        input_path = self.file_path
        output_path = input_path + '.enc'
        
        if os.path.exists(output_path):
            self.log_sig.emit(f"[*] 命中同名文件，等待策略确认: {output_path}")
            self.ask_overwrite_sig.emit(output_path)
            self.overwrite_event.wait()
            if not self.overwrite_decision:
                self.log_sig.emit("[-] 事务中止。")
                return

        tmp_path = output_path + '.tmp'
        total_bytes = os.path.getsize(input_path)
        
        try:
            salt = os.urandom(SALT_SIZE)
            base_nonce = os.urandom(BASE_NONCE_SIZE)
            self.log_sig.emit("[*] 派生抗 ASIC 密钥 (Scrypt)...")
            key = self.get_key(salt)
            aesgcm = AESGCM(key)
            
            # 【修复1】元数据绑定：将 8 字节总大小打包进 MAC 保护范围
            orig_name_bytes = os.path.basename(input_path).encode('utf-8')
            meta_payload = struct.pack('>Q', total_bytes) + orig_name_bytes
            
            meta_nonce = base_nonce + struct.pack('>I', 0)
            enc_meta = aesgcm.encrypt(meta_nonce, meta_payload, None)

            self.log_sig.emit(f"[*] 启动流式加密引擎: {os.path.basename(input_path)} ...")
            
            with open(input_path, 'rb') as f_in, open(tmp_path, 'wb') as f_out:
                f_out.write(MAGIC_NUMBER + salt + base_nonce + struct.pack('>H', len(enc_meta)) + enc_meta)
                
                counter = 1
                while self._is_running:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk: break
                    
                    nonce = base_nonce + struct.pack('>I', counter)
                    enc_chunk = aesgcm.encrypt(nonce, chunk, None)
                    f_out.write(struct.pack('>I', len(enc_chunk)) + enc_chunk)
                    
                    # 【修复4】进度计算修正为绝对字节数
                    current_bytes = counter * CHUNK_SIZE
                    self.progress_sig.emit(min(current_bytes, total_bytes), total_bytes)
                    counter += 1

            if self._is_running:
                os.replace(tmp_path, output_path)
                self.log_sig.emit(f"[+] 加密封存完成: {output_path}")
                self.progress_sig.emit(total_bytes, total_bytes)
            else:
                if os.path.exists(tmp_path): os.remove(tmp_path)

        except Exception as e:
            if os.path.exists(tmp_path): os.remove(tmp_path)
            raise e

    def _decrypt(self):
        input_path = self.file_path
        tmp_path = None
        
        try:
            total_file_size = os.path.getsize(input_path)
            with open(input_path, 'rb') as f_in:
                if f_in.read(len(MAGIC_NUMBER)) != MAGIC_NUMBER:
                    raise ValueError("非法的头部魔数，文件格式错误或引擎版本不匹配。")
                
                salt = f_in.read(SALT_SIZE)
                base_nonce = f_in.read(BASE_NONCE_SIZE)
                meta_len = struct.unpack('>H', f_in.read(2))[0]
                enc_meta = f_in.read(meta_len)
                data_start_pos = f_in.tell()

            self.log_sig.emit("[*] 校验协议层，派生临时密钥...")
            key = self.get_key(salt)
            aesgcm = AESGCM(key)
            
            try:
                meta_payload = aesgcm.decrypt(base_nonce + struct.pack('>I', 0), enc_meta, None)
            except InvalidTag:
                raise ValueError("访问拒绝：密钥无效或元数据遭破坏。")
                
            # 【修复1/2】拆解元数据并实施路径净化
            expected_size = struct.unpack('>Q', meta_payload[:8])[0]
            orig_name_raw = meta_payload[8:].decode('utf-8', 'replace')
            orig_name = os.path.basename(orig_name_raw.replace('\\', '/'))
            
            self.log_sig.emit(f"[+] 密钥验证通过。目标还原态: {orig_name} (体积: {expected_size} Bytes)")
            
            output_path = os.path.join(os.path.dirname(input_path), orig_name)
            if os.path.exists(output_path):
                self.log_sig.emit(f"[*] 命中同名文件，等待策略确认: {output_path}")
                self.ask_overwrite_sig.emit(output_path)
                self.overwrite_event.wait()
                if not self.overwrite_decision:
                    self.log_sig.emit("[-] 事务中止。")
                    return
                    
            tmp_path = output_path + '.tmp'
            self.log_sig.emit("[*] 执行数据块还原序列...")
            
            with open(input_path, 'rb') as f_in, open(tmp_path, 'wb') as f_out:
                f_in.seek(data_start_pos)
                counter = 1
                
                # 减去头部的偏移，计算实际载荷大小用于进度条
                payload_total = total_file_size - data_start_pos
                payload_processed = 0
                
                while self._is_running:
                    len_data = f_in.read(4)
                    if not len_data: break
                    if len(len_data) < 4: raise ValueError("EOF异常：密文尾部意外截断。")
                        
                    chunk_len = struct.unpack('>I', len_data)[0]
                    enc_chunk = f_in.read(chunk_len)
                    
                    try:
                        chunk = aesgcm.decrypt(base_nonce + struct.pack('>I', counter), enc_chunk, None)
                    except InvalidTag:
                        raise ValueError(f"完整性防线触发：区块 {counter} MAC 校验失败！")
                        
                    f_out.write(chunk)
                    
                    payload_processed += (4 + chunk_len)
                    self.progress_sig.emit(min(payload_processed, payload_total), payload_total)
                    counter += 1

            if self._is_running:
                # 【修复1】核心防线：双重校验解密后的文件体积，防御密文截断攻击
                actual_size = os.path.getsize(tmp_path)
                if actual_size != expected_size:
                    os.remove(tmp_path)
                    raise ValueError(f"一致性致命错误：期望体积 {expected_size}，实际体积 {actual_size}。拦截截断攻击，已销毁受损载荷。")

                os.replace(tmp_path, output_path)
                self.log_sig.emit(f"[+] 引擎作业完毕，无损释出至: {output_path}")
                self.progress_sig.emit(1, 1) # 强置100%
            else:
                if tmp_path and os.path.exists(tmp_path): os.remove(tmp_path)

        except Exception as e:
            if tmp_path and os.path.exists(tmp_path): os.remove(tmp_path)
            raise e

# ================= 主界面 GUI =================
class DropZoneLabel(QLabel):
    file_dropped = Signal(str)

    def __init__(self):
        super().__init__("拖拽源文件至此\n(Drop Zone)")
        self.setObjectName("DropZone")
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)
        self.setFont(QFont("Segoe UI", 16, QFont.Bold))
        self.setMinimumHeight(150)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            self.setProperty("active", "true")
            self.style().unpolish(self)
            self.style().polish(self)
            event.accept()
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self.setProperty("active", "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def dropEvent(self, event):
        self.setProperty("active", "false")
        self.style().unpolish(self)
        self.style().polish(self)
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            if os.path.isfile(file_path):
                self.file_dropped.emit(file_path)

    def mousePressEvent(self, event):
        file_path, _ = QFileDialog.getOpenFileName(self, "指定 I/O 目标")
        if file_path:
            self.file_dropped.emit(file_path)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES-GCM Core")
        self.setFixedSize(550, 480)
        self.worker = None

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        self.drop_zone = DropZoneLabel()
        self.drop_zone.file_dropped.connect(self.on_file_selected)
        main_layout.addWidget(self.drop_zone)

        self.lbl_target = QLabel("I/O 游标：未装载")
        self.lbl_target.setStyleSheet("color: #aaaaaa;")
        main_layout.addWidget(self.lbl_target)

        pwd_layout = QHBoxLayout()
        self.input_pwd = QLineEdit()
        self.input_pwd.setPlaceholderText("注入安全凭据 (Scrypt)")
        self.input_pwd.setEchoMode(QLineEdit.Password)
        pwd_layout.addWidget(self.input_pwd)
        
        self.btn_toggle_pwd = QPushButton("透视")
        self.btn_toggle_pwd.setFixedWidth(60)
        self.btn_toggle_pwd.clicked.connect(self.toggle_password_echo)
        pwd_layout.addWidget(self.btn_toggle_pwd)
        main_layout.addLayout(pwd_layout)

        action_layout = QHBoxLayout()
        self.btn_enc = QPushButton("执行封印 (Encrypt)")
        self.btn_dec = QPushButton("解除封印 (Decrypt)")
        self.btn_enc.clicked.connect(lambda: self.start_engine('encrypt'))
        self.btn_dec.clicked.connect(lambda: self.start_engine('decrypt'))
        action_layout.addWidget(self.btn_enc)
        action_layout.addWidget(self.btn_dec)
        main_layout.addLayout(action_layout)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        main_layout.addWidget(self.progress)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.appendPlainText(">> 引擎初始化就绪. 等待指令...")
        main_layout.addWidget(self.console)

        self.current_file = None

    def toggle_password_echo(self):
        if self.input_pwd.echoMode() == QLineEdit.Password:
            self.input_pwd.setEchoMode(QLineEdit.Normal)
            self.btn_toggle_pwd.setText("掩蔽")
        else:
            self.input_pwd.setEchoMode(QLineEdit.Password)
            self.btn_toggle_pwd.setText("透视")

    def on_file_selected(self, path):
        self.current_file = path
        self.lbl_target.setText(f"I/O 游标: {os.path.basename(path)}")
        self.log(f"[*] 内存地址映射: {path}")

    def log(self, text):
        self.console.appendPlainText(text)
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    def update_progress(self, current_bytes, total_bytes):
        if total_bytes > 0:
            percent = int((current_bytes / total_bytes) * 100)
            self.progress.setValue(min(max(percent, 0), 100))

    def handle_overwrite_request(self, target_path):
        reply = QMessageBox.warning(
            self, "内存覆写警告", 
            f"目标轨道已被占用:\n{os.path.basename(target_path)}\n继续操作将擦除原有数据，是否强行覆盖？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        self.worker.overwrite_decision = (reply == QMessageBox.Yes)
        self.worker.overwrite_event.set()

    def start_engine(self, mode):
        if not self.current_file:
            self.log("[-] 非法操作：I/O 游标为空。")
            return
        
        pwd = self.input_pwd.text()
        if not pwd:
            self.log("[-] 凭据拦截：安全凭据不可为空。")
            return

        self.btn_enc.setEnabled(False)
        self.btn_dec.setEnabled(False)
        self.drop_zone.setEnabled(False)
        self.progress.setValue(0)
        self.console.clear()

        self.worker = CryptoWorker(mode, self.current_file, pwd)
        self.worker.log_sig.connect(self.log)
        self.worker.progress_sig.connect(self.update_progress)
        self.worker.error_sig.connect(lambda e: self.log(f"[-] {e}"))
        self.worker.ask_overwrite_sig.connect(self.handle_overwrite_request)
        self.worker.finished_sig.connect(self.on_engine_finished)
        self.worker.start()

    def on_engine_finished(self):
        self.btn_enc.setEnabled(True)
        self.btn_dec.setEnabled(True)
        self.drop_zone.setEnabled(True)
        self.worker.deleteLater()
        self.worker = None

    # 【修复3】拦截主窗口关闭事件，优雅清理挂起的工作线程
    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.log("[!] 捕获退出指令，正在释放底层系统锁...")
            self.worker._is_running = False
            self.worker.overwrite_event.set() # 释放死锁
            self.worker.wait(1500) # 容忍 1.5 秒的安全停机时间
        event.accept()

if __name__ == "__main__":
    app = QApplication([])
    app.setStyleSheet(DARK_QSS)
    window = MainWindow()
    window.show()
    app.exec()