import os
import sys
import struct
import threading
import time
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                               QProgressBar, QPlainTextEdit, QMessageBox, QFileDialog)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

# ================= 核心常量配置 =================
CHUNK_SIZE = 4 * 1024 * 1024
MAGIC_NUMBER = b"SAES\x03"
SALT_SIZE = 16
BASE_NONCE_SIZE = 8

SCRYPT_N = 2**17  
SCRYPT_R = 8
SCRYPT_P = 1
CACHE_TIMEOUT_SECS = 900  

# ================= 内存凭据保险箱 =================
class CredentialVault:
    def __init__(self, timeout=CACHE_TIMEOUT_SECS):
        self._pwd_bytes = bytearray()
        self.timeout = timeout
        self.expiry_time = 0

    def is_locked(self):
        return time.time() > self.expiry_time or len(self._pwd_bytes) == 0

    def lock(self):
        for i in range(len(self._pwd_bytes)):
            self._pwd_bytes[i] = 0
        self._pwd_bytes.clear()
        self.expiry_time = 0

    def unlock(self, pwd_str):
        self.lock() 
        self._pwd_bytes.extend(pwd_str.encode('utf-8'))
        self.expiry_time = time.time() + self.timeout

    def get_password_bytes(self):
        if self.is_locked():
            self.lock() 
            return None
        self.expiry_time = time.time() + self.timeout
        return bytes(self._pwd_bytes)

    def get_ttl(self):
        if self.is_locked(): return 0
        return max(0, int(self.expiry_time - time.time()))

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
#BtnLock { background-color: #8a2be2; }
#BtnLock:hover { background-color: #9932cc; }
#BtnAbort { background-color: #c53030; }
#BtnAbort:hover { background-color: #e53e3e; }
#BtnAbort:pressed { background-color: #9b2c2c; }
QProgressBar {
    border: 1px solid #3d3d3d; border-radius: 4px; text-align: center; 
    background-color: #2d2d2d; color: white; height: 16px;
}
QProgressBar::chunk { background-color: #007acc; border-radius: 3px; }
QPlainTextEdit {
    background-color: #1a1a1a; border: 1px solid #2d2d2d; 
    border-radius: 4px; color: #4af626; font-family: "Consolas", monospace; font-size: 12px;
}
#DropZone { border: 2px dashed #3d3d3d; border-radius: 8px; background-color: #252526; }
#DropZone[active="true"] { border: 2px dashed #007acc; background-color: #2d2d30; }
"""

# ================= 异步工作线程 =================
class CryptoWorker(QThread):
    log_sig = Signal(str)
    progress_sig = Signal(int, int)
    finished_sig = Signal(bool)
    error_sig = Signal(str)
    ask_overwrite_sig = Signal(str)

    def __init__(self, mode, file_path, pwd_bytes):
        super().__init__()
        self.mode = mode
        self.file_path = file_path
        self.pwd_bytes = pwd_bytes  
        
        self.overwrite_event = threading.Event()
        self.overwrite_decision = False
        self._is_running = True
        self._last_percent = -1

    def run(self):
        success = False
        try:
            if self.mode == 'encrypt':
                self._encrypt()
            elif self.mode == 'decrypt':
                self._decrypt()
            if self._is_running:
                success = True
        except Exception as e:
            self.error_sig.emit(f"异常阻断: {str(e)}")
        finally:
            if hasattr(self, 'key'): del self.key
            if hasattr(self, 'aesgcm'): del self.aesgcm
            self.pwd_bytes = b""
            self.finished_sig.emit(success)

    def emit_progress_throttled(self, current, total):
        if total == 0:
            self.progress_sig.emit(1, 1) 
            return
        if total < 0: return
        
        percent = int((current / total) * 100)
        if percent > self._last_percent or current == total:
            self.progress_sig.emit(current, total)
            self._last_percent = percent

    def safe_replace(self, src, dst):
        max_retries = 4
        for attempt in range(max_retries):
            try:
                os.replace(src, dst)
                return
            except PermissionError as e:
                if attempt == max_retries - 1: raise e
                time.sleep(0.5 * (2 ** attempt))

    def _encrypt(self):
        input_path = self.file_path
        output_path = input_path + '.enc'
        tmp_path = None  
        
        if os.path.exists(output_path):
            self.log_sig.emit(f"[*] 命中同名文件，等待策略确认: {output_path}")
            self.ask_overwrite_sig.emit(output_path)
            self.overwrite_event.wait()
            if not self.overwrite_decision:
                self.log_sig.emit("[-] 事务中止。")
                self._is_running = False
                return

        try:
            tmp_path = output_path + '.tmp'
            total_bytes = os.path.getsize(input_path)
            
            salt = os.urandom(SALT_SIZE)
            base_nonce = os.urandom(BASE_NONCE_SIZE)
            
            self.progress_sig.emit(-1, -1)
            self.log_sig.emit("[*] 派生抗 ASIC 密钥...")
            kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
            self.key = kdf.derive(self.pwd_bytes)
            self.aesgcm = AESGCM(self.key)
            
            orig_name_bytes = os.path.basename(input_path).encode('utf-8')
            meta_payload = struct.pack('>Q', total_bytes) + orig_name_bytes
            header = MAGIC_NUMBER + salt + base_nonce
            
            meta_nonce = base_nonce + struct.pack('>I', 0)
            enc_meta = self.aesgcm.encrypt(meta_nonce, meta_payload, associated_data=header)

            self.log_sig.emit(f"[*] 启动流式加密: {os.path.basename(input_path)}")
            self.progress_sig.emit(0, total_bytes)
            
            with open(input_path, 'rb') as f_in, open(tmp_path, 'wb') as f_out:
                f_out.write(header + struct.pack('>H', len(enc_meta)) + enc_meta)
                counter = 1
                while self._is_running:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk: break
                    
                    nonce = base_nonce + struct.pack('>I', counter)
                    enc_chunk = self.aesgcm.encrypt(nonce, chunk, None)
                    f_out.write(struct.pack('>I', len(enc_chunk)) + enc_chunk)
                    
                    current_bytes = min(counter * CHUNK_SIZE, total_bytes)
                    self.emit_progress_throttled(current_bytes, total_bytes)
                    counter += 1

            if self._is_running:
                self.safe_replace(tmp_path, output_path)
                self.log_sig.emit(f"[+] 封印完成: {output_path}")
            else:
                self.log_sig.emit("[-] 操作已强制阻断，清理临时载荷。")
                if tmp_path and os.path.exists(tmp_path): os.remove(tmp_path)
        except Exception as e:
            if tmp_path and os.path.exists(tmp_path): os.remove(tmp_path)
            raise e

    def _decrypt(self):
        input_path = self.file_path
        tmp_path = None 
        
        try:
            total_file_size = os.path.getsize(input_path)
            with open(input_path, 'rb') as f_in:
                if f_in.read(len(MAGIC_NUMBER)) != MAGIC_NUMBER:
                    raise ValueError("非法的头部魔数，引擎版本不匹配。")
                
                salt = f_in.read(SALT_SIZE)
                base_nonce = f_in.read(BASE_NONCE_SIZE)
                meta_len = struct.unpack('>H', f_in.read(2))[0]
                enc_meta = f_in.read(meta_len)
                data_start_pos = f_in.tell()

            self.progress_sig.emit(-1, -1)
            self.log_sig.emit("[*] 派生临时密钥校验协议...")
            kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
            self.key = kdf.derive(self.pwd_bytes)
            self.aesgcm = AESGCM(self.key)
            
            try:
                header = MAGIC_NUMBER + salt + base_nonce
                meta_payload = self.aesgcm.decrypt(base_nonce + struct.pack('>I', 0), enc_meta, associated_data=header)
            except InvalidTag:
                raise ValueError("访问拒绝：AAD 校验失败，文件头受损或密钥错误。")
                
            expected_size = struct.unpack('>Q', meta_payload[:8])[0]
            orig_name_raw = meta_payload[8:].decode('utf-8', 'replace')
            orig_name = os.path.basename(orig_name_raw.replace('\\', '/'))
            
            output_path = os.path.join(os.path.dirname(input_path), orig_name)
            if os.path.exists(output_path):
                self.log_sig.emit(f"[*] 命中同名文件: {output_path}")
                self.ask_overwrite_sig.emit(output_path)
                self.overwrite_event.wait()
                if not self.overwrite_decision:
                    self.log_sig.emit("[-] 中止。")
                    self._is_running = False
                    return
                    
            tmp_path = output_path + '.tmp'
            self.progress_sig.emit(0, expected_size)
            
            with open(input_path, 'rb') as f_in, open(tmp_path, 'wb') as f_out:
                f_in.seek(data_start_pos)
                counter = 1
                payload_processed = 0
                
                while self._is_running:
                    len_data = f_in.read(4)
                    if not len_data: break
                    if len(len_data) < 4: raise ValueError("EOF异常：密文截断。")
                        
                    chunk_len = struct.unpack('>I', len_data)[0]
                    
                    if chunk_len > CHUNK_SIZE + 16:
                        raise ValueError(f"严重防线触发：非法区块尺寸 ({chunk_len}B)。拦截内存耗尽攻击。")
                        
                    enc_chunk = f_in.read(chunk_len)
                    try:
                        chunk = self.aesgcm.decrypt(base_nonce + struct.pack('>I', counter), enc_chunk, None)
                    except InvalidTag:
                        raise ValueError(f"完整性防线触发：区块 {counter} MAC 校验失败！")
                        
                    f_out.write(chunk)
                    payload_processed += len(chunk)
                    self.emit_progress_throttled(payload_processed, expected_size)
                    counter += 1

            if self._is_running:
                if os.path.getsize(tmp_path) != expected_size:
                    os.remove(tmp_path)
                    raise ValueError("一致性致命错误，拦截受损载荷。")
                self.safe_replace(tmp_path, output_path)
                self.log_sig.emit(f"[+] 释出至: {output_path}")
            else:
                self.log_sig.emit("[-] 操作已强制阻断，清理受损还原文件。")
                if tmp_path and os.path.exists(tmp_path): os.remove(tmp_path)
        except Exception as e:
            if tmp_path and os.path.exists(tmp_path): os.remove(tmp_path)
            raise e

# ================= 主界面 GUI =================
class DropZoneLabel(QLabel):
    files_dropped = Signal(list)
    def __init__(self):
        super().__init__("拖拽文件/目录至此进入队列\n(Drop Zone)")
        self.setObjectName("DropZone")
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)
        self.setFont(QFont("Segoe UI", 16, QFont.Bold))
        self.setMinimumHeight(120)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            self.setProperty("active", "true")
            self.style().unpolish(self)
            self.style().polish(self)
            event.accept()
        else: event.ignore()

    def dragLeaveEvent(self, event):
        self.setProperty("active", "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def dropEvent(self, event):
        self.setProperty("active", "false")
        self.style().unpolish(self)
        self.style().polish(self)
        urls = event.mimeData().urls()
        if urls: self.files_dropped.emit([u.toLocalFile() for u in urls])

class MainWindow(QMainWindow):
    def __init__(self, initial_files=None):
        super().__init__()
        self.setWindowTitle("AES-GCM Core V3.2 (Production Ready)")
        self.setFixedSize(580, 560)
        
        self.worker = None
        self.task_queue = []
        self.current_mode = None
        self.vault = CredentialVault()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)

        self.drop_zone = DropZoneLabel()
        self.drop_zone.files_dropped.connect(self.on_files_added)
        main_layout.addWidget(self.drop_zone)

        self.lbl_queue = QLabel("任务队列：空闲")
        self.lbl_queue.setStyleSheet("color: #007acc; font-weight: bold;")
        main_layout.addWidget(self.lbl_queue)

        pwd_layout = QHBoxLayout()
        self.input_pwd = QLineEdit()
        self.input_pwd.setPlaceholderText("在此注入凭据 (存入保险箱后将自动清空)")
        self.input_pwd.setEchoMode(QLineEdit.Password)
        pwd_layout.addWidget(self.input_pwd)
        
        self.btn_toggle_pwd = QPushButton("透视")
        self.btn_toggle_pwd.setFixedWidth(60)
        self.btn_toggle_pwd.clicked.connect(self.toggle_password_echo)
        pwd_layout.addWidget(self.btn_toggle_pwd)
        
        self.btn_lock = QPushButton("主动销毁")
        self.btn_lock.setObjectName("BtnLock")
        self.btn_lock.setFixedWidth(80)
        self.btn_lock.clicked.connect(self.manual_lock_vault)
        pwd_layout.addWidget(self.btn_lock)
        main_layout.addLayout(pwd_layout)

        self.lbl_vault = QLabel("🔒 保险箱状态：未装载凭据")
        self.lbl_vault.setStyleSheet("color: #aaaaaa;")
        main_layout.addWidget(self.lbl_vault)

        action_layout = QHBoxLayout()
        self.btn_enc = QPushButton("封印队列")
        self.btn_dec = QPushButton("解除封印")
        self.btn_abort = QPushButton("紧急制动 (Abort)") # 【注入新组件】
        self.btn_abort.setObjectName("BtnAbort")
        self.btn_abort.setEnabled(False) # 默认处于非激活态
        
        self.btn_enc.clicked.connect(lambda: self.start_batch('encrypt'))
        self.btn_dec.clicked.connect(lambda: self.start_batch('decrypt'))
        self.btn_abort.clicked.connect(self.abort_batch)
        
        action_layout.addWidget(self.btn_enc)
        action_layout.addWidget(self.btn_dec)
        action_layout.addWidget(self.btn_abort)
        main_layout.addLayout(action_layout)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        main_layout.addWidget(self.progress)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.appendPlainText(">> 引擎初始化就绪. 状态机闭环 (包含异步中断阻断).")
        main_layout.addWidget(self.console)

        self.heartbeat = QTimer(self)
        self.heartbeat.timeout.connect(self.update_vault_status)
        self.heartbeat.start(1000)

        if initial_files:
            self.console.appendPlainText(f">> 捕获外部调用 (CLI)，装载 {len(initial_files)} 个挂起任务...")
            self.on_files_added(initial_files)

    # 【新增】紧急阻断方法
    def abort_batch(self):
        if not self.worker: return
        
        self.log("[!!!] >>> 触发系统级紧急制动 <<<")
        self.log("[!] 正在清空挂起队列，截断后续指令流...")
        self.task_queue.clear()
        
        if self.worker.isRunning():
            self.log("[!] 正在向底层计算单元广播中止信号，等待当前 I/O 区块释放...")
            self.worker._is_running = False
            # 【防线机制】强制释放可能处于阻塞状态的覆盖对话框锁
            self.worker.overwrite_event.set()
            
        self.btn_abort.setEnabled(False)

    def manual_lock_vault(self):
        self.vault.lock()
        self.log("[!] 触发内存物理覆写，凭据已安全销毁。")
        self.update_vault_status()

    def update_vault_status(self):
        if self.vault.expiry_time > 0 and time.time() > self.vault.expiry_time:
            self.vault.lock()
            self.log("[!] 保险箱存活期耗尽，底层守护进程已主动抹除内存凭据。")

        if self.vault.is_locked():
            self.lbl_vault.setText("🔒 状态：物理内存已隔离，需重新注入凭据")
            self.lbl_vault.setStyleSheet("color: #aaaaaa;")
        else:
            m, s = divmod(self.vault.get_ttl(), 60)
            self.lbl_vault.setText(f"🔓 状态：凭据活跃中 (将在 {m:02d}:{s:02d} 后自动物理覆写)")
            self.lbl_vault.setStyleSheet("color: #4af626;")

    def toggle_password_echo(self):
        if self.input_pwd.echoMode() == QLineEdit.Password:
            self.input_pwd.setEchoMode(QLineEdit.Normal)
            self.btn_toggle_pwd.setText("掩蔽")
        else:
            self.input_pwd.setEchoMode(QLineEdit.Password)
            self.btn_toggle_pwd.setText("透视")

    def on_files_added(self, paths):
        added_count = 0
        
        def add_single_file(filepath):
            nonlocal added_count
            norm_p = os.path.normpath(os.path.abspath(filepath))
            if os.path.isfile(norm_p) and norm_p not in self.task_queue:
                self.task_queue.append(norm_p)
                added_count += 1

        for p in paths:
            if os.path.isfile(p):
                add_single_file(p)
            elif os.path.isdir(p):
                self.log(f"[*] 侦测到目录装载，正在扫描文件树: {os.path.basename(p)}...")
                for root, _, files in os.walk(p):
                    for file in files:
                        add_single_file(os.path.join(root, file))

        if added_count > 0:
            self.log(f"[*] 映射 {added_count} 个文件至队列。")
            self.lbl_queue.setText(f"任务队列：等待执行 ({len(self.task_queue)} 个文件)")

    def log(self, text):
        self.console.appendPlainText(text)
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    def handle_progress(self, current, total):
        if current == -1 and total == -1:
            self.progress.setRange(0, 0)
        else:
            if self.progress.maximum() == 0: self.progress.setRange(0, 100)
            if total > 0: self.progress.setValue(int((current / total) * 100))

    def handle_overwrite_request(self, target_path):
        reply = QMessageBox.warning(self, "内存覆写警告", f"目标已占用:\n{target_path}\n是否强行覆盖？", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        self.worker.overwrite_decision = (reply == QMessageBox.Yes)
        self.worker.overwrite_event.set()

    def start_batch(self, mode):
        if not self.task_queue:
            self.log("[-] 队列为空，无可执行流。")
            return
        
        pwd_str = self.input_pwd.text()
        if pwd_str:
            self.vault.unlock(pwd_str)
            self.input_pwd.clear()
            self.log("[*] 新凭据已注入保险箱，GUI 界面输入已抹除。")
        elif self.vault.is_locked():
            self.log("[-] 凭据拦截：保险箱已锁，且未检测到新凭据注入。")
            return

        self.current_mode = mode
        # 【状态机切换】接管控制流，封锁常规操作，激活紧急制动
        self.btn_enc.setEnabled(False)
        self.btn_dec.setEnabled(False)
        self.drop_zone.setEnabled(False)
        self.btn_abort.setEnabled(True) 
        self.console.clear()
        self.process_next_task()

    def process_next_task(self):
        if not self.task_queue:
            self.log(">>> 流水线已彻底停机。")
            # 【状态机恢复】重置 UI，锁定紧急制动按钮
            self.btn_enc.setEnabled(True)
            self.btn_dec.setEnabled(True)
            self.drop_zone.setEnabled(True)
            self.btn_abort.setEnabled(False)
            self.progress.setRange(0, 100); self.progress.setValue(0)
            self.lbl_queue.setText("任务队列：空闲")
            return

        target_file = self.task_queue.pop(0)
        self.lbl_queue.setText(f"正在处理: {os.path.basename(target_file)} (剩余 {len(self.task_queue)})")
        self.progress.setValue(0)

        pwd_bytes = self.vault.get_password_bytes()
        if not pwd_bytes:
            self.log("[-] 异常中断：凭据保险箱已被隔离，流水线中止。")
            self.task_queue.clear() 
            self.process_next_task()
            return

        self.worker = CryptoWorker(self.current_mode, target_file, pwd_bytes)
        self.worker.log_sig.connect(self.log)
        self.worker.progress_sig.connect(self.handle_progress)
        self.worker.error_sig.connect(lambda e: self.log(f"[-] {e}"))
        self.worker.ask_overwrite_sig.connect(self.handle_overwrite_request)
        self.worker.finished_sig.connect(self.on_task_finished)
        self.worker.start()

    def on_task_finished(self, success):
        self.worker.deleteLater()
        self.worker = None
        # 单节点生命周期结束，回调流转核心处理下一节点
        self.process_next_task()

    def closeEvent(self, event):
        self.vault.lock()
        if self.worker and self.worker.isRunning():
            self.worker._is_running = False
            self.worker.overwrite_event.set()
            self.worker.wait(1500)
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_QSS)
    
    cli_files = sys.argv[1:] if len(sys.argv) > 1 else None
    
    window = MainWindow(initial_files=cli_files)
    window.show()
    sys.exit(app.exec())