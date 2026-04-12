import os
import sys
import struct
import threading
import time
import gc
import stat
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                               QProgressBar, QPlainTextEdit, QMessageBox, QFileDialog, QCheckBox)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QTextCursor

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

# ================= 系统级路径越权探针 =================
def get_safe_win_path(path):
    if os.name != 'nt': return os.path.normpath(os.path.abspath(path))
    path = os.path.normpath(os.path.abspath(path))
    if path.startswith('\\\\?\\'): return path
    if path.startswith('\\\\'): 
        return '\\\\?\\UNC\\' + path[2:]
    return '\\\\?\\' + path

# ================= 内存凭据保险箱 =================
class CredentialVault:
    def __init__(self, timeout=CACHE_TIMEOUT_SECS):
        self._pwd_bytes = bytearray()
        self.timeout = timeout
        self.expiry_time = 0
        self.mutex = threading.Lock() # 【防线建立】引入互斥锁

    def is_locked(self):
        with self.mutex:
            return time.time() > self.expiry_time or len(self._pwd_bytes) == 0

    def lock(self):
        with self.mutex:
            for i in range(len(self._pwd_bytes)):
                self._pwd_bytes[i] = 0
            self._pwd_bytes.clear()
            self.expiry_time = 0
        gc.collect() 

    def unlock(self, pwd_str):
        self.lock() 
        with self.mutex:
            self._pwd_bytes.extend(pwd_str.encode('utf-8'))
            self.expiry_time = time.time() + self.timeout

    def get_password_bytes(self):
        """【修复致命 Bug】返回不可变的快照，防止 C 扩展层 KDF 计算时发生内存穿透突变"""
        with self.mutex:
            if time.time() > self.expiry_time or len(self._pwd_bytes) == 0:
                return None
            self.expiry_time = time.time() + self.timeout # 重置 TTL 存活期
            return bytes(self._pwd_bytes) 

    def get_ttl(self):
        with self.mutex:
            if time.time() > self.expiry_time or len(self._pwd_bytes) == 0: return 0
            return max(0, int(self.expiry_time - time.time()))

# ================= QSS 样式表 =================
DARK_QSS = """
QMainWindow { background-color: #1e1e1e; }
QWidget { color: #cccccc; font-family: "Segoe UI", "Microsoft YaHei", sans-serif; }
QLabel { font-size: 13px; }
QLineEdit { background-color: #2d2d2d; border: 1px solid #3d3d3d; border-radius: 4px; padding: 8px; color: #ffffff; }
QLineEdit:focus { border: 1px solid #007acc; }
QPushButton { background-color: #0e639c; color: white; border: none; border-radius: 4px; padding: 8px 16px; font-weight: bold; }
QPushButton:hover { background-color: #1177bb; }
QPushButton:pressed { background-color: #094771; }
QPushButton:disabled { background-color: #3d3d3d; color: #888888; }
.ToolBtn { background-color: #2d2d2d; border: 1px solid #3d3d3d; color: #cccccc; }
.ToolBtn:hover { background-color: #3d3d3d; border: 1px solid #007acc; }
#BtnLock { background-color: #8a2be2; }
#BtnLock:hover { background-color: #9932cc; }
#BtnAbort { background-color: #c53030; }
#BtnAbort:hover { background-color: #e53e3e; }
#BtnAbort:pressed { background-color: #9b2c2c; }
QProgressBar { border: 1px solid #3d3d3d; border-radius: 4px; text-align: center; background-color: #2d2d2d; color: white; height: 16px; }
QProgressBar::chunk { background-color: #007acc; border-radius: 3px; }
QPlainTextEdit { background-color: #1a1a1a; border: 1px solid #2d2d2d; border-radius: 4px; color: #4af626; font-family: "Consolas", monospace; font-size: 12px; }
#DropZone { border: 2px dashed #3d3d3d; border-radius: 8px; background-color: #252526; }
#DropZone[active="true"] { border: 2px dashed #007acc; background-color: #2d2d30; }
QCheckBox { color: #cccccc; spacing: 8px; }
QCheckBox::indicator { width: 14px; height: 14px; background-color: #2d2d2d; border: 1px solid #3d3d3d; border-radius: 3px; }
QCheckBox::indicator:checked { background-color: #007acc; border: 1px solid #007acc; }
"""

# ================= 异步 I/O 扫描器 =================
class FileScannerWorker(QThread):
    batch_found_sig = Signal(list)
    finished_sig = Signal()

    def __init__(self, paths):
        super().__init__()
        self.paths = paths
        self._is_running = True

    def run(self):
        batch = []
        for p in self.paths:
            if not self._is_running: break
            safe_p = get_safe_win_path(p) 
            if os.path.isfile(safe_p):
                batch.append(safe_p)
            elif os.path.isdir(safe_p):
                for root, _, files in os.walk(safe_p):
                    if not self._is_running: break
                    for file in files:
                        batch.append(os.path.join(root, file))
                        if len(batch) >= 200:
                            self.batch_found_sig.emit(batch)
                            batch = []
        if batch and self._is_running:
            self.batch_found_sig.emit(batch)
        self.finished_sig.emit()

    def abort(self):
        self._is_running = False

# ================= 密码学核心引擎 =================
class CryptoWorker(QThread):
    log_sig = Signal(str)
    progress_sig = Signal(int, int)
    finished_sig = Signal(bool)
    error_sig = Signal(str)
    ask_overwrite_sig = Signal(str)

    def __init__(self, mode, file_path, pwd_bytes, shred_original):
        super().__init__()
        self.mode = mode
        self.file_path = file_path
        self.pwd_bytes = pwd_bytes  
        self.shred_original = shred_original
        
        self.overwrite_event = threading.Event()
        self.overwrite_decision = False
        self._is_running = True
        self._last_percent = -1

    def run(self):
        success = False
        try:
            if self.mode == 'encrypt': success = self._encrypt()
            elif self.mode == 'decrypt': success = self._decrypt()
            
            if success and self.shred_original and self._is_running:
                self.log_sig.emit("[!] 正在执行军事级文件粉碎...")
                self._secure_delete(self.file_path)

        except Exception as e:
            self.error_sig.emit(f"异常阻断: {str(e)}")
        finally:
            # 【清理残影】擦除不可变快照的内存引用
            if hasattr(self, 'key'): del self.key
            if hasattr(self, 'aesgcm'): del self.aesgcm
            self.pwd_bytes = None
            gc.collect() 
            self.finished_sig.emit(success)

    def _remove_readonly(self, path):
        try: os.chmod(path, stat.S_IWRITE)
        except Exception: pass 

    def _secure_delete(self, path):
        try:
            if not os.path.exists(path): return
            self._remove_readonly(path) 
            size = os.path.getsize(path)
            if size > 0:
                with open(path, 'r+b') as f:
                    zero_chunk = b'\x00' * (1024 * 1024)
                    for _ in range(0, size, len(zero_chunk)):
                        f.write(zero_chunk[:min(len(zero_chunk), size - f.tell())])
                    f.flush(); os.fsync(f.fileno())
            os.remove(path)
            self.log_sig.emit("[+] 源文件已彻底粉碎。")
        except Exception as e:
            self.error_sig.emit(f"粉碎核心被拦截，退化为普通删除: {str(e)}")
            try: os.remove(path)
            except Exception as ex: self.error_sig.emit(f"残留清理失败: {str(ex)}")

    def emit_progress_throttled(self, current, total):
        if total == 0:
            self.progress_sig.emit(1, 1); return
        if total < 0: return
        percent = int((current / total) * 100)
        if percent > self._last_percent or current == total:
            self.progress_sig.emit(current, total)
            self._last_percent = percent

    def safe_replace(self, src, dst):
        if os.path.exists(dst): self._remove_readonly(dst) 
        max_retries = 4
        for attempt in range(max_retries):
            try:
                os.replace(src, dst); return
            except PermissionError as e:
                if attempt == max_retries - 1: raise e
                time.sleep(0.5 * (2 ** attempt))

    def _clone_timestamps(self, src, dst):
        try:
            stat_info = os.stat(src)
            os.utime(dst, (stat_info.st_atime, stat_info.st_mtime))
        except Exception: pass

    def _encrypt(self):
        input_path = self.file_path
        output_path = input_path + '.enc'
        tmp_path = None  
        
        if os.path.exists(output_path):
            self.log_sig.emit(f"[*] 命中同名文件: {output_path}")
            self.ask_overwrite_sig.emit(output_path)
            self.overwrite_event.wait()
            if not self.overwrite_decision:
                self.log_sig.emit("[-] 事务中止。")
                self._is_running = False
                return False
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
            
            orig_name_bytes = os.path.basename(os.path.abspath(input_path).replace('\\\\?\\', '')).encode('utf-8')
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
                    
                    self.emit_progress_throttled(min(counter * CHUNK_SIZE, total_bytes), total_bytes)
                    counter += 1

            if self._is_running:
                self._clone_timestamps(input_path, tmp_path) 
                self.safe_replace(tmp_path, output_path)
                self.log_sig.emit(f"[+] 封印完成: {output_path}")
                return True
            else:
                self.log_sig.emit("[-] 操作已强制阻断，清理临时载荷。")
                if tmp_path and os.path.exists(tmp_path): 
                    self._remove_readonly(tmp_path); os.remove(tmp_path)
                return False
        except Exception as e:
            if tmp_path and os.path.exists(tmp_path): 
                self._remove_readonly(tmp_path); os.remove(tmp_path)
            raise e

    def _decrypt(self):
        input_path = self.file_path
        tmp_path = None 
        try:
            total_file_size = os.path.getsize(input_path)
            with open(input_path, 'rb') as f_in:
                if f_in.read(len(MAGIC_NUMBER)) != MAGIC_NUMBER: raise ValueError("引擎版本不匹配。")
                salt = f_in.read(SALT_SIZE)
                base_nonce = f_in.read(BASE_NONCE_SIZE)
                meta_len = struct.unpack('>H', f_in.read(2))[0]
                enc_meta = f_in.read(meta_len)
                data_start_pos = f_in.tell()

            self.progress_sig.emit(-1, -1)
            self.log_sig.emit("[*] 派生临时密钥...")
            kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
            self.key = kdf.derive(self.pwd_bytes)
            self.aesgcm = AESGCM(self.key)
            
            try:
                header = MAGIC_NUMBER + salt + base_nonce
                meta_payload = self.aesgcm.decrypt(base_nonce + struct.pack('>I', 0), enc_meta, associated_data=header)
            except InvalidTag: raise ValueError("AAD 校验失败，文件头受损或密钥错误。")
                
            expected_size = struct.unpack('>Q', meta_payload[:8])[0]
            orig_name_raw = meta_payload[8:].decode('utf-8', 'replace')
            orig_name = os.path.basename(orig_name_raw.replace('\\', '/'))
            
            output_path = get_safe_win_path(os.path.join(os.path.dirname(input_path), orig_name))
            if os.path.exists(output_path):
                self.log_sig.emit(f"[*] 命中同名文件: {output_path}")
                self.ask_overwrite_sig.emit(output_path)
                self.overwrite_event.wait()
                if not self.overwrite_decision:
                    self.log_sig.emit("[-] 中止。")
                    self._is_running = False
                    return False
                    
            tmp_path = output_path + '.tmp'
            self.progress_sig.emit(0, expected_size)
            
            with open(input_path, 'rb') as f_in, open(tmp_path, 'wb') as f_out:
                f_in.seek(data_start_pos)
                counter = 1
                payload_processed = 0
                while self._is_running:
                    len_data = f_in.read(4)
                    if not len_data: break
                    if len(len_data) < 4: raise ValueError("致命截断：文件尾部数据不完整。")
                    chunk_len = struct.unpack('>I', len_data)[0]
                    if chunk_len > CHUNK_SIZE + 16: raise ValueError(f"内存防线触发：非法区块尺寸 ({chunk_len}B)。")
                    enc_chunk = f_in.read(chunk_len)
                    if len(enc_chunk) != chunk_len: raise ValueError("I/O 数据流断裂。")
                        
                    try: chunk = self.aesgcm.decrypt(base_nonce + struct.pack('>I', counter), enc_chunk, None)
                    except InvalidTag: raise ValueError(f"完整性防线触发：区块 {counter} MAC 校验失败！")
                        
                    f_out.write(chunk)
                    payload_processed += len(chunk)
                    self.emit_progress_throttled(payload_processed, expected_size)
                    counter += 1

            if self._is_running:
                if os.path.getsize(tmp_path) != expected_size:
                    self._remove_readonly(tmp_path); os.remove(tmp_path)
                    raise ValueError("一致性致命错误，释出体尺寸校验失败。")
                self._clone_timestamps(input_path, tmp_path) 
                self.safe_replace(tmp_path, output_path)
                self.log_sig.emit(f"[+] 释出至: {output_path}")
                return True
            else:
                self.log_sig.emit("[-] 操作已强制阻断。")
                if tmp_path and os.path.exists(tmp_path): 
                    self._remove_readonly(tmp_path); os.remove(tmp_path)
                return False
        except Exception as e:
            if tmp_path and os.path.exists(tmp_path): 
                self._remove_readonly(tmp_path); os.remove(tmp_path)
            raise e

# ================= 主界面 GUI =================
class DropZoneLabel(QLabel):
    files_dropped = Signal(list)
    def __init__(self):
        super().__init__("将文件/目录拖拽至此进入队列\n(Drop Zone)")
        self.setObjectName("DropZone")
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)
        self.setFont(QFont("Segoe UI", 14, QFont.Bold))
        self.setMinimumHeight(100)
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            self.setProperty("active", "true"); self.style().unpolish(self); self.style().polish(self); event.accept()
        else: event.ignore()
    def dragLeaveEvent(self, event):
        self.setProperty("active", "false"); self.style().unpolish(self); self.style().polish(self)
    def dropEvent(self, event):
        self.setProperty("active", "false"); self.style().unpolish(self); self.style().polish(self)
        urls = event.mimeData().urls()
        if urls: self.files_dropped.emit([u.toLocalFile() for u in urls])

class MainWindow(QMainWindow):
    def __init__(self, initial_files=None):
        super().__init__()
        self.setWindowTitle("AES-GCM Core V3.3.4 (Thread-Safe)")
        self.setFixedSize(620, 640)
        self.worker = None; self.scanner = None
        self.task_queue = []; self.seen_files = set() 
        self.current_mode = None
        self.vault = CredentialVault()

        central_widget = QWidget(); self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget); main_layout.setContentsMargins(20, 20, 20, 20)

        self.drop_zone = DropZoneLabel(); self.drop_zone.files_dropped.connect(self.start_async_scan)
        main_layout.addWidget(self.drop_zone)

        file_tools_layout = QHBoxLayout()
        self.btn_add_files = QPushButton("📄 注入文件"); self.btn_add_files.setProperty("class", "ToolBtn")
        self.btn_add_dir = QPushButton("📁 注入目录"); self.btn_add_dir.setProperty("class", "ToolBtn")
        self.btn_clear_q = QPushButton("🧹 清空队列"); self.btn_clear_q.setProperty("class", "ToolBtn")
        self.btn_add_files.clicked.connect(self.dialog_add_files)
        self.btn_add_dir.clicked.connect(self.dialog_add_dir)
        self.btn_clear_q.clicked.connect(self.clear_queue)
        file_tools_layout.addWidget(self.btn_add_files); file_tools_layout.addWidget(self.btn_add_dir); file_tools_layout.addWidget(self.btn_clear_q)
        main_layout.addLayout(file_tools_layout)

        self.lbl_queue = QLabel("任务队列：空闲 (0)"); self.lbl_queue.setStyleSheet("color: #007acc; font-weight: bold;")
        main_layout.addWidget(self.lbl_queue)

        settings_layout = QHBoxLayout()
        self.chk_shred = QCheckBox("🖨️ 完成后彻底粉碎源文件")
        self.chk_smart = QCheckBox("🧠 智能防呆过滤"); self.chk_smart.setChecked(True)
        settings_layout.addWidget(self.chk_shred); settings_layout.addWidget(self.chk_smart)
        main_layout.addLayout(settings_layout)

        pwd_layout = QHBoxLayout()
        self.input_pwd = QLineEdit(); self.input_pwd.setPlaceholderText("注入凭据 (存入保险箱后将自动清空)"); self.input_pwd.setEchoMode(QLineEdit.Password)
        self.btn_toggle_pwd = QPushButton("透视"); self.btn_toggle_pwd.setFixedWidth(60); self.btn_toggle_pwd.clicked.connect(self.toggle_password_echo)
        self.btn_lock = QPushButton("主动销毁"); self.btn_lock.setObjectName("BtnLock"); self.btn_lock.setFixedWidth(80); self.btn_lock.clicked.connect(self.manual_lock_vault)
        pwd_layout.addWidget(self.input_pwd); pwd_layout.addWidget(self.btn_toggle_pwd); pwd_layout.addWidget(self.btn_lock)
        main_layout.addLayout(pwd_layout)

        self.lbl_vault = QLabel("🔒 保险箱状态：未装载凭据"); self.lbl_vault.setStyleSheet("color: #aaaaaa;")
        main_layout.addWidget(self.lbl_vault)

        action_layout = QHBoxLayout()
        self.btn_enc = QPushButton("封印队列"); self.btn_enc.clicked.connect(lambda: self.start_batch('encrypt'))
        self.btn_dec = QPushButton("解除封印"); self.btn_dec.clicked.connect(lambda: self.start_batch('decrypt'))
        self.btn_abort = QPushButton("紧急制动 (Abort)"); self.btn_abort.setObjectName("BtnAbort"); self.btn_abort.setEnabled(False); self.btn_abort.clicked.connect(self.abort_batch)
        action_layout.addWidget(self.btn_enc); action_layout.addWidget(self.btn_dec); action_layout.addWidget(self.btn_abort)
        main_layout.addLayout(action_layout)

        self.progress = QProgressBar(); self.progress.setValue(0); self.progress.setTextVisible(False)
        main_layout.addWidget(self.progress)

        self.console = QPlainTextEdit(); self.console.setReadOnly(True)
        self.console.appendPlainText(">> V3.3.4 引擎就绪. 并发竞态条件防线 (Mutex) 已建立.")
        main_layout.addWidget(self.console)

        self.heartbeat = QTimer(self); self.heartbeat.timeout.connect(self.update_vault_status); self.heartbeat.start(1000)

        if initial_files: self.start_async_scan(initial_files)

    def dialog_add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "注入文件", "", "All Files (*)")
        if paths: self.start_async_scan(paths)
    def dialog_add_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "注入目录")
        if dir_path: self.start_async_scan([dir_path])
    def clear_queue(self):
        self.task_queue.clear(); self.seen_files.clear(); self.update_queue_label(); self.log("[*] 任务队列已清空。")
    def update_queue_label(self):
        self.lbl_queue.setText(f"任务队列：等待执行 ({len(self.task_queue)} 个文件)")

    def start_async_scan(self, paths):
        if self.scanner and self.scanner.isRunning(): return
        self.log("[*] 启动异步 I/O 探针...")
        self.scanner = FileScannerWorker(paths); self.scanner.batch_found_sig.connect(self.on_scan_batch_found)
        self.scanner.finished_sig.connect(self.on_scanner_finished); self.scanner.start()

    def on_scan_batch_found(self, batch):
        added = 0
        for p in batch:
            norm_p = get_safe_win_path(p)
            if norm_p not in self.seen_files:
                self.seen_files.add(norm_p); self.task_queue.append(norm_p); added += 1
        if added > 0: self.update_queue_label()

    def on_scanner_finished(self):
        self.log(f"[+] 扫描完成。当前挂载 {len(self.task_queue)} 项。")
        self.scanner.deleteLater(); self.scanner = None

    def abort_batch(self):
        if self.scanner and self.scanner.isRunning(): self.scanner.abort(); self.log("[!] 截断 I/O 扫描器...")
        if not self.worker: return
        self.log("[!!!] >>> 触发系统级紧急制动 <<<")
        self.task_queue.clear(); self.seen_files.clear()
        if self.worker.isRunning(): self.worker._is_running = False; self.worker.overwrite_event.set()
        self.btn_abort.setEnabled(False)

    def manual_lock_vault(self):
        self.vault.lock(); self.log("[!] 触发物理覆写，凭据已安全销毁。"); self.update_vault_status()

    def update_vault_status(self):
        if getattr(self.vault, 'expiry_time', 0) > 0 and time.time() > self.vault.expiry_time:
            self.vault.lock(); self.log("[!] 保险箱存活期耗尽，自动抹除凭据。")
        if self.vault.is_locked():
            self.lbl_vault.setText("🔒 状态：已锁定，需注入凭据"); self.lbl_vault.setStyleSheet("color: #aaaaaa;")
        else:
            m, s = divmod(self.vault.get_ttl(), 60)
            self.lbl_vault.setText(f"🔓 状态：活跃中 ({m:02d}:{s:02d} 后销毁)"); self.lbl_vault.setStyleSheet("color: #4af626;")

    def toggle_password_echo(self):
        if self.input_pwd.echoMode() == QLineEdit.Password:
            self.input_pwd.setEchoMode(QLineEdit.Normal); self.btn_toggle_pwd.setText("掩蔽")
        else:
            self.input_pwd.setEchoMode(QLineEdit.Password); self.btn_toggle_pwd.setText("透视")

    def log(self, text):
        self.console.appendPlainText(text); self.console.moveCursor(QTextCursor.End)

    def handle_progress(self, current, total):
        if current == -1 and total == -1: self.progress.setRange(0, 0)
        else:
            if self.progress.maximum() == 0: self.progress.setRange(0, 100)
            if total > 0: self.progress.setValue(int((current / total) * 100))

    def handle_overwrite_request(self, target_path):
        display_path = target_path.replace('\\\\?\\', '')
        reply = QMessageBox.warning(self, "内存覆写", f"目标已占用:\n{display_path}\n强行覆盖？", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        self.worker.overwrite_decision = (reply == QMessageBox.Yes)
        self.worker.overwrite_event.set()

    def _apply_smart_filter(self):
        if not self.chk_smart.isChecked(): return
        filtered_queue = []; skipped = 0
        for path in self.task_queue:
            is_enc = path.endswith('.enc')
            if (self.current_mode == 'encrypt' and is_enc) or (self.current_mode == 'decrypt' and not is_enc): skipped += 1
            else: filtered_queue.append(path)
        self.task_queue = filtered_queue; self.seen_files = set(self.task_queue)
        if skipped > 0: self.log(f"[*] 智能过滤自动剥离了 {skipped} 个不合规文件。")

    def start_batch(self, mode):
        if not self.task_queue: return
        self.current_mode = mode
        self._apply_smart_filter()
        if not self.task_queue:
            self.log("[-] 过滤后队列为空。"); self.update_queue_label(); return
        
        pwd_str = self.input_pwd.text()
        if pwd_str:
            self.vault.unlock(pwd_str); self.input_pwd.clear(); self.log("[*] 新凭据已注入保险箱。")
        elif self.vault.is_locked():
            self.log("[-] 保险箱已锁。"); return

        for btn in [self.btn_enc, self.btn_dec, self.btn_add_files, self.btn_add_dir, self.btn_clear_q]: btn.setEnabled(False)
        self.drop_zone.setEnabled(False); self.chk_shred.setEnabled(False); self.chk_smart.setEnabled(False)
        self.btn_abort.setEnabled(True); self.console.clear()
        self.process_next_task()

    def process_next_task(self):
        if not self.task_queue:
            self.log(">>> 流水线停机。")
            for btn in [self.btn_enc, self.btn_dec, self.btn_add_files, self.btn_add_dir, self.btn_clear_q]: btn.setEnabled(True)
            self.drop_zone.setEnabled(True); self.chk_shred.setEnabled(True); self.chk_smart.setEnabled(True)
            self.btn_abort.setEnabled(False); self.progress.setRange(0, 100); self.progress.setValue(0)
            self.seen_files.clear(); self.update_queue_label(); return

        target_file = self.task_queue.pop(0)
        display_name = os.path.basename(target_file.replace('\\\\?\\', ''))
        self.lbl_queue.setText(f"处理: {display_name} (剩余 {len(self.task_queue)})")
        self.progress.setValue(0)

        pwd_bytes = self.vault.get_password_bytes()
        if not pwd_bytes:
            self.log("[-] 凭据超时，流水线阻断。"); self.task_queue.clear(); self.process_next_task(); return

        self.worker = CryptoWorker(self.current_mode, target_file, pwd_bytes, self.chk_shred.isChecked())
        self.worker.log_sig.connect(self.log); self.worker.progress_sig.connect(self.handle_progress)
        self.worker.error_sig.connect(lambda e: self.log(f"[-] {e}"))
        self.worker.ask_overwrite_sig.connect(self.handle_overwrite_request)
        self.worker.finished_sig.connect(self.on_task_finished)
        self.worker.start()

    def on_task_finished(self, success):
        self.worker.deleteLater(); self.worker = None; self.process_next_task()

    def closeEvent(self, event):
        self.vault.lock()
        if self.scanner and self.scanner.isRunning(): self.scanner.abort(); self.scanner.wait(1000)
        if self.worker and self.worker.isRunning():
            self.worker._is_running = False; self.worker.overwrite_event.set(); self.worker.wait(1500)
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv); app.setStyleSheet(DARK_QSS)
    window = MainWindow(initial_files=sys.argv[1:] if len(sys.argv) > 1 else None); window.show(); sys.exit(app.exec())