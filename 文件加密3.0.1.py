import os
import sys
import struct
import threading
import time
import gc
import stat
import re
import logging
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                               QProgressBar, QPlainTextEdit, QMessageBox, QFileDialog, 
                               QCheckBox, QComboBox, QDialog, QInputDialog)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QTextCursor

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# 配置日志系统
logging.basicConfig(
    filename='crypto_operation.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    encoding='utf-8'
)

# 核心常量配置
CHUNK_SIZE = 4 * 1024 * 1024
MAGIC_V2 = b"SAES\x03"
MAGIC_V1 = b"SAES\x02"
SALT_SIZE = 16
SCRYPT_N_V2 = 2**17  
SCRYPT_N_V1 = 2**14
CACHE_TIMEOUT_SECS = 900  

DARK_QSS = """
QMainWindow { background-color: #1e1e1e; }
QWidget { color: #cccccc; font-family: "Segoe UI", "Microsoft YaHei", sans-serif; }
QLineEdit, QComboBox { background-color: #2d2d2d; border: 1px solid #3d3d3d; border-radius: 4px; padding: 8px; color: #ffffff; }
QPushButton { background-color: #0e639c; color: white; border: none; border-radius: 4px; padding: 8px 16px; font-weight: bold; }
QPushButton:hover { background-color: #1177bb; }
#BtnLock { background-color: #8a2be2; }
#BtnAbort { background-color: #c53030; }
QProgressBar { border: 1px solid #3d3d3d; border-radius: 4px; text-align: center; background-color: #2d2d2d; height: 16px; }
QProgressBar::chunk { background-color: #007acc; }
QPlainTextEdit { background-color: #1a1a1a; border: 1px solid #2d2d2d; color: #4af626; font-family: "Consolas", monospace; }
#DropZone { border: 2px dashed #3d3d3d; border-radius: 8px; background-color: #252526; }
"""

def sanitize_filename(filename):
    # 剔除 Windows 非法字符并限制长度
    name = re.sub(r'[<>:"/\\|?*]', '', filename)
    name = name.strip()
    return name if name else "unnamed_decoded"

def get_safe_win_path(path):
    if os.name != 'nt': return os.path.normpath(os.path.abspath(path))
    path = os.path.normpath(os.path.abspath(path))
    if path.startswith('\\\\?\\'): return path
    if path.startswith('\\\\'): return '\\\\?\\UNC\\' + path[2:]
    return '\\\\?\\' + path

def force_replace(src, dst):
    try:
        if os.path.exists(dst):
            os.chmod(dst, stat.S_IWRITE)
        os.replace(src, dst)
    except:
        os.replace(src, dst)

class V0FilenameDialog(QDialog):
    def __init__(self, parent, path):
        super().__init__(parent)
        self.setWindowTitle("V0.0.1 协议溯源")
        self.setFixedSize(420, 180)
        self.result_val = None
        layout = QVBoxLayout(self)
        display_name = os.path.basename(path.replace('\\\\?\\', ''))
        suggested = display_name[:-4] if display_name.lower().endswith('.enc') else display_name + ".dec"
        layout.addWidget(QLabel(f"检测到缺乏元数据的 V0 协议文件：\n{display_name}\n请输入释出文件名："))
        self.line_edit = QLineEdit(suggested)
        layout.addWidget(self.line_edit)
        btn_layout = QHBoxLayout()
        btn_ok = QPushButton("确定(释出)")
        btn_skip = QPushButton("跳过")
        btn_abort = QPushButton("终止全部任务")
        btn_abort.setStyleSheet("background-color: #c53030; color: white;")
        btn_layout.addWidget(btn_ok); btn_layout.addWidget(btn_skip); btn_layout.addWidget(btn_abort)
        layout.addLayout(btn_layout)
        btn_ok.clicked.connect(self.on_ok); btn_skip.clicked.connect(self.reject); btn_abort.clicked.connect(self.on_abort)
    def on_ok(self): self.result_val = self.line_edit.text().strip(); self.accept()
    def on_abort(self): self.result_val = "__SYS_ABORT__"; self.reject()

class CredentialVault:
    def __init__(self, timeout=CACHE_TIMEOUT_SECS):
        self._pwd_bytes = bytearray()
        self.timeout = timeout
        self.expiry_time = 0
        self.mutex = threading.Lock()
    def is_locked(self):
        with self.mutex: return time.time() > self.expiry_time or len(self._pwd_bytes) == 0
    def lock(self):
        with self.mutex:
            for i in range(len(self._pwd_bytes)): self._pwd_bytes[i] = 0
            self._pwd_bytes.clear()
            self.expiry_time = 0
        gc.collect() 
    def unlock(self, pwd_str):
        self.lock() 
        with self.mutex:
            self._pwd_bytes.extend(pwd_str.encode('utf-8'))
            self.expiry_time = time.time() + self.timeout
    def heartbeat(self):
        with self.mutex:
            if self.expiry_time > 0 and len(self._pwd_bytes) > 0:
                self.expiry_time = time.time() + self.timeout
    def get_password_bytes(self):
        with self.mutex:
            if time.time() > self.expiry_time or len(self._pwd_bytes) == 0: return None
            return bytes(self._pwd_bytes) 
    def get_ttl(self):
        with self.mutex:
            if time.time() > self.expiry_time or len(self._pwd_bytes) == 0: return 0
            return max(0, int(self.expiry_time - time.time()))

class CryptoWorker(QThread):
    log_sig = Signal(str); progress_sig = Signal(int); file_done_sig = Signal(str, int)
    finished_sig = Signal(); ask_overwrite_sig = Signal(str, bool)
    ask_filename_sig = Signal(str); heartbeat_sig = Signal()

    def __init__(self, mode, enc_ver, queue, vault, shred, overwrite_strat):
        super().__init__()
        self.mode = mode; self.enc_ver = enc_ver; self.queue = queue
        self.vault = vault; self.shred = shred
        self.overwrite_strat = overwrite_strat 
        self.overwrite_event = threading.Event(); self.overwrite_decision = False
        self.filename_event = threading.Event(); self.filename_decision = None
        self._is_running = True; self.consecutive_errors = 0; self.reported_in_file = 0

    def run(self):
        try:
            processed_since_gc = 0
            for file_path, file_size in self.queue:
                if not self._is_running: break
                pwd_bytes = self.vault.get_password_bytes()
                if not pwd_bytes: 
                    self.log_sig.emit("[-] 凭据撤销，流水线熔断。")
                    break
                
                self.reported_in_file = 0
                try:
                    self.current_file = file_path
                    res = self._process_single(file_path, pwd_bytes)
                    if res:
                        self.consecutive_errors = 0
                        if self.shred: self._secure_delete(file_path)
                        self.file_done_sig.emit("success", file_size - self.reported_in_file)
                    elif not self._is_running: 
                        break
                    else:
                        self.consecutive_errors = 0
                        self.file_done_sig.emit("skip", file_size - self.reported_in_file)
                except InvalidTag:
                    self.log_sig.emit(f"[{os.path.basename(file_path)}] 错误：凭据不匹配（解密校验失败）。")
                    self.file_done_sig.emit("error", file_size - self.reported_in_file)
                    self.log_sig.emit("[!!!] 触发安全熔断：密码错误，停止后续任务。")
                    break
                except Exception as e:
                    self.consecutive_errors += 1
                    self.log_sig.emit(f"[{os.path.basename(file_path)}] 异常: {str(e)}")
                    self.file_done_sig.emit("error", file_size - self.reported_in_file)
                    if self.consecutive_errors >= 10:
                        self.log_sig.emit("[!!!] 连续异常触发现场熔断。")
                        break
                finally:
                    processed_since_gc += file_size
                    if processed_since_gc > 256 * 1024 * 1024:
                        gc.collect()
                        processed_since_gc = 0
        finally:
            self.finished_sig.emit()

    def _process_single(self, path, pwd):
        if self.mode == 'encrypt':
            if self.enc_ver == 2: return self._enc_v2(path, pwd)
            if self.enc_ver == 1: return self._enc_v1(path, pwd)
            return self._enc_v0(path, pwd)
        else:
            with open(path, 'rb') as f: magic = f.read(5)
            if magic == MAGIC_V2: return self._dec_v2(path, pwd)
            if magic == MAGIC_V1: return self._dec_v1(path, pwd)
            return self._dec_v0(path, pwd)

    def _secure_delete(self, path):
        try:
            os.chmod(path, stat.S_IWRITE); size = os.path.getsize(path)
            if size > 0:
                with open(path, 'r+b') as f:
                    f.write(b'\x00' * min(size, 4*1024*1024)); self.heartbeat_sig.emit()
                    if size > 5*1024*1024:
                        f.seek(size - 1024*1024); f.write(b'\x00' * 1024*1024)
                    f.flush(); os.fsync(f.fileno())
            os.remove(path)
        except: pass

    def _check_overwrite(self, out_p):
        # 路径长度预检 (Windows 限制预警)
        pure_path = out_p.replace('\\\\?\\', '')
        if len(pure_path) > 255:
            self.log_sig.emit(f"[!] 警告：输出路径超过 255 字符，旧版软件可能无法访问：{os.path.basename(out_p)}")

        if self.overwrite_strat == 'overwrite': return True
        if self.overwrite_strat == 'skip': 
            if os.path.exists(out_p): return False
            return True
        if self.overwrite_strat == 'rename': 
            if os.path.exists(out_p): return self._rename(out_p)
            return True
            
        if os.path.exists(out_p):
            self.ask_overwrite_sig.emit(out_p, False)
            self.overwrite_event.wait()
            res = self.overwrite_decision
            self.overwrite_event.clear()
            if res == 'rename': return self._rename(out_p)
            return res
        return True

    def _rename(self, path):
        base, ext = os.path.splitext(path)
        new_p = f"{base}_{time.strftime('%Y%m%d_%H%M%S')}_{os.urandom(2).hex()}{ext}"
        while os.path.exists(new_p): 
            new_p = f"{base}_{time.strftime('%Y%m%d_%H%M%S')}_{os.urandom(2).hex()}{ext}"
        return new_p

    def _enc_v2(self, path, pwd):
        out_p = path + '.enc'
        chk = self._check_overwrite(out_p)
        if not chk: return None
        if isinstance(chk, str): out_p = chk
        tmp = out_p + '.tmp'
        try:
            salt = os.urandom(16)
            nonce = os.urandom(8)
            kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N_V2, r=8, p=1)
            key = kdf.derive(pwd)
            gcm = AESGCM(key)
            head = MAGIC_V2 + salt + nonce
            meta = gcm.encrypt(nonce + b'\x00\x00\x00\x00', struct.pack('>Q', os.path.getsize(path)) + os.path.basename(path).encode('utf-8'), head)
            with open(path, 'rb') as fi, open(tmp, 'wb') as fo:
                fo.write(head + struct.pack('>H', len(meta)) + meta)
                c = 1
                while self._is_running:
                    buf = fi.read(CHUNK_SIZE)
                    if not buf: break
                    fo.write(struct.pack('>I', len(buf)+16) + gcm.encrypt(nonce + struct.pack('>I', c), buf, None))
                    self.progress_sig.emit(len(buf)); self.reported_in_file += len(buf); self.heartbeat_sig.emit(); c += 1
            if self._is_running: 
                force_replace(tmp, out_p)
                return out_p
        finally: 
            if 'gcm' in locals(): del gcm
            if os.path.exists(tmp): os.remove(tmp)

    def _dec_v2(self, path, pwd):
        tmp = None
        try:
            with open(path, 'rb') as f:
                f.read(5); salt = f.read(16); nonce = f.read(8)
                mlen_buf = f.read(2)
                if not mlen_buf: return None
                mlen = struct.unpack('>H', mlen_buf)[0]
                emeta = f.read(mlen); pos = f.tell()
            kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N_V2, r=8, p=1)
            key = kdf.derive(pwd); gcm = AESGCM(key)
            meta = gcm.decrypt(nonce + b'\x00\x00\x00\x00', emeta, MAGIC_V2+salt+nonce)
            out_name = sanitize_filename(meta[8:].decode('utf-8'))
            out_p = get_safe_win_path(os.path.join(os.path.dirname(path), out_name))
            chk = self._check_overwrite(out_p)
            if not chk: return None
            if isinstance(chk, str): out_p = chk
            tmp = out_p + '.tmp'
            with open(path, 'rb') as fi, open(tmp, 'wb') as fo:
                fi.seek(pos); c = 1
                while self._is_running:
                    lb = fi.read(4)
                    if not lb: break
                    chunk = gcm.decrypt(nonce + struct.pack('>I', c), fi.read(struct.unpack('>I', lb)[0]), None)
                    fo.write(chunk); self.progress_sig.emit(len(chunk)); self.reported_in_file += len(chunk); self.heartbeat_sig.emit(); c += 1
            if self._is_running: 
                force_replace(tmp, out_p)
                return out_p
        finally:
            if 'gcm' in locals(): del gcm
            if tmp and os.path.exists(tmp): os.remove(tmp)

    def _enc_v1(self, path, pwd):
        out_p = path + '.enc'
        chk = self._check_overwrite(out_p)
        if not chk: return None
        if isinstance(chk, str): out_p = chk
        tmp = out_p + '.tmp'
        try:
            salt = os.urandom(16); nonce = os.urandom(8)
            kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N_V1, r=8, p=1); key = kdf.derive(pwd); gcm = AESGCM(key)
            meta = gcm.encrypt(nonce + b'\x00\x00\x00\x00', struct.pack('>Q', os.path.getsize(path)) + os.path.basename(path).encode('utf-8'), None)
            with open(path, 'rb') as fi, open(tmp, 'wb') as fo:
                fo.write(MAGIC_V1 + salt + nonce + struct.pack('>H', len(meta)) + meta)
                c = 1
                while self._is_running:
                    buf = fi.read(CHUNK_SIZE)
                    if not buf: break
                    fo.write(struct.pack('>I', len(buf)+16) + gcm.encrypt(nonce + struct.pack('>I', c), buf, None))
                    self.progress_sig.emit(len(buf)); self.reported_in_file += len(buf); self.heartbeat_sig.emit(); c += 1
            if self._is_running: 
                force_replace(tmp, out_p)
                return out_p
        finally: 
            if 'gcm' in locals(): del gcm
            if os.path.exists(tmp): os.remove(tmp)

    def _dec_v1(self, path, pwd):
        tmp = None
        try:
            with open(path, 'rb') as f:
                f.read(5); salt = f.read(16); nonce = f.read(8); mlen_buf = f.read(2)
                if not mlen_buf: return None
                mlen = struct.unpack('>H', mlen_buf)[0]
                emeta = f.read(mlen); pos = f.tell()
            kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N_V1, r=8, p=1); key = kdf.derive(pwd); gcm = AESGCM(key)
            meta = gcm.decrypt(nonce + b'\x00\x00\x00\x00', emeta, None)
            out_name = sanitize_filename(meta[8:].decode('utf-8'))
            out_p = get_safe_win_path(os.path.join(os.path.dirname(path), out_name))
            chk = self._check_overwrite(out_p)
            if not chk: return None
            if isinstance(chk, str): out_p = chk
            tmp = out_p + '.tmp'
            with open(path, 'rb') as fi, open(tmp, 'wb') as fo:
                fi.seek(pos); c = 1
                while self._is_running:
                    lb = fi.read(4)
                    if not lb: break
                    chunk = gcm.decrypt(nonce + struct.pack('>I', c), fi.read(struct.unpack('>I', lb)[0]), None)
                    fo.write(chunk); self.progress_sig.emit(len(chunk)); self.reported_in_file += len(chunk); self.heartbeat_sig.emit(); c += 1
            if self._is_running: 
                force_replace(tmp, out_p)
                return out_p
        finally:
            if 'gcm' in locals(): del gcm
            if tmp and os.path.exists(tmp): os.remove(tmp)

    def _enc_v0(self, path, pwd):
        out_p = path + '.enc'
        chk = self._check_overwrite(out_p)
        if not chk: return None
        if isinstance(chk, str): out_p = chk
        tmp = out_p + '.tmp'
        try:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000); key = kdf.derive(pwd); gcm = AESGCM(key)
            with open(path, 'rb') as fi, open(tmp, 'wb') as fo:
                fo.write(salt); c = 0; buf = fi.read(CHUNK_SIZE)
                while buf:
                    nxt = fi.read(CHUNK_SIZE)
                    is_last = b'\x01' if not nxt else b'\x00'
                    nonce = os.urandom(12); aad = c.to_bytes(8,'big') + is_last
                    enc = gcm.encrypt(nonce, buf, aad)
                    fo.write(is_last + (len(buf)+16).to_bytes(4,'big') + nonce + enc)
                    self.progress_sig.emit(len(buf)); self.reported_in_file += len(buf); self.heartbeat_sig.emit(); buf = nxt; c += 1
            if self._is_running: 
                force_replace(tmp, out_p)
                return out_p
        finally: 
            if 'gcm' in locals(): del gcm
            if os.path.exists(tmp): os.remove(tmp)

    def _dec_v0(self, path, pwd):
        tmp = None
        try:
            with open(path, 'rb') as f: salt = f.read(16)
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000); gcm = AESGCM(kdf.derive(pwd))
            self.ask_filename_sig.emit(path); self.filename_event.wait()
            if not self.filename_decision or self.filename_decision == "__SYS_ABORT__":
                if self.filename_decision == "__SYS_ABORT__": self._is_running = False
                self.filename_event.clear(); return None
            
            out_name = sanitize_filename(self.filename_decision)
            out_p = get_safe_win_path(os.path.join(os.path.dirname(path), out_name))
            self.filename_event.clear()
            chk = self._check_overwrite(out_p)
            if not chk: return None
            if isinstance(chk, str): out_p = chk
            tmp = out_p + '.tmp'
            with open(path, 'rb') as fi, open(tmp, 'wb') as fo:
                fi.seek(16); c = 0
                while self._is_running:
                    is_last_buf = fi.read(1)
                    if not is_last_buf: break
                    is_last = is_last_buf
                    ln_buf = fi.read(4)
                    if not ln_buf: break
                    ln = int.from_bytes(ln_buf, 'big')
                    nonce = fi.read(12)
                    chunk = gcm.decrypt(nonce, fi.read(ln), c.to_bytes(8,'big') + is_last)
                    fo.write(chunk); self.progress_sig.emit(len(chunk)); self.reported_in_file += len(chunk); self.heartbeat_sig.emit(); c += 1
            if self._is_running: 
                force_replace(tmp, out_p)
                return out_p
        finally:
            if 'gcm' in locals(): del gcm
            if tmp and os.path.exists(tmp): os.remove(tmp)

class FileScannerWorker(QThread):
    batch_found_sig = Signal(list); finished_sig = Signal()
    def __init__(self, paths):
        super().__init__(); self.paths = paths; self._is_running = True
    def run(self):
        try:
            batch = []
            for p in self.paths:
                if not self._is_running: break
                safe_p = get_safe_win_path(p) 
                if os.path.isfile(safe_p):
                    try: batch.append((safe_p, os.path.getsize(safe_p)))
                    except: pass
                elif os.path.isdir(safe_p):
                    for root, _, files in os.walk(safe_p):
                        if not self._is_running: break
                        for f in files:
                            fp = os.path.join(root, f)
                            try: batch.append((fp, os.path.getsize(fp)))
                            except: pass
                            if len(batch) >= 500: self.batch_found_sig.emit(batch); batch = []
            if batch and self._is_running: self.batch_found_sig.emit(batch)
        finally:
            self.finished_sig.emit()
    def abort(self): self._is_running = False

class QueueFilterWorker(QThread):
    results_ready_sig = Signal(list, int, int); finished_sig = Signal()
    def __init__(self, task_queue, mode, use_smart):
        super().__init__(); self.task_queue = task_queue
        self.mode = mode; self.use_smart = use_smart; self._is_running = True
    def run(self):
        try:
            filtered = []; skipped = 0; total_bytes = 0
            for path, sz in self.task_queue:
                if not self._is_running: break
                is_enc = False
                if self.use_smart:
                    try:
                        with open(path, 'rb') as f: magic = f.read(5)
                        if magic in (MAGIC_V2, MAGIC_V1): is_enc = True
                    except: pass
                    if not is_enc and path.lower().endswith('.enc'): is_enc = True
                if self.use_smart and ((self.mode == 'encrypt' and is_enc) or (self.mode == 'decrypt' and not is_enc)): skipped += 1
                else: filtered.append((path, sz)); total_bytes += sz
            if self._is_running: self.results_ready_sig.emit(filtered, skipped, total_bytes)
        finally:
            self.finished_sig.emit()
    def abort(self): self._is_running = False

class MainWindow(QMainWindow):
    def __init__(self, initial_files=None):
        super().__init__()
        self.setWindowTitle("AES-GCM Core V3.0.3 收官版")
        self.setMinimumSize(640, 700); self.resize(720, 780)
        self.worker = None; self.scanner = None; self.filter_worker = None; self.current_mode = None
        self.task_queue = []; self.seen_paths = set(); self.vault = CredentialVault()
        self.dying_workers = []; self.active_dialog = None; self._pending_filtered_data = None
        self.abort_in_progress = False; self.fuse_timer = QTimer(self); self.fuse_timer.timeout.connect(self._fuse_melted)
        self.b_total = 0; self.b_success = 0; self.b_skip = 0; self.b_error = 0
        self.g_total_bytes = 0; self.g_proc_bytes = 0; self.g_start_time = 0
        
        central = QWidget(); self.setCentralWidget(central); main_ly = QVBoxLayout(central)
        self.drop_zone = QLabel("将文件/目录拖拽至此 (Drop Zone)")
        self.drop_zone.setFixedHeight(120); self.drop_zone.setAlignment(Qt.AlignCenter)
        self.drop_zone.setAcceptDrops(True); self.drop_zone.setObjectName("DropZone"); main_ly.addWidget(self.drop_zone)
        
        tools = QHBoxLayout()
        self.btn_add = QPushButton("📄 注入文件"); self.btn_dir = QPushButton("📁 注入目录"); self.btn_clear = QPushButton("🧹 清空队列")
        tools.addWidget(self.btn_add); tools.addWidget(self.btn_dir); tools.addWidget(self.btn_clear); main_ly.addLayout(tools)
        self.lbl_q = QLabel("任务队列：空闲 (0)"); self.lbl_q.setStyleSheet("color: #007acc;"); main_ly.addWidget(self.lbl_q)
        
        sets = QHBoxLayout(); self.chk_shred = QCheckBox("🖨️ 彻底粉碎 (头尾覆盖)")
        self.chk_smart = QCheckBox("🧠 智能过滤"); self.chk_smart.setChecked(True)
        sets.addWidget(self.chk_shred); sets.addWidget(self.chk_smart); main_ly.addLayout(sets)

        strat_ly = QHBoxLayout()
        strat_ly.addWidget(QLabel("冲突策略:"))
        self.combo_strat = QComboBox()
        self.combo_strat.addItems(["询问 (手动)", "自动更名", "自动跳过", "直接覆盖"])
        self.combo_strat.setCurrentIndex(1)
        strat_ly.addWidget(self.combo_strat); main_ly.addLayout(strat_ly)
        
        pwd_ly = QHBoxLayout(); self.inp_pwd = QLineEdit(); self.inp_pwd.setPlaceholderText("注入凭据"); self.inp_pwd.setEchoMode(QLineEdit.Password)
        self.btn_eye = QPushButton("透视"); self.btn_kill = QPushButton("销毁"); self.btn_kill.setObjectName("BtnLock")
        pwd_ly.addWidget(self.inp_pwd); pwd_ly.addWidget(self.btn_eye); pwd_ly.addWidget(self.btn_kill); main_ly.addLayout(pwd_ly)
        self.lbl_v = QLabel("🔒 保险箱状态：未装载"); main_ly.addWidget(self.lbl_v)
        
        self.combo_v = QComboBox(); self.combo_v.addItems(["V2.0.2 (Scrypt N=17)", "V1.0.1 (Scrypt N=14)", "V0.0.1 (PBKDF2)"]); main_ly.addWidget(self.combo_v)
        act_ly = QHBoxLayout(); self.btn_enc = QPushButton("开始封印"); self.btn_dec = QPushButton("解除封印"); self.btn_abort = QPushButton("紧急制动 (Abort)")
        self.btn_abort.setEnabled(False); act_ly.addWidget(self.btn_enc); act_ly.addWidget(self.btn_dec); act_ly.addWidget(self.btn_abort); main_ly.addLayout(act_ly)
        
        self.lbl_eta = QLabel("遥测: 待命 | ETA: 00:00"); self.lbl_eta.setStyleSheet("color: #4af626;"); main_ly.addWidget(self.lbl_eta)
        self.prog = QProgressBar(); self.prog.setTextVisible(False); main_ly.addWidget(self.prog)
        self.cons = QPlainTextEdit(); self.cons.setReadOnly(True); self.cons.setMaximumBlockCount(1000); main_ly.addWidget(self.cons)
        
        self.drop_zone.dragEnterEvent = self._drag_enter; self.drop_zone.dropEvent = self._drop_ev
        self.btn_add.clicked.connect(self._dialog_files); self.btn_dir.clicked.connect(self._dialog_dir); self.btn_clear.clicked.connect(self._clear_q)
        self.btn_eye.clicked.connect(self._toggle_pwd); self.btn_kill.clicked.connect(self._manual_lock)
        self.btn_enc.clicked.connect(lambda: self._start_batch('encrypt')); self.btn_dec.clicked.connect(lambda: self._start_batch('decrypt'))
        self.btn_abort.clicked.connect(self._abort_batch)
        
        self.heartbeat_timer = QTimer(self); self.heartbeat_timer.timeout.connect(self._heartbeat_ui); self.heartbeat_timer.start(1000)
        self.setStyleSheet(DARK_QSS)
        
        self._startup_cleanup()
        if initial_files: self._start_scan(initial_files)

    def _startup_cleanup(self):
        # 扫描程序目录下的残留临时文件
        exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        tmp_files = [f for f in os.listdir(exe_dir) if f.endswith('.tmp')]
        if tmp_files:
            reply = QMessageBox.question(self, "清理建议", f"检测到上次运行残留的临时文件 ({len(tmp_files)}个)，是否清理？", QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                for f in tmp_files:
                    try: os.remove(os.path.join(exe_dir, f))
                    except: pass
                logging.info(f"启动时清理了 {len(tmp_files)} 个残留临时文件。")

    def _heartbeat_ui(self):
        if self.vault.is_locked(): self.lbl_v.setText("🔒 状态：已锁定"); self.lbl_v.setStyleSheet("color: #aaaaaa;")
        else: m,s = divmod(self.vault.get_ttl(), 60); self.lbl_v.setText(f"🔓 活跃中 ({m:02d}:{s:02d})"); self.lbl_v.setStyleSheet("color: #4af626;")

    def _log(self, txt, sender=None):
        if sender and sender != self.worker: return
        logging.info(txt) # 写入本地日志文件
        sb = self.cons.verticalScrollBar(); at_bot = sb.value() >= sb.maximum()-10
        self.cons.appendPlainText(txt); 
        if at_bot: sb.setValue(sb.maximum())

    def _set_ui_lock(self, locked):
        for b in [self.btn_enc, self.btn_dec, self.combo_v, self.inp_pwd, self.btn_add, self.btn_dir, self.btn_clear, self.combo_strat]: b.setEnabled(not locked)
        self.drop_zone.setEnabled(not locked); self.btn_abort.setEnabled(locked)
        self.drop_zone.setText("引擎运行中 (锁定)" if locked else "将文件/目录拖拽至此 (Drop Zone)")
        if not locked: self.chk_shred.setChecked(False)

    def _abort_batch(self):
        if self.abort_in_progress: return
        self.abort_in_progress = True; self._log("[!!!] >>> 触发系统级紧急制动 <<<")
        if self.scanner: self.scanner.abort(); self.dying_workers.append(self.scanner); self.scanner = None
        if self.filter_worker: self.filter_worker.abort(); self.dying_workers.append(self.filter_worker); self.filter_worker = None
        if self.worker:
            self.worker._is_running = False; self.worker.overwrite_event.set(); self.worker.filename_event.set(); self.dying_workers.append(self.worker); self.worker = None
        if self.active_dialog: self.active_dialog.reject()
        self.task_queue.clear(); self.seen_paths.clear(); self.btn_abort.setEnabled(False)
        if not self.dying_workers: self._cleanup_unlock()
        else: self.fuse_timer.start(15000)

    def _fuse_melted(self): self.fuse_timer.stop(); self._log("[!] I/O 释放超时，强制复位。"); self._cleanup_unlock()

    def _cleanup_unlock(self):
        self.abort_in_progress = False; self.fuse_timer.stop(); self._set_ui_lock(False); self.lbl_q.setText(f"任务队列：空闲 ({len(self.task_queue)})")
        self._log(f"[统计] 载荷: {self.b_total} | 成功: {self.b_success} | 跳过: {self.b_skip} | 错误: {self.b_error}")

    def _start_batch(self, mode):
        if not self.task_queue: return
        self.current_mode = mode; self.cons.clear(); self.b_total = self.b_success = self.b_skip = self.b_error = self.g_proc_bytes = 0
        self.prog.setValue(0); self._set_ui_lock(True); self._log("[*] 开始扫描测算...")
        self.filter_worker = QueueFilterWorker(list(self.task_queue), mode, self.chk_smart.isChecked())
        self.filter_worker.results_ready_sig.connect(self._on_filter_results)
        self.filter_worker.finished_sig.connect(self._on_worker_dead); self.filter_worker.start()

    def _on_filter_results(self, filtered, skipped, total_bytes):
        if self.abort_in_progress: return
        self._pending_filtered_data = (filtered, skipped, total_bytes)

    def _on_worker_dead(self):
        s = self.sender()
        if s in self.dying_workers:
            self.dying_workers.remove(s); s.deleteLater()
            if not self.worker and not self.dying_workers and not self.scanner and not self.filter_worker: self._cleanup_unlock()
            return
        if s == self.worker:
            self.worker.deleteLater(); self.worker = None; self.prog.setValue(100); self.lbl_eta.setText("状态: 完结"); self._cleanup_unlock()
        elif s == self.scanner:
            self.scanner.deleteLater(); self.scanner = None; self._set_scan_lock(False)
        elif s == self.filter_worker:
            data = self._pending_filtered_data; self._pending_filtered_data = None
            self.filter_worker.deleteLater(); self.filter_worker = None
            if self.abort_in_progress or not data: return
            self._finalize_start_batch(*data)

    def _finalize_start_batch(self, filtered, skipped, total_bytes):
        self.task_queue = filtered; self.seen_paths = {os.path.normcase(x) for x,y in filtered}; self.b_total = len(filtered); self.g_total_bytes = total_bytes
        self._log(f"[*] 预检完成。容量: {total_bytes/(1024*1024):.2f} MB | 已隔离: {skipped}")
        if not filtered: self._cleanup_unlock(); return
        pwd = self.inp_pwd.text()
        if pwd:
            if self.current_mode == 'encrypt':
                self.active_dialog = QInputDialog(self); self.active_dialog.setWindowTitle("凭据确认"); self.active_dialog.setLabelText("封印任务开始前，再次核对凭据:"); self.active_dialog.setTextEchoMode(QLineEdit.Password)
                if not self.active_dialog.exec() or self.active_dialog.textValue() != pwd: self._cleanup_unlock(); return
                self.active_dialog.deleteLater(); self.active_dialog = None
            self.vault.unlock(pwd); self.inp_pwd.clear(); self._reset_pwd()
        elif self.vault.is_locked(): self._log("[-] 凭据未装载。"); self._cleanup_unlock(); return
        
        strat_map = {0: 'ask', 1: 'rename', 2: 'skip', 3: 'overwrite'}
        strat = strat_map[self.combo_strat.currentIndex()]
        
        self.g_start_time = time.time()
        self.worker = CryptoWorker(self.current_mode, 2-self.combo_v.currentIndex(), list(self.task_queue), self.vault, self.chk_shred.isChecked(), strat)
        self.task_queue.clear(); self.seen_paths.clear()
        self.worker.log_sig.connect(self._log); self.worker.progress_sig.connect(self._handle_prog)
        self.worker.file_done_sig.connect(self._handle_file_done); self.worker.finished_sig.connect(self._on_worker_dead)
        self.worker.ask_overwrite_sig.connect(self._handle_overwrite); self.worker.ask_filename_sig.connect(self._handle_v0)
        self.worker.heartbeat_sig.connect(self.vault.heartbeat); self.worker.start()

    def _handle_prog(self, inc):
        if self.sender() != self.worker: return
        self.g_proc_bytes += inc; elapsed = time.time()-self.g_start_time; speed = self.g_proc_bytes/elapsed if elapsed>0 else 0
        if self.g_total_bytes > 0:
            self.prog.setValue(int((self.g_proc_bytes/self.g_total_bytes)*100))
            eta = (self.g_total_bytes-self.g_proc_bytes)/speed if speed>0 else 0
            self.lbl_eta.setText(f"速度: {speed/(1024*1024):.2f} MB/s | ETA: {int(eta//60):02d}:{int(eta%60):02d}")

    def _handle_file_done(self, status, remaining):
        if self.sender() != self.worker: return
        self.g_proc_bytes += remaining 
        if status == "success": self.b_success += 1
        elif status == "skip": self.b_skip += 1
        else: self.b_error += 1
        self.lbl_q.setText(f"吞吐中 (剩余 {self.b_total - (self.b_success + self.b_skip + self.b_error)})")

    def _handle_overwrite(self, path, inplace):
        if self.sender() != self.worker: return
        self.active_dialog = QMessageBox(self); self.active_dialog.setWindowTitle("冲突处理")
        self.active_dialog.setText(f"目标已存在: {os.path.basename(path)}")
        b_yes = self.active_dialog.addButton("覆盖", QMessageBox.AcceptRole); b_ren = self.active_dialog.addButton("更名", QMessageBox.AcceptRole); b_no = self.active_dialog.addButton("跳过", QMessageBox.RejectRole)
        self.active_dialog.exec(); res = self.active_dialog.clickedButton()
        if res == b_yes: self.worker.overwrite_decision = True
        elif res == b_ren: self.worker.overwrite_decision = 'rename'
        else: self.worker.overwrite_decision = False
        self.worker.overwrite_event.set(); self.active_dialog.deleteLater(); self.active_dialog = None

    def _handle_v0(self, path):
        if self.sender() != self.worker: return
        self.active_dialog = V0FilenameDialog(self, path); self.active_dialog.exec()
        self.worker.filename_decision = self.active_dialog.result_val; self.worker.filename_event.set(); self.active_dialog.deleteLater(); self.active_dialog = None

    def _drag_enter(self, ev):
        if self.drop_zone.isEnabled() and ev.mimeData().hasUrls(): ev.accept()
    def _drop_ev(self, ev): self._start_scan([u.toLocalFile() for u in ev.mimeData().urls()])
    def _start_scan(self, ps):
        if self.scanner: return
        self._set_scan_lock(True); self.scanner = FileScannerWorker(ps)
        self.scanner.batch_found_sig.connect(self._on_scan_batch)
        self.scanner.finished_sig.connect(self._on_worker_dead); self.scanner.start()
    def _on_scan_batch(self, b):
        if self.abort_in_progress or not b or not self.scanner: return
        for p, sz in b:
            norm_p = os.path.normcase(p)
            if norm_p not in self.seen_paths: self.seen_paths.add(norm_p); self.task_queue.append((p, sz))
        self.lbl_q.setText(f"任务队列：载入中 ({len(self.task_queue)})")
    def _set_scan_lock(self, s):
        for b in [self.btn_enc, self.btn_dec]: b.setEnabled(not s)
        self.drop_zone.setText("深度扫描中..." if s else "将文件/目录拖拽至此 (Drop Zone)")
    def _clear_q(self):
        if self.scanner: self.scanner.abort()
        self.task_queue.clear(); self.seen_paths.clear(); self.lbl_q.setText("任务队列：空闲 (0)")
    def _dialog_files(self): ps,_ = QFileDialog.getOpenFileNames(self, "注入文件"); self._start_scan(ps) if ps else None
    def _dialog_dir(self): d = QFileDialog.getExistingDirectory(self, "注入目录"); self._start_scan([d]) if d else None
    def _manual_lock(self): self.vault.lock(); self._reset_pwd(); self._log("[!] 凭据已销毁。")
    def _reset_pwd(self): self.inp_pwd.setEchoMode(QLineEdit.Password); self.btn_eye.setText("透视")
    def _toggle_pwd(self):
        if self.inp_pwd.echoMode() == QLineEdit.Password: self.inp_pwd.setEchoMode(QLineEdit.Normal); self.btn_eye.setText("掩蔽")
        else: self._reset_pwd()
    def closeEvent(self, ev):
        self.vault.lock()
        for w in [self.worker, self.scanner, self.filter_worker]:
            if w: w._is_running = False; w.wait(1000)
        for d in self.dying_workers: d.wait(1000)
        ev.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv); app.setStyleSheet(DARK_QSS)
    win = MainWindow(initial_files=sys.argv[1:] if len(sys.argv)>1 else None); win.show(); sys.exit(app.exec())