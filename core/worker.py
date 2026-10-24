import os
import sys
import struct
import threading
import time
import queue
import stat
import ctypes
import gc

from PySide6.QtCore import QThread, Signal
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption,
    load_pem_private_key, load_pem_public_key
)
from cryptography.exceptions import InvalidTag

from core.config import (
    CHUNK_SIZE, IO_BUFFER_SIZE, MAX_CHUNK_PLAIN_LEN, MAX_CHUNK_CIPHER_LEN,
    MAX_WRAP_DEK_LEN, MAX_META_LEN, MAGIC_SFK_V1, MAGIC_ECC_V1, MAGIC_CHACHA_V1,
    MAGIC_V4, MAGIC_V3, MAGIC_V2, MAGIC_V1, MAGIC_HW_V1, SALT_SIZE, SCRYPT_N_V3, SCRYPT_N_V2,
    SCRYPT_N_V1, SCRYPT_N_SFK, KEYFILE_MAX_SIZE, VOLATILE_EXTENSIONS, logger
)
from core.memory import zero_bytes
from core.compression import StreamCompression
from core.resume_mgr import ResumeManager
from core.hardware import HardwareTokenManager
from core.utils import (
    format_crypto_error, safe_close, safe_remove, sanitize_filename,
    get_safe_win_path, force_replace, compute_file_blake2b, read_exact
)

class KeyfileHasherWorker(QThread):
    hash_ready_sig = Signal(int, str, bytes, int)
    error_sig = Signal(int, str, str)

    def __init__(self, keyfile_path, token):
        super().__init__()
        self.keyfile_path = keyfile_path
        self.token = token
        self._is_running = True

    def run(self):
        try:
            safe_p = get_safe_win_path(self.keyfile_path)
            sz = os.path.getsize(safe_p)
            h = hashes.Hash(hashes.BLAKE2b(64))
            with open(safe_p, 'rb', buffering=IO_BUFFER_SIZE) as f:
                while self._is_running:
                    buf = f.read(CHUNK_SIZE)
                    if not buf:
                        break
                    h.update(buf)
            if self._is_running:
                self.hash_ready_sig.emit(self.token, self.keyfile_path, h.finalize(), sz)
        except Exception as e:
            if self._is_running:
                self.error_sig.emit(self.token, self.keyfile_path, format_crypto_error(e))

    def abort(self):
        self._is_running = False

class WorkerProgressTracker:
    def __init__(self, worker_sig, w_id, filename, total_size):
        self.worker_sig = worker_sig
        self.w_id = w_id
        self.filename = filename
        self.total_size = total_size
        self.processed = 0
        self.last_emit = 0
        self.last_pct = -1

    def add(self, n):
        self.processed += n
        if self.total_size > 0:
            pct = min(100, int((self.processed * 100) // self.total_size))
            now = time.monotonic()
            if pct != self.last_pct and (now - self.last_emit >= 0.08 or pct in (0, 100)):
                self.last_pct = pct
                self.last_emit = now
                self.worker_sig.emit(self.w_id, self.filename, pct)

    def __getitem__(self, idx):
        return self.processed

    def __setitem__(self, idx, val):
        diff = val - self.processed
        self.add(diff)

class CryptoWorker(QThread):
    worker_status_sig = Signal(int, str, int)  # worker_id, filename, progress_percent
    throughput_sig = Signal(float, int)        # current_speed_MBs, eta_seconds
    file_start_sig = Signal(str)
    log_sig = Signal(str)
    progress_sig = Signal(int)
    file_done_sig = Signal(str, str, object)
    ask_overwrite_sig = Signal(str, bool)
    ask_filename_sig = Signal(str)
    heartbeat_sig = Signal()

    def __init__(self, mode, enc_type, enc_ver, queue, vault, shred, overwrite_strat, allow_v0, 
                 keyfile_path=None, peer_public_key=None, my_private_key=None, 
                 enable_backdoor=False, master_pubkey=None, master_privkey=None, 
                 batch_salt=None, precomputed_lock_hash=None, max_workers=1,
                 hw_serial=None):
        super().__init__()
        self.mode = mode
        self.enc_type = enc_type
        self.enc_ver = enc_ver
        self.queue = queue
        self.vault = vault
        self.shred = shred
        self.allow_v0 = allow_v0
        self.overwrite_strat = overwrite_strat
        self.keyfile_path = keyfile_path
        self.peer_public_key = peer_public_key
        self.my_private_key = my_private_key
        self.enable_backdoor = enable_backdoor
        self.master_pubkey = master_pubkey
        self.master_privkey = master_privkey
        self.max_workers = max(1, max_workers)
        self.hw_serial = hw_serial.strip().upper() if hw_serial else None
        
        self.overwrite_event = threading.Event()
        self.overwrite_decision = False
        self.filename_event = threading.Event()
        self.filename_decision = None
        
        self._is_running = True
        self.consecutive_errors = 0
        self.batch_salt = batch_salt or os.urandom(16)
        self._v4_cache_salt = None
        self._v4_cache_key = None
        self._pending_bytes = 0
        self._last_emit_time = time.monotonic()
        self._cached_lock_hash = precomputed_lock_hash
        self._emit_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._dialog_lock = threading.Lock()

    def run(self):
        try:
            if self.keyfile_path and not self._cached_lock_hash:
                try:
                    self.log_sig.emit("[*] 正在计算文件锁 BLAKE2b 摘要...")
                    self._cached_lock_hash = compute_file_blake2b(self.keyfile_path)
                except Exception as e:
                    self.log_sig.emit(f"[-] 文件锁读取/计算失败: {str(e)}")
                    return

            task_q = queue.Queue()
            for item in self.queue:
                task_q.put(item)

            consecutive_errors = 0
            error_lock = threading.Lock()

            def worker_loop(w_id=0):
                nonlocal consecutive_errors
                while self._is_running:
                    try:
                        item = task_q.get_nowait()
                        if isinstance(item, (list, tuple)) and len(item) >= 2:
                            file_path, file_size = item[0], item[1]
                        elif isinstance(item, (list, tuple)) and len(item) == 1:
                            file_path = item[0]
                            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                        else:
                            file_path = str(item)
                            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    except queue.Empty:
                        break

                    if self.enc_type in ('saes', 'chacha') and self.mode == 'encrypt' and self.vault.is_locked():
                        self.log_sig.emit("[-] 凭据超时已撤销，流水线紧急熔断。")
                        self._is_running = False
                        task_q.task_done()
                        break

                    self.file_start_sig.emit(file_path)
                    expected_work = file_size * 2 if (self.shred and self.mode == 'encrypt') else file_size
                    reported_in_file = WorkerProgressTracker(self.worker_status_sig, w_id, os.path.basename(file_path), expected_work)
                    self.worker_status_sig.emit(w_id, os.path.basename(file_path), 0)
                    try:
                        res = self._process_single(file_path, file_size, reported_in_file)
                        if res == "SKIP_V0":
                            self.log_sig.emit(f"[{os.path.basename(file_path)}] V0 协议未开启兼容，已跳过。")
                            self.file_done_sig.emit(file_path, "skip", (expected_work, reported_in_file[0]))
                        elif res:
                            shred_ok = True
                            if self.mode == 'encrypt' and self.shred:
                                shred_ok = self._secure_delete(file_path, file_size, reported_in_file)
                            if shred_ok:
                                with error_lock:
                                    consecutive_errors = 0
                                self.file_done_sig.emit(file_path, "success", (expected_work, reported_in_file[0]))
                            else:
                                with error_lock:
                                    consecutive_errors += 1
                                self.file_done_sig.emit(file_path, "error", (expected_work, reported_in_file[0]))
                        elif not self._is_running:
                            break
                        else:
                            with error_lock:
                                consecutive_errors = 0
                            self.file_done_sig.emit(file_path, "skip", (expected_work, reported_in_file[0]))
                    except InvalidTag as it_err:
                        err_msg = format_crypto_error(it_err)
                        self.log_sig.emit(f"[{os.path.basename(file_path)}] {err_msg}")
                        self.file_done_sig.emit(file_path, "error", (expected_work, reported_in_file[0]))
                        self._is_running = False
                        break
                    except (PermissionError, OSError) as os_err:
                        with error_lock:
                            consecutive_errors += 1
                            cur_errs = consecutive_errors
                        err_msg = format_crypto_error(os_err)
                        self.log_sig.emit(f"[{os.path.basename(file_path)}] {err_msg}")
                        self.file_done_sig.emit(file_path, "error", (expected_work, reported_in_file[0]))
                        if cur_errs >= 5:
                            self.log_sig.emit("[-] 连续遭遇系统 I/O 或权限错误达 5 次，安全熔断制动。")
                            self._is_running = False
                            break
                    except Exception as e:
                        with error_lock:
                            consecutive_errors += 1
                            cur_errs = consecutive_errors
                        err_msg = format_crypto_error(e)
                        self.log_sig.emit(f"[{os.path.basename(file_path)}] 发生异常: {err_msg}")
                        self.file_done_sig.emit(file_path, "error", (expected_work, reported_in_file[0]))
                        if cur_errs >= 10:
                            self.log_sig.emit("[-] 连续错误次数达上限 10 次，流水线已熔断。")
                            self._is_running = False
                            break
                    finally:
                        self.worker_status_sig.emit(w_id, "空闲", 0)
                        self._flush_emit()
                        task_q.task_done()
                self.worker_status_sig.emit(w_id, "空闲", 0)

            actual_workers = min(self.max_workers, len(self.queue))
            if actual_workers <= 1:
                worker_loop(0)
            else:
                threads = [threading.Thread(target=worker_loop, args=(i,), daemon=True) for i in range(actual_workers)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
        finally:
            with self._cache_lock:
                if self._v4_cache_key:
                    zero_bytes(self._v4_cache_key)
                    self._v4_cache_key = None
            if self._cached_lock_hash:
                zero_bytes(self._cached_lock_hash)
                self._cached_lock_hash = None
            self._flush_emit()
            gc.collect()

    def _throttle_emit(self, byte_count):
        with self._emit_lock:
            self._pending_bytes += byte_count
            now = time.monotonic()
            if now - self._last_emit_time >= 0.08:
                self.progress_sig.emit(self._pending_bytes)
                self._pending_bytes = 0
                self._last_emit_time = now
                if self.vault:
                    self.vault.heartbeat()

    def _flush_emit(self):
        with self._emit_lock:
            if self.vault:
                self.vault.heartbeat()
            if self._pending_bytes > 0:
                self.progress_sig.emit(self._pending_bytes)
                self._pending_bytes = 0
                self._last_emit_time = time.monotonic()

    def _check_overwrite(self, out_p):
        if self.overwrite_strat == 'overwrite':
            return True
        if self.overwrite_strat == 'skip':
            return not os.path.exists(out_p)
        if self.overwrite_strat == 'rename':
            return self._rename(out_p) if os.path.exists(out_p) else True
        if os.path.exists(out_p):
            with self._dialog_lock:
                if not self._is_running:
                    return None
                self.ask_overwrite_sig.emit(out_p, False)
                self.overwrite_event.wait()
                if not self._is_running:
                    return None
                res = self.overwrite_decision
                self.overwrite_event.clear()
                return self._rename(out_p) if res == 'rename' else res
        return True

    def _rename(self, path):
        base, ext = os.path.splitext(path)
        new_p = f"{base}_{time.strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}{ext}"
        while os.path.exists(new_p):
            new_p = f"{base}_{time.strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}{ext}"
        return new_p

    def _secure_delete(self, path, file_size, prog_container=None):
        try:
            path = get_safe_win_path(path)
            orig_mode = stat.S_IMODE(os.stat(path).st_mode)
            os.chmod(path, orig_mode | stat.S_IWRITE)
            size = file_size
            if size > 0:
                zero_buf = b'\x00' * min(CHUNK_SIZE, 4 * 1024 * 1024)
                zero_mv = memoryview(zero_buf)
                with open(path, 'r+b', buffering=IO_BUFFER_SIZE) as f:
                    written = 0
                    while written < size and self._is_running:
                        chunk_sz = min(CHUNK_SIZE, size - written)
                        if chunk_sz == len(zero_buf):
                            f.write(zero_buf)
                        else:
                            f.write(zero_mv[:chunk_sz])
                        written += chunk_sz
                        if prog_container is not None:
                            prog_container[0] += chunk_sz
                        self._throttle_emit(chunk_sz)
                    f.flush()
                    os.fsync(f.fileno())
            if not self._is_running:
                self.log_sig.emit(f"[!] 任务已制动，保留未完整粉碎的原文件: {os.path.basename(path)}")
                return False
            os.remove(path)
            return True
        except Exception as e:
            self.log_sig.emit(f"[!] 原文件粉碎失败: {os.path.basename(path)} ({format_crypto_error(e)})")
            return False

    def _process_single(self, path, file_size, prog_container=None):
        path = get_safe_win_path(path)
        if self.mode == 'encrypt':
            if self.enc_type == 'filekey':
                return self._enc_sfk(path, file_size, prog_container)
            if self.enc_type == 'ecc':
                return self._enc_ecc(path, file_size, prog_container)
            if self.enc_type == 'chacha':
                return self._enc_chacha(path, file_size, prog_container)
            if self.enc_ver == 4: return self._enc_v4(path, file_size, prog_container)
            if self.enc_ver == 3: return self._enc_v3(path, file_size, prog_container)
            return self._enc_v3(path, file_size, prog_container)
        else:
            with open(path, 'rb') as f:
                magic = f.read(5)
            
            hw_offset = 0
            hw_serial = None
            if magic == MAGIC_HW_V1:
                with open(path, 'rb') as f:
                    f.seek(5)
                    lb = f.read(1)
                    if not lb:
                        raise ValueError("硬件锁头部损坏")
                    slen = struct.unpack('>B', lb)[0]
                    serial_bytes = f.read(slen)
                    hw_serial = serial_bytes.decode('utf-8', errors='replace').strip().upper()
                    hw_offset = 5 + 1 + slen
                    inner_magic = f.read(5)
                
                # 严格物理硬件锁核验：未插入则物理阻断抛出异常
                is_present, drive_info = HardwareTokenManager.verify_token_present(hw_serial)
                if not is_present:
                    raise ValueError(f"【硬件锁拦截】该文件已物理绑定硬件钥匙设备 (序列号: {hw_serial})，当前电脑未插入该 U 盘 / 移动硬盘，解密被物理拒绝！")
                
                self.log_sig.emit(f"[*] 硬件锁核验通过: 已识别绑定的物理设备 [{drive_info['drive']}] {drive_info['label']} (序列号: {hw_serial})")
                magic = inner_magic

            if magic == MAGIC_SFK_V1: return self._dec_sfk(path, prog_container, hw_offset=hw_offset, hw_serial=hw_serial)
            if magic == MAGIC_ECC_V1: return self._dec_ecc(path, prog_container, hw_offset=hw_offset, hw_serial=hw_serial)
            if magic == MAGIC_CHACHA_V1: return self._dec_chacha(path, prog_container, hw_offset=hw_offset, hw_serial=hw_serial)
            if magic == MAGIC_V4: return self._dec_v4(path, prog_container, hw_offset=hw_offset, hw_serial=hw_serial)
            if magic == MAGIC_V3: return self._dec_v3(path, prog_container, hw_offset=hw_offset, hw_serial=hw_serial)
            if magic == MAGIC_V2: return self._dec_v2(path, prog_container)
            if magic == MAGIC_V1: return self._dec_v1(path, prog_container)
            if not self.allow_v0: return "SKIP_V0"
            return self._dec_v0(path, prog_container)

    def _derive_sfk_lock_key(self, lock_hash, salt, hw_serial=None):
        kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N_SFK, r=8, p=1)
        scrypt_key = kdf.derive(lock_hash)
        try:
            info_str = b"SFK_V1_STRETCHED_KEY" + (b":HW:" + hw_serial.encode('utf-8') if hw_serial else b"")
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info_str)
            return hkdf.derive(scrypt_key)
        finally:
            zero_bytes(scrypt_key)

    def _enc_sfk(self, path, file_size, prog_container=None):
        out_p = path + '.enc'
        chk = self._check_overwrite(out_p)
        if not chk: return None
        if isinstance(chk, str): out_p = chk
        
        if not self._cached_lock_hash:
            raise ValueError("未载入有效的文件锁摘要")
            
        salt = os.urandom(16)
        nonce_file = os.urandom(8)
        dek_ba = bytearray(os.urandom(32))
        lock_key = None
        escrow_key = None
        shared_secret = None
        
        try:
            lock_key = self._derive_sfk_lock_key(self._cached_lock_hash, salt, self.hw_serial)
            flags = 0
            backdoor_block = b""
            if self.enable_backdoor and self.master_pubkey:
                if not isinstance(self.master_pubkey, x25519.X25519PublicKey):
                    raise TypeError("主公钥类型错误，必须为 X25519PublicKey")
                flags |= 0x01
                eph_priv = x25519.X25519PrivateKey.generate()
                eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                shared_secret = eph_priv.exchange(self.master_pubkey)
                hkdf_escrow = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"SFK_MASTER_ESCROW")
                escrow_key = hkdf_escrow.derive(shared_secret)
                
                escrow_aad = MAGIC_SFK_V1 + struct.pack('>B', flags) + salt + nonce_file + eph_pub_bytes
                gcm_escrow = AESGCM(escrow_key)
                enc_dek_escrow = gcm_escrow.encrypt(nonce_file + b'\x00\x00\x00\x02', bytes(dek_ba), escrow_aad)
                backdoor_block = eph_pub_bytes + struct.pack('>H', len(enc_dek_escrow)) + enc_dek_escrow

            lock_aad = MAGIC_SFK_V1 + struct.pack('>B', flags) + salt + nonce_file + backdoor_block
            gcm_lock = AESGCM(lock_key)
            enc_dek_lock = gcm_lock.encrypt(nonce_file + b'\x00\x00\x00\x01', bytes(dek_ba), lock_aad)

            gcm_payload = AESGCM(bytes(dek_ba))
            meta_plain = struct.pack('>Q', file_size) + os.path.basename(path).encode('utf-8')
            enc_meta = gcm_payload.encrypt(nonce_file + b'\x00\x00\x00\x00', meta_plain, None)
            
            tmp = out_p + '.tmp'
            fi = fo = None
            try:
                fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
                fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
                if self.hw_serial:
                    s_bytes = self.hw_serial.encode('utf-8')
                    fo.write(MAGIC_HW_V1 + struct.pack('>B', len(s_bytes)) + s_bytes)
                header = (
                    MAGIC_SFK_V1 +
                    struct.pack('>B', flags) +
                    salt +
                    nonce_file +
                    struct.pack('>H', len(enc_dek_lock)) +
                    enc_dek_lock +
                    (struct.pack('>H', len(backdoor_block)) + backdoor_block if (flags & 0x01) else b"") +
                    struct.pack('>H', len(enc_meta)) +
                    enc_meta
                )
                fo.write(header)
                c = 1
                while self._is_running:
                    buf = fi.read(CHUNK_SIZE)
                    if not buf:
                        break
                    enc_chunk = gcm_payload.encrypt(nonce_file + struct.pack('>I', c), buf, None)
                    fo.write(struct.pack('>I', len(enc_chunk)))
                    fo.write(enc_chunk)
                    if prog_container is not None: prog_container[0] += len(buf)
                    self._throttle_emit(len(buf))
                    c += 1
                if self._is_running:
                    safe_close(fi); safe_close(fo); fi = fo = None
                    force_replace(tmp, out_p)
                    return out_p
            finally:
                safe_close(fi); safe_close(fo); safe_remove(tmp)
        finally:
            zero_bytes(dek_ba, lock_key, escrow_key, shared_secret)

    def _dec_sfk(self, path, prog_container=None, hw_offset=0, hw_serial=None):
        fi = fo = tmp = None
        dek = None
        dek_ba = None
        lock_key = None
        escrow_key = None
        shared_secret = None
        try:
            fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
            if hw_offset > 0:
                fi.seek(hw_offset)
            magic = read_exact(fi, 5)
            if magic != MAGIC_SFK_V1:
                raise ValueError("SFK 魔数无效")
            flags = struct.unpack('>B', read_exact(fi, 1))[0]
            if flags not in (0x00, 0x01):
                raise ValueError(f"SFK 头部包含未定义的 flags 标志位: 0x{flags:02X}")
                
            salt = read_exact(fi, 16)
            nonce_file = read_exact(fi, 8)
            len_lock_dek = struct.unpack('>H', read_exact(fi, 2))[0]
            if len_lock_dek > MAX_WRAP_DEK_LEN:
                raise ValueError("封印密钥长度超出限制")
            enc_dek_lock = read_exact(fi, len_lock_dek)
            
            backdoor_block = b""
            backdoor_eph_pub = None
            enc_dek_escrow = None
            if flags & 0x01:
                len_bd = struct.unpack('>H', read_exact(fi, 2))[0]
                if len_bd < 34 or len_bd > 4096:
                    raise ValueError(f"畸形后门数据块: 长度为 {len_bd}")
                bd_data = read_exact(fi, len_bd)
                backdoor_block = bd_data
                backdoor_eph_pub = bd_data[:32]
                bd_dek_len = struct.unpack('>H', bd_data[32:34])[0]
                if 34 + bd_dek_len != len_bd:
                    raise ValueError("后门 DEK 结构长度不符")
                enc_dek_escrow = bd_data[34:34 + bd_dek_len]
                
            len_meta = struct.unpack('>H', read_exact(fi, 2))[0]
            if len_meta > MAX_META_LEN:
                raise ValueError("元数据长度超出限制")
            enc_meta = read_exact(fi, len_meta)

            dek = None
            if self._cached_lock_hash:
                try:
                    lock_key = self._derive_sfk_lock_key(self._cached_lock_hash, salt, hw_serial)
                    lock_aad = MAGIC_SFK_V1 + struct.pack('>B', flags) + salt + nonce_file + backdoor_block
                    gcm_lock = AESGCM(lock_key)
                    dek = gcm_lock.decrypt(nonce_file + b'\x00\x00\x00\x01', enc_dek_lock, lock_aad)
                except InvalidTag:
                    dek = None
                except Exception as ex:
                    self.log_sig.emit(f"[{os.path.basename(path)}] 锁解密异常: {str(ex)}")
                    dek = None

            if not dek and (flags & 0x01) and self.master_privkey and enc_dek_escrow and backdoor_eph_pub:
                try:
                    if not isinstance(self.master_privkey, x25519.X25519PrivateKey):
                        raise TypeError("master_privkey 必须为 X25519PrivateKey")
                    peer_eph_key = x25519.X25519PublicKey.from_public_bytes(backdoor_eph_pub)
                    shared_secret = self.master_privkey.exchange(peer_eph_key)
                    hkdf_escrow = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"SFK_MASTER_ESCROW")
                    escrow_key = hkdf_escrow.derive(shared_secret)
                    
                    escrow_aad = MAGIC_SFK_V1 + struct.pack('>B', flags) + salt + nonce_file + backdoor_eph_pub
                    gcm_escrow = AESGCM(escrow_key)
                    dek = gcm_escrow.decrypt(nonce_file + b'\x00\x00\x00\x02', enc_dek_escrow, escrow_aad)
                    self.log_sig.emit(f"[{os.path.basename(path)}] 文件锁未匹配，触发主私钥后门成功救援！")
                except InvalidTag:
                    dek = None
                except Exception as ex:
                    dek = None
                    self.log_sig.emit(f"[{os.path.basename(path)}] 主私钥后门救援尝试失败: {str(ex)}")

            if not dek:
                raise InvalidTag("文件锁不匹配，且无法通过主私钥后门救援")

            dek_ba = bytearray(dek)
            gcm_payload = AESGCM(bytes(dek_ba))
            meta_plain = gcm_payload.decrypt(nonce_file + b'\x00\x00\x00\x00', enc_meta, None)
            if len(meta_plain) < 8:
                raise ValueError("元数据损坏，长度不足 8 字节")
            expected_file_size = struct.unpack('>Q', meta_plain[:8])[0]
            orig_filename = sanitize_filename(meta_plain[8:].decode('utf-8', errors='replace'))
            out_p = get_safe_win_path(os.path.join(os.path.dirname(path), orig_filename))
            
            chk = self._check_overwrite(out_p)
            if not chk: return None
            if isinstance(chk, str): out_p = chk
            
            tmp = out_p + '.tmp'
            fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
            c = 1
            total_plain_written = 0
            while self._is_running:
                lb = fi.read(4)
                if not lb:
                    break
                if len(lb) != 4:
                    raise ValueError("分块头长度截断")
                chunk_len = struct.unpack('>I', lb)[0]
                if chunk_len > MAX_CHUNK_CIPHER_LEN or chunk_len < 16:
                    raise ValueError(f"分块密文长度非法: {chunk_len}")
                raw_chunk = read_exact(fi, chunk_len)
                chunk = gcm_payload.decrypt(nonce_file + struct.pack('>I', c), raw_chunk, None)
                fo.write(chunk)
                total_plain_written += len(chunk)
                if prog_container is not None: prog_container[0] += len(chunk)
                self._throttle_emit(len(chunk))
                c += 1
                
            if self._is_running:
                if total_plain_written != expected_file_size:
                    raise ValueError(f"文件大小校验不符！预期 {expected_file_size} 字节，实际恢复 {total_plain_written} 字节")
                safe_close(fi); safe_close(fo); fi = fo = None
                force_replace(tmp, out_p)
                return out_p
        finally:
            zero_bytes(dek, dek_ba, lock_key, escrow_key, shared_secret)
            safe_close(fi); safe_close(fo); safe_remove(tmp)

    def _enc_ecc(self, path, file_size, prog_container=None):
        out_p = path + '.enc'
        chk = self._check_overwrite(out_p)
        if not chk: return None
        if isinstance(chk, str): out_p = chk
        
        if not self.peer_public_key or not isinstance(self.peer_public_key, x25519.X25519PublicKey):
            raise ValueError("缺少有效的接收方 X25519 公钥")
            
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared_secret = eph_priv.exchange(self.peer_public_key)
        
        salt = os.urandom(16)
        nonce_file = os.urandom(8)
        dek_ba = bytearray(os.urandom(32))
        wrap_key = None
        
        try:
            info_str = b"SAECC_V1_DEK_WRAP" + (b":HW:" + self.hw_serial.encode('utf-8') if self.hw_serial else b"")
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info_str)
            wrap_key = hkdf.derive(shared_secret)
            
            gcm_wrap = AESGCM(wrap_key)
            enc_dek = gcm_wrap.encrypt(nonce_file + b'\x00\x00\x00\x01', bytes(dek_ba), MAGIC_ECC_V1 + salt + eph_pub_bytes)
            
            gcm_payload = AESGCM(bytes(dek_ba))
            meta_plain = struct.pack('>Q', file_size) + os.path.basename(path).encode('utf-8')
            enc_meta = gcm_payload.encrypt(nonce_file + b'\x00\x00\x00\x00', meta_plain, None)
            
            tmp = out_p + '.tmp'
            fi = fo = None
            try:
                fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
                fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
                if self.hw_serial:
                    s_bytes = self.hw_serial.encode('utf-8')
                    fo.write(MAGIC_HW_V1 + struct.pack('>B', len(s_bytes)) + s_bytes)
                header = (
                    MAGIC_ECC_V1 +
                    salt +
                    nonce_file +
                    eph_pub_bytes +
                    struct.pack('>H', len(enc_dek)) +
                    enc_dek +
                    struct.pack('>H', len(enc_meta)) +
                    enc_meta
                )
                fo.write(header)
                c = 1
                while self._is_running:
                    buf = fi.read(CHUNK_SIZE)
                    if not buf: break
                    enc_chunk = gcm_payload.encrypt(nonce_file + struct.pack('>I', c), buf, None)
                    fo.write(struct.pack('>I', len(enc_chunk)))
                    fo.write(enc_chunk)
                    if prog_container is not None: prog_container[0] += len(buf)
                    self._throttle_emit(len(buf))
                    c += 1
                if self._is_running:
                    safe_close(fi); safe_close(fo); fi = fo = None
                    force_replace(tmp, out_p)
                    return out_p
            finally:
                safe_close(fi); safe_close(fo); safe_remove(tmp)
        finally:
            zero_bytes(dek_ba, shared_secret, wrap_key)

    def _dec_ecc(self, path, prog_container=None, hw_offset=0, hw_serial=None):
        fi = fo = tmp = None
        dek = None
        dek_ba = None
        shared_secret = None
        wrap_key = None
        try:
            if not self.my_private_key or not isinstance(self.my_private_key, x25519.X25519PrivateKey):
                raise ValueError("未装载用于解密该文件的本地 X25519 私钥")
                
            fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
            if hw_offset > 0:
                fi.seek(hw_offset)
            magic = read_exact(fi, 5)
            if magic != MAGIC_ECC_V1:
                raise ValueError("ECC 协议魔数无效")
            salt = read_exact(fi, 16)
            nonce_file = read_exact(fi, 8)
            eph_pub_bytes = read_exact(fi, 32)
            len_enc_dek = struct.unpack('>H', read_exact(fi, 2))[0]
            if len_enc_dek > MAX_WRAP_DEK_LEN:
                raise ValueError("ECC 封装 DEK 长度超限")
            enc_dek = read_exact(fi, len_enc_dek)
            len_enc_meta = struct.unpack('>H', read_exact(fi, 2))[0]
            if len_enc_meta > MAX_META_LEN:
                raise ValueError("ECC 元数据长度超限")
            enc_meta = read_exact(fi, len_enc_meta)
                
            peer_eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
            shared_secret = self.my_private_key.exchange(peer_eph_pub)
            
            info_str = b"SAECC_V1_DEK_WRAP" + (b":HW:" + hw_serial.encode('utf-8') if hw_serial else b"")
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info_str)
            wrap_key = hkdf.derive(shared_secret)
            
            gcm_wrap = AESGCM(wrap_key)
            dek = gcm_wrap.decrypt(nonce_file + b'\x00\x00\x00\x01', enc_dek, MAGIC_ECC_V1 + salt + eph_pub_bytes)
            dek_ba = bytearray(dek)
            
            gcm_payload = AESGCM(bytes(dek_ba))
            meta_plain = gcm_payload.decrypt(nonce_file + b'\x00\x00\x00\x00', enc_meta, None)
            if len(meta_plain) < 8:
                raise ValueError("ECC 元数据损坏")
            expected_file_size = struct.unpack('>Q', meta_plain[:8])[0]
            orig_filename = sanitize_filename(meta_plain[8:].decode('utf-8', errors='replace'))
            out_p = get_safe_win_path(os.path.join(os.path.dirname(path), orig_filename))
            
            chk = self._check_overwrite(out_p)
            if not chk: return None
            if isinstance(chk, str): out_p = chk
            
            tmp = out_p + '.tmp'
            fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
            c = 1
            total_plain_written = 0
            while self._is_running:
                lb = fi.read(4)
                if not lb: break
                if len(lb) != 4: raise ValueError("分块头截断")
                chunk_len = struct.unpack('>I', lb)[0]
                if chunk_len > MAX_CHUNK_CIPHER_LEN or chunk_len < 16:
                    raise ValueError(f"非法分块密文长度: {chunk_len}")
                raw_chunk = read_exact(fi, chunk_len)
                chunk = gcm_payload.decrypt(nonce_file + struct.pack('>I', c), raw_chunk, None)
                fo.write(chunk)
                total_plain_written += len(chunk)
                if prog_container is not None: prog_container[0] += len(chunk)
                self._throttle_emit(len(chunk))
                c += 1
                
            if self._is_running:
                if total_plain_written != expected_file_size:
                    raise ValueError(f"ECC 文件大小校验失败！预期 {expected_file_size}，实际 {total_plain_written}")
                safe_close(fi); safe_close(fo); fi = fo = None
                force_replace(tmp, out_p)
                return out_p
        finally:
            zero_bytes(dek, dek_ba, shared_secret, wrap_key)
            safe_close(fi); safe_close(fo); safe_remove(tmp)


    def _enc_chacha(self, path, file_size, prog_container=None):
        out_p = path + '.enc'
        chk = self._check_overwrite(out_p)
        if not chk: return None
        if isinstance(chk, str): out_p = chk
        
        pwd = self.vault.get_password_copy()
        if not pwd: raise ValueError("凭据不可用")
        
        tmp = out_p + '.tmp'
        fi = fo = None
        file_key = None
        try:
            master_salt = self.batch_salt
            file_salt = os.urandom(16)
            nonce_file = os.urandom(8)
            
            with self._cache_lock:
                if master_salt == self._v4_cache_salt and self._v4_cache_key:
                    master_key = bytes(self._v4_cache_key)
                    zero_bytes(pwd)
                else:
                    try:
                        kdf = Scrypt(salt=master_salt, length=32, n=SCRYPT_N_V3, r=8, p=1)
                        master_key = kdf.derive(bytes(pwd))
                    finally:
                        zero_bytes(pwd)
                    self._v4_cache_salt = master_salt
                    self._v4_cache_key = bytearray(master_key)
                
            info_str = b"SAES_CHACHA_FILE_KEY" + (b":HW:" + self.hw_serial.encode('utf-8') if self.hw_serial else b"")
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=file_salt, info=info_str)
            file_key = hkdf.derive(master_key)
            
            self.heartbeat_sig.emit()
            chacha = ChaCha20Poly1305(file_key)
            head = MAGIC_CHACHA_V1 + master_salt + file_salt + nonce_file
            meta = chacha.encrypt(nonce_file + b'\x00\x00\x00\x00', struct.pack('>Q', file_size) + os.path.basename(path).encode('utf-8'), head)
            
            fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
            fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
            if self.hw_serial:
                s_bytes = self.hw_serial.encode('utf-8')
                fo.write(MAGIC_HW_V1 + struct.pack('>B', len(s_bytes)) + s_bytes)
            fo.write(head + struct.pack('>H', len(meta)) + meta)
            
            c = 1
            while self._is_running:
                buf = fi.read(CHUNK_SIZE)
                if not buf: break
                enc_chunk = chacha.encrypt(nonce_file + struct.pack('>I', c), buf, None)
                fo.write(struct.pack('>I', len(enc_chunk)))
                fo.write(enc_chunk)
                if prog_container is not None: prog_container[0] += len(buf)
                self._throttle_emit(len(buf))
                c += 1
            if self._is_running:
                safe_close(fi); safe_close(fo); fi = fo = None
                force_replace(tmp, out_p)
                return out_p
        finally:
            zero_bytes(pwd, file_key)
            safe_close(fi); safe_close(fo); safe_remove(tmp)

    def _dec_chacha(self, path, prog_container=None, hw_offset=0, hw_serial=None):
        tmp = fi = fo = None
        pwd = None
        file_key = None
        try:
            fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
            if hw_offset > 0:
                fi.seek(hw_offset)
            magic = read_exact(fi, 5)
            if magic != MAGIC_CHACHA_V1: raise ValueError("ChaCha20 魔数错误")
            master_salt = read_exact(fi, 16)
            file_salt = read_exact(fi, 16)
            nonce_file = read_exact(fi, 8)
            len_meta = struct.unpack('>H', read_exact(fi, 2))[0]
            if len_meta > MAX_META_LEN: raise ValueError("ChaCha20 元数据超限")
            emeta = read_exact(fi, len_meta)
                
            pwd = self.vault.get_password_copy()
            if not pwd: raise ValueError("凭据已失效")
            
            with self._cache_lock:
                if master_salt == self._v4_cache_salt and self._v4_cache_key:
                    master_key = bytes(self._v4_cache_key)
                    zero_bytes(pwd)
                else:
                    try:
                        kdf = Scrypt(salt=master_salt, length=32, n=SCRYPT_N_V3, r=8, p=1)
                        master_key = kdf.derive(bytes(pwd))
                    finally:
                        zero_bytes(pwd)
                    self._v4_cache_salt = master_salt
                    self._v4_cache_key = bytearray(master_key)
                
            info_str = b"SAES_CHACHA_FILE_KEY" + (b":HW:" + hw_serial.encode('utf-8') if hw_serial else b"")
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=file_salt, info=info_str)
            file_key = hkdf.derive(master_key)
            
            self.heartbeat_sig.emit()
            chacha = ChaCha20Poly1305(file_key)
            head = MAGIC_CHACHA_V1 + master_salt + file_salt + nonce_file
            meta = chacha.decrypt(nonce_file + b'\x00\x00\x00\x00', emeta, head)
            if len(meta) < 8: raise ValueError("ChaCha20 元数据损坏")
            expected_file_size = struct.unpack('>Q', meta[:8])[0]
            out_p = get_safe_win_path(os.path.join(os.path.dirname(path), sanitize_filename(meta[8:].decode('utf-8', errors='replace'))))
            
            chk = self._check_overwrite(out_p)
            if not chk: return None
            if isinstance(chk, str): out_p = chk
            tmp = out_p + '.tmp'
            
            fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
            c = 1
            total_plain_written = 0
            while self._is_running:
                lb = fi.read(4)
                if not lb: break
                if len(lb) != 4: raise ValueError("分块头截断")
                chunk_len = struct.unpack('>I', lb)[0]
                if chunk_len > MAX_CHUNK_CIPHER_LEN or chunk_len < 16:
                    raise ValueError(f"ChaCha20 密文分块长度非法: {chunk_len}")
                raw_chunk = read_exact(fi, chunk_len)
                chunk = chacha.decrypt(nonce_file + struct.pack('>I', c), raw_chunk, None)
                fo.write(chunk)
                total_plain_written += len(chunk)
                if prog_container is not None: prog_container[0] += len(chunk)
                self._throttle_emit(len(chunk))
                c += 1
            if self._is_running:
                if total_plain_written != expected_file_size:
                    raise ValueError(f"ChaCha20 校验失败！预期 {expected_file_size}，实际 {total_plain_written}")
                safe_close(fi); safe_close(fo); fi = fo = None
                force_replace(tmp, out_p)
                return out_p
        finally:
            zero_bytes(pwd, file_key)
            safe_close(fi); safe_close(fo); safe_remove(tmp)

    def _enc_v4(self, path, file_size, prog_container=None):
        out_p = path + '.enc'
        chk = self._check_overwrite(out_p)
        if not chk: return None
        if isinstance(chk, str): out_p = chk
        
        pwd = self.vault.get_password_copy()
        if not pwd: raise ValueError("凭据不可用")
        
        tmp = out_p + '.tmp'
        fi = fo = None
        file_key = None
        try:
            master_salt = self.batch_salt
            file_salt = os.urandom(16)
            nonce_file = os.urandom(8)
            
            with self._cache_lock:
                if master_salt == self._v4_cache_salt and self._v4_cache_key:
                    master_key = bytes(self._v4_cache_key)
                    zero_bytes(pwd)
                else:
                    try:
                        kdf = Scrypt(salt=master_salt, length=32, n=SCRYPT_N_V3, r=8, p=1)
                        master_key = kdf.derive(bytes(pwd))
                    finally:
                        zero_bytes(pwd)
                    self._v4_cache_salt = master_salt
                    self._v4_cache_key = bytearray(master_key)
                
            info_str = b"SAES_V4_FILE_KEY" + (b":HW:" + self.hw_serial.encode('utf-8') if self.hw_serial else b"")
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=file_salt, info=info_str)
            file_key = hkdf.derive(master_key)
            
            self.heartbeat_sig.emit()
            gcm = AESGCM(file_key)
            head = MAGIC_V4 + master_salt + file_salt + nonce_file
            meta = gcm.encrypt(nonce_file + b'\x00\x00\x00\x00', struct.pack('>Q', file_size) + os.path.basename(path).encode('utf-8'), head)
            
            fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
            fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
            if self.hw_serial:
                s_bytes = self.hw_serial.encode('utf-8')
                fo.write(MAGIC_HW_V1 + struct.pack('>B', len(s_bytes)) + s_bytes)
            fo.write(head + struct.pack('>H', len(meta)) + meta)
            
            c = 1
            while self._is_running:
                buf = fi.read(CHUNK_SIZE)
                if not buf: break
                enc_chunk = gcm.encrypt(nonce_file + struct.pack('>I', c), buf, None)
                fo.write(struct.pack('>I', len(enc_chunk)))
                fo.write(enc_chunk)
                if prog_container is not None: prog_container[0] += len(buf)
                self._throttle_emit(len(buf))
                c += 1
            if self._is_running:
                safe_close(fi); safe_close(fo); fi = fo = None
                force_replace(tmp, out_p)
                return out_p
        finally:
            zero_bytes(pwd, file_key)
            safe_close(fi); safe_close(fo); safe_remove(tmp)

    def _dec_v4(self, path, prog_container=None, hw_offset=0, hw_serial=None):
        tmp = fi = fo = None
        pwd = None
        file_key = None
        try:
            fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
            if hw_offset > 0:
                fi.seek(hw_offset)
            magic = read_exact(fi, 5)
            if magic != MAGIC_V4: raise ValueError("V4 魔数错误")
            master_salt = read_exact(fi, 16)
            file_salt = read_exact(fi, 16)
            nonce_file = read_exact(fi, 8)
            len_meta = struct.unpack('>H', read_exact(fi, 2))[0]
            if len_meta > MAX_META_LEN: raise ValueError("V4 元数据超限")
            emeta = read_exact(fi, len_meta)
                
            pwd = self.vault.get_password_copy()
            if not pwd: raise ValueError("凭据已失效")
            
            with self._cache_lock:
                if master_salt == self._v4_cache_salt and self._v4_cache_key:
                    master_key = bytes(self._v4_cache_key)
                    zero_bytes(pwd)
                else:
                    try:
                        kdf = Scrypt(salt=master_salt, length=32, n=SCRYPT_N_V3, r=8, p=1)
                        master_key = kdf.derive(bytes(pwd))
                    finally:
                        zero_bytes(pwd)
                    self._v4_cache_salt = master_salt
                    self._v4_cache_key = bytearray(master_key)
                
            info_str = b"SAES_V4_FILE_KEY" + (b":HW:" + hw_serial.encode('utf-8') if hw_serial else b"")
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=file_salt, info=info_str)
            file_key = hkdf.derive(master_key)
            
            self.heartbeat_sig.emit()
            gcm = AESGCM(file_key)
            head = MAGIC_V4 + master_salt + file_salt + nonce_file
            meta = gcm.decrypt(nonce_file + b'\x00\x00\x00\x00', emeta, head)
            if len(meta) < 8: raise ValueError("V4 元数据损坏")
            expected_file_size = struct.unpack('>Q', meta[:8])[0]
            out_p = get_safe_win_path(os.path.join(os.path.dirname(path), sanitize_filename(meta[8:].decode('utf-8', errors='replace'))))
            
            chk = self._check_overwrite(out_p)
            if not chk: return None
            if isinstance(chk, str): out_p = chk
            tmp = out_p + '.tmp'
            
            fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
            c = 1
            total_plain_written = 0
            while self._is_running:
                lb = fi.read(4)
                if not lb: break
                if len(lb) != 4: raise ValueError("分块头截断")
                chunk_len = struct.unpack('>I', lb)[0]
                if chunk_len > MAX_CHUNK_CIPHER_LEN or chunk_len < 16:
                    raise ValueError(f"V4 密文分块长度非法: {chunk_len}")
                raw_chunk = read_exact(fi, chunk_len)
                chunk = gcm.decrypt(nonce_file + struct.pack('>I', c), raw_chunk, None)
                fo.write(chunk)
                total_plain_written += len(chunk)
                if prog_container is not None: prog_container[0] += len(chunk)
                self._throttle_emit(len(chunk))
                c += 1
            if self._is_running:
                if total_plain_written != expected_file_size:
                    raise ValueError(f"V4 校验失败！预期 {expected_file_size}，实际 {total_plain_written}")
                safe_close(fi); safe_close(fo); fi = fo = None
                force_replace(tmp, out_p)
                return out_p
        finally:
            zero_bytes(pwd, file_key)
            safe_close(fi); safe_close(fo); safe_remove(tmp)

    def _enc_v3(self, path, file_size, prog_container=None):
        out_p = path + '.enc'
        chk = self._check_overwrite(out_p)
        if not chk: return None
        if isinstance(chk, str): out_p = chk
        
        pwd = self.vault.get_password_copy()
        if not pwd: raise ValueError("凭据已失效")
        
        tmp = out_p + '.tmp'
        fi = fo = None
        key = None
        try:
            salt = os.urandom(16)
            nonce = os.urandom(4) 
            try:
                kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N_V3, r=8, p=1)
                derived_key = kdf.derive(bytes(pwd))
                if self.hw_serial:
                    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"SAES_V3_HW_KEY:" + self.hw_serial.encode('utf-8'))
                    key = hkdf.derive(derived_key)
                else:
                    key = derived_key
            finally:
                zero_bytes(pwd)
            self.heartbeat_sig.emit()
            gcm = AESGCM(key)
            head = MAGIC_V3 + salt + b'\x00\x00\x00\x00' + nonce
            meta = gcm.encrypt(b'\x00\x00\x00\x00' + nonce + b'\x00\x00\x00\x00', struct.pack('>Q', file_size) + os.path.basename(path).encode('utf-8'), head)
            fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
            fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
            if self.hw_serial:
                s_bytes = self.hw_serial.encode('utf-8')
                fo.write(MAGIC_HW_V1 + struct.pack('>B', len(s_bytes)) + s_bytes)
            fo.write(head + struct.pack('>H', len(meta)) + meta)
            c = 1
            while self._is_running:
                buf = fi.read(CHUNK_SIZE)
                if not buf: break
                enc_chunk = gcm.encrypt(nonce + struct.pack('>Q', c), buf, None)
                fo.write(struct.pack('>I', len(enc_chunk)))
                fo.write(enc_chunk)
                if prog_container is not None: prog_container[0] += len(buf)
                self._throttle_emit(len(buf))
                c += 1
            if self._is_running: 
                safe_close(fi); safe_close(fo); fi = fo = None
                force_replace(tmp, out_p)
                return out_p
        finally: 
            zero_bytes(pwd, key)
            safe_close(fi); safe_close(fo); safe_remove(tmp)

    def _dec_v3(self, path, prog_container=None, hw_offset=0, hw_serial=None):
        tmp = fi = fo = None
        pwd = None
        key = None
        try:
            fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
            if hw_offset > 0:
                fi.seek(hw_offset)
            magic = read_exact(fi, 5)
            if magic != MAGIC_V3: raise ValueError("V3 魔数错误")
            salt = read_exact(fi, 16)
            nonce_raw = read_exact(fi, 8)
            nonce = nonce_raw[4:]
            len_meta = struct.unpack('>H', read_exact(fi, 2))[0]
            if len_meta > MAX_META_LEN: raise ValueError("V3 元数据超限")
            emeta = read_exact(fi, len_meta)
                
            pwd = self.vault.get_password_copy()
            if not pwd: raise ValueError("凭据已失效")
            
            try:
                kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N_V3, r=8, p=1)
                derived_key = kdf.derive(bytes(pwd))
                if hw_serial:
                    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"SAES_V3_HW_KEY:" + hw_serial.encode('utf-8'))
                    key = hkdf.derive(derived_key)
                else:
                    key = derived_key
            finally:
                zero_bytes(pwd)
            self.heartbeat_sig.emit()
            gcm = AESGCM(key)
            meta = gcm.decrypt(nonce_raw + b'\x00\x00\x00\x00', emeta, MAGIC_V3+salt+nonce_raw)
            if len(meta) < 8: raise ValueError("V3 元数据损坏")
            expected_file_size = struct.unpack('>Q', meta[:8])[0]
            out_p = get_safe_win_path(os.path.join(os.path.dirname(path), sanitize_filename(meta[8:].decode('utf-8', errors='replace'))))
            
            chk = self._check_overwrite(out_p)
            if not chk: return None
            if isinstance(chk, str): out_p = chk
            tmp = out_p + '.tmp'
            fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
            c = 1
            total_plain_written = 0
            while self._is_running:
                lb = fi.read(4)
                if not lb: break
                if len(lb) != 4: raise ValueError("分块头截断")
                chunk_len = struct.unpack('>I', lb)[0]
                if chunk_len > MAX_CHUNK_CIPHER_LEN or chunk_len < 16:
                    raise ValueError(f"V3 密文分块长度非法: {chunk_len}")
                raw_chunk = read_exact(fi, chunk_len)
                chunk = gcm.decrypt(nonce + struct.pack('>Q', c), raw_chunk, None)
                fo.write(chunk)
                total_plain_written += len(chunk)
                if prog_container is not None: prog_container[0] += len(chunk)
                self._throttle_emit(len(chunk))
                c += 1
            if self._is_running:
                if total_plain_written != expected_file_size:
                    raise ValueError(f"V3 校验失败！预期 {expected_file_size}，实际 {total_plain_written}")
                safe_close(fi); safe_close(fo); fi = fo = None
                force_replace(tmp, out_p)
                return out_p
        finally:
            zero_bytes(pwd, key)
            safe_close(fi); safe_close(fo); safe_remove(tmp)

    def _dec_v2(self, path, prog_container=None):
        tmp = fi = fo = None
        pwd = None
        key = None
        try:
            fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
            magic = read_exact(fi, 5)
            if magic != MAGIC_V2: raise ValueError("V2 魔数错误")
            salt = read_exact(fi, 16)
            nonce = read_exact(fi, 8)
            len_meta = struct.unpack('>H', read_exact(fi, 2))[0]
            if len_meta > MAX_META_LEN: raise ValueError("V2 元数据超限")
            emeta = read_exact(fi, len_meta)
                
            pwd = self.vault.get_password_copy()
            if not pwd: raise ValueError("凭据已失效")
            
            try:
                kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N_V2, r=8, p=1)
                key = kdf.derive(bytes(pwd))
            finally:
                zero_bytes(pwd)
            self.heartbeat_sig.emit()
            gcm = AESGCM(key)
            meta = gcm.decrypt(nonce + b'\x00\x00\x00\x00', emeta, MAGIC_V2+salt+nonce)
            if len(meta) < 8: raise ValueError("V2 元数据损坏")
            expected_file_size = struct.unpack('>Q', meta[:8])[0]
            out_p = get_safe_win_path(os.path.join(os.path.dirname(path), sanitize_filename(meta[8:].decode('utf-8', errors='replace'))))
            
            chk = self._check_overwrite(out_p)
            if not chk: return None
            if isinstance(chk, str): out_p = chk
            tmp = out_p + '.tmp'
            fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
            c = 1
            total_plain_written = 0
            while self._is_running:
                lb = fi.read(4)
                if not lb: break
                if len(lb) != 4: raise ValueError("分块头截断")
                chunk_len = struct.unpack('>I', lb)[0]
                if chunk_len > MAX_CHUNK_CIPHER_LEN or chunk_len < 16:
                    raise ValueError(f"V2 密文分块长度非法: {chunk_len}")
                raw_chunk = read_exact(fi, chunk_len)
                chunk = gcm.decrypt(nonce + struct.pack('>I', c), raw_chunk, None)
                fo.write(chunk)
                total_plain_written += len(chunk)
                if prog_container is not None: prog_container[0] += len(chunk)
                self._throttle_emit(len(chunk))
                c += 1
            if self._is_running:
                if total_plain_written != expected_file_size:
                    raise ValueError(f"V2 校验失败！预期 {expected_file_size}，实际 {total_plain_written}")
                safe_close(fi); safe_close(fo); fi = fo = None
                force_replace(tmp, out_p)
                return out_p
        finally:
            zero_bytes(pwd, key)
            safe_close(fi); safe_close(fo); safe_remove(tmp)

    def _dec_v1(self, path, prog_container=None):
        tmp = fi = fo = None
        pwd = None
        key = None
        try:
            fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
            magic = read_exact(fi, 5)
            if magic != MAGIC_V1: raise ValueError("V1 魔数错误")
            salt = read_exact(fi, 16)
            nonce = read_exact(fi, 8)
            len_meta = struct.unpack('>H', read_exact(fi, 2))[0]
            if len_meta > MAX_META_LEN: raise ValueError("V1 元数据超限")
            emeta = read_exact(fi, len_meta)
                
            pwd = self.vault.get_password_copy()
            if not pwd: raise ValueError("凭据已失效")
            
            try:
                kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N_V1, r=8, p=1)
                key = kdf.derive(bytes(pwd))
            finally:
                zero_bytes(pwd)
            self.heartbeat_sig.emit()
            gcm = AESGCM(key)
            meta = gcm.decrypt(nonce + b'\x00\x00\x00\x00', emeta, None)
            if len(meta) < 8: raise ValueError("V1 元数据损坏")
            expected_file_size = struct.unpack('>Q', meta[:8])[0]
            out_p = get_safe_win_path(os.path.join(os.path.dirname(path), sanitize_filename(meta[8:].decode('utf-8', errors='replace'))))
            
            chk = self._check_overwrite(out_p)
            if not chk: return None
            if isinstance(chk, str): out_p = chk
            tmp = out_p + '.tmp'
            fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
            c = 1
            total_plain_written = 0
            while self._is_running:
                lb = fi.read(4)
                if not lb: break
                if len(lb) != 4: raise ValueError("分块头截断")
                chunk_len = struct.unpack('>I', lb)[0]
                if chunk_len > MAX_CHUNK_CIPHER_LEN or chunk_len < 16:
                    raise ValueError(f"V1 密文分块长度非法: {chunk_len}")
                raw_chunk = read_exact(fi, chunk_len)
                chunk = gcm.decrypt(nonce + struct.pack('>I', c), raw_chunk, None)
                fo.write(chunk)
                total_plain_written += len(chunk)
                if prog_container is not None: prog_container[0] += len(chunk)
                self._throttle_emit(len(chunk))
                c += 1
            if self._is_running:
                if total_plain_written != expected_file_size:
                    raise ValueError(f"V1 校验失败！预期 {expected_file_size}，实际 {total_plain_written}")
                safe_close(fi); safe_close(fo); fi = fo = None
                force_replace(tmp, out_p)
                return out_p
        finally:
            zero_bytes(pwd, key)
            safe_close(fi); safe_close(fo); safe_remove(tmp)

    def _dec_v0(self, path, prog_container=None):
        tmp = fi = fo = None
        pwd = None
        key = None
        try:
            fi = open(path, 'rb', buffering=IO_BUFFER_SIZE)
            salt = read_exact(fi, 16)
                
            with self._dialog_lock:
                self.ask_filename_sig.emit(path)
                self.filename_event.wait()
                if not self._is_running: return None
                if not self.filename_decision or self.filename_decision == "__SYS_ABORT__":
                    if self.filename_decision == "__SYS_ABORT__": self._is_running = False
                    self.filename_event.clear()
                    return None
                out_p = get_safe_win_path(os.path.join(os.path.dirname(path), sanitize_filename(self.filename_decision)))
                self.filename_event.clear()
            
            chk = self._check_overwrite(out_p)
            if not chk: return None
            if isinstance(chk, str): out_p = chk
            
            pwd = self.vault.get_password_copy()
            if not pwd: raise ValueError("延迟凭据获取超时")
            
            try:
                kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600000)
                key = kdf.derive(bytes(pwd))
            finally:
                zero_bytes(pwd)
            self.heartbeat_sig.emit()
            gcm = AESGCM(key)
            
            tmp = out_p + '.tmp'
            fo = open(tmp, 'wb', buffering=IO_BUFFER_SIZE)
            c = 0
            seen_last_chunk = False
            while self._is_running:
                is_last_buf = fi.read(1)
                if not is_last_buf: break
                ln_buf = read_exact(fi, 4)
                chunk_len = int.from_bytes(ln_buf, 'big')
                if chunk_len > MAX_CHUNK_CIPHER_LEN or chunk_len < 16:
                    raise ValueError(f"V0 分块长度异常: {chunk_len}")
                nonce_12 = read_exact(fi, 12)
                cipher_data = read_exact(fi, chunk_len)
                chunk = gcm.decrypt(nonce_12, cipher_data, (c & 0xFFFFFFFFFFFFFFFF).to_bytes(8,'big') + is_last_buf)
                fo.write(chunk)
                if prog_container is not None: prog_container[0] += len(chunk)
                self._throttle_emit(len(chunk))
                c += 1
                if is_last_buf == b'\x01':
                    seen_last_chunk = True
                    break
            if self._is_running:
                if not seen_last_chunk:
                    raise ValueError("V0 密文流意外截断，未检测到终止分块")
                safe_close(fi); safe_close(fo); fi = fo = None
                force_replace(tmp, out_p)
                return out_p
        finally:
            zero_bytes(pwd, key)
            safe_close(fi); safe_close(fo); safe_remove(tmp)

class FileScannerWorker(QThread):
    batch_found_sig = Signal(list)
    log_sig = Signal(str)
    def __init__(self, paths, allow_v0=False):
        super().__init__()
        self.paths = paths
        self.allow_v0 = allow_v0
        self._is_running = True

    def _classify_file(self, safe_p):
        grp = 'plain'
        try:
            with open(safe_p, 'rb') as f:
                mag = f.read(5)
                if mag == MAGIC_HW_V1:
                    lb = f.read(1)
                    if lb:
                        slen = struct.unpack('>B', lb)[0]
                        f.seek(5 + 1 + slen)
                        mag = f.read(5)
            if mag == MAGIC_SFK_V1: grp = 'sfk'
            elif mag == MAGIC_ECC_V1: grp = 'ecc'
            elif mag in (MAGIC_CHACHA_V1, MAGIC_V4, MAGIC_V3, MAGIC_V2, MAGIC_V1): grp = 'saes'
            elif self.allow_v0 and safe_p.lower().endswith('.enc'): grp = 'saes'
        except Exception:
            pass
        return grp

    def run(self):
        batch = []
        for p in self.paths:
            if not self._is_running: break
            safe_p = get_safe_win_path(p) 
            if os.path.isfile(safe_p):
                try:
                    sz = os.path.getsize(safe_p)
                    grp = self._classify_file(safe_p)
                    batch.append((safe_p, sz, grp))
                except Exception:
                    pass
            elif os.path.isdir(safe_p):
                def walk_err(e):
                    self.log_sig.emit(f"[-] 扫描目录权限拒绝或错误: {str(e)}")
                for root, _, files in os.walk(safe_p, onerror=walk_err):
                    if not self._is_running: break
                    for f in files:
                        if not self._is_running: break
                        fp = get_safe_win_path(os.path.join(root, f))
                        try:
                            sz = os.path.getsize(fp)
                            grp = self._classify_file(fp)
                            batch.append((fp, sz, grp))
                        except Exception:
                            pass
                        if len(batch) >= 500:
                            self.batch_found_sig.emit(batch)
                            batch = []
        if batch and self._is_running:
            self.batch_found_sig.emit(batch)

    def abort(self):
        self._is_running = False

