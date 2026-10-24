import time
import threading
import ctypes
import atexit
from core.config import CACHE_TIMEOUT_SECS
from core.memory import MemoryShield, zero_bytes

class CredentialVault:
    def __init__(self, timeout=CACHE_TIMEOUT_SECS):
        self._pwd_bytes = bytearray()
        self._locked_mem_addr = None
        self._locked_mem_size = 0
        self._is_mem_locked = False
        self.timeout = timeout
        self.expiry_time = 0
        self.mutex = threading.Lock()
        
    def is_locked(self):
        with self.mutex:
            return time.time() > self.expiry_time or len(self._pwd_bytes) == 0
            
    def lock(self):
        with self.mutex:
            zero_bytes(self._pwd_bytes)
            self._pwd_bytes.clear()
            if self._locked_mem_addr:
                MemoryShield.free_locked(self._locked_mem_addr, self._locked_mem_size)
                self._locked_mem_addr = None
                self._locked_mem_size = 0
                self._is_mem_locked = False
            self.expiry_time = 0
            
    def unlock(self, pwd_bytes_in):
        with self.mutex:
            zero_bytes(self._pwd_bytes)
            self._pwd_bytes.clear()
            if self._locked_mem_addr:
                MemoryShield.free_locked(self._locked_mem_addr, self._locked_mem_size)
                self._locked_mem_addr = None
                self._locked_mem_size = 0
                self._is_mem_locked = False

            if isinstance(pwd_bytes_in, str):
                encoded = bytearray(pwd_bytes_in.encode('utf-8'))
                self._pwd_bytes.extend(encoded)
                zero_bytes(encoded)
            elif isinstance(pwd_bytes_in, (bytearray, bytes)):
                self._pwd_bytes.extend(pwd_bytes_in)

            # 启用 Windows 物理内存加锁盾 (防止置换至 pagefile.sys)
            if len(self._pwd_bytes) > 0:
                addr, sz, locked = MemoryShield.alloc_locked(len(self._pwd_bytes))
                if addr:
                    self._locked_mem_addr = addr
                    self._locked_mem_size = sz
                    self._is_mem_locked = locked
                    ctypes.memmove(addr, (ctypes.c_char * len(self._pwd_bytes)).from_buffer(self._pwd_bytes), len(self._pwd_bytes))

            self.expiry_time = time.time() + self.timeout
            
    def is_physically_locked(self):
        with self.mutex:
            return self._is_mem_locked
            
    def heartbeat(self):
        with self.mutex:
            if self.expiry_time > 0 and len(self._pwd_bytes) > 0:
                self.expiry_time = time.time() + self.timeout
                
    def get_password_copy(self):
        with self.mutex:
            if time.time() > self.expiry_time or len(self._pwd_bytes) == 0:
                return None
            return bytearray(self._pwd_bytes)
            
    def get_ttl(self):
        with self.mutex:
            if time.time() > self.expiry_time or len(self._pwd_bytes) == 0:
                return 0
            return max(0, int(self.expiry_time - time.time()))

global_vault = CredentialVault()
atexit.register(global_vault.lock)
