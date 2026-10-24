import os
import ctypes

class MemoryShield:
    """
    Windows 物理内存加锁盾 (VirtualLock / VirtualAlloc)
    确保敏感口令与密钥所在的内存页常驻物理 RAM，禁止 Windows 系统交换到硬盘 pagefile.sys
    """
    _kernel32 = None
    _available = False

    @classmethod
    def init(cls):
        if cls._kernel32 is None and os.name == 'nt':
            try:
                from ctypes import wintypes
                k32 = ctypes.windll.kernel32
                k32.VirtualAlloc.restype = ctypes.c_void_p
                k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
                k32.VirtualLock.restype = wintypes.BOOL
                k32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                k32.VirtualUnlock.restype = wintypes.BOOL
                k32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                k32.VirtualFree.restype = wintypes.BOOL
                k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
                cls._kernel32 = k32
                cls._available = True
            except Exception:
                cls._available = False

    @classmethod
    def alloc_locked(cls, size):
        cls.init()
        if cls._available and size > 0:
            try:
                alloc_sz = ((size + 4095) // 4096) * 4096
                addr = cls._kernel32.VirtualAlloc(None, alloc_sz, 0x1000 | 0x2000, 0x04)
                if addr:
                    locked = cls._kernel32.VirtualLock(addr, alloc_sz)
                    return addr, alloc_sz, bool(locked)
            except Exception:
                pass
        return None, 0, False

    @classmethod
    def free_locked(cls, addr, size):
        if cls._available and addr:
            try:
                ctypes.memset(addr, 0, size)
                cls._kernel32.VirtualUnlock(addr, size)
                cls._kernel32.VirtualFree(addr, 0, 0x8000)
            except Exception:
                pass

def zero_bytes(*bufs):
    """
    安全覆写内存中的敏感数据，支持 bytearray, memoryview 以及 CPython 底层 bytes。
    对长度 >= 16 的 bytes 使用 ctypes.memset 原地擦除，安全避开 CPython 针对 0/1 字节的单例缓存池。
    """
    for buf in bufs:
        if buf is None:
            continue
        try:
            if isinstance(buf, (bytearray, memoryview)):
                try:
                    buf[:] = b'\x00' * len(buf)
                except Exception:
                    for i in range(len(buf)):
                        buf[i] = 0
            elif isinstance(buf, bytes):
                if len(buf) >= 16:
                    try:
                        offset = ctypes.sizeof(ctypes.c_size_t) * 4
                        data_ptr = id(buf) + offset
                        ctypes.memset(data_ptr, 0, len(buf))
                    except Exception:
                        pass
        except Exception:
            pass
