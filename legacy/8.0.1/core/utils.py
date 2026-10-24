import os
import stat
import re
import time
import ctypes
import hashlib
from cryptography.exceptions import InvalidTag
from core.config import WIN_RESERVED_NAMES, logger, IO_BUFFER_SIZE

def format_crypto_error(e):
    """根据异常类型生成用户友好的精准诊断信息"""
    if isinstance(e, InvalidTag):
        return "身份验证失败：密码错误、密文被篡改或签名认证未通过 (AEAD Tag Mismatch)"
    if isinstance(e, PermissionError):
        return f"权限错误：文件被其他程序独占、处于只读介质或拒绝访问 ({str(e)})"
    if isinstance(e, FileNotFoundError):
        return f"文件未找到：指定的文件路径不存在或已被移动 ({str(e)})"
    if isinstance(e, MemoryError):
        return "内存不足：系统物理/虚拟内存耗尽，无法分配当前加解密数据块缓存"
    if isinstance(e, ValueError):
        msg = str(e)
        if "魔数" in msg or "magic" in msg.lower():
            return f"文件格式识别失败：不支持的加密协议或文件头损坏 ({msg})"
        if "截断" in msg or "流意外终止" in msg:
            return f"文件损坏：数据流异常截断或密文不完整 ({msg})"
        if "大小校验" in msg or "校验失败" in msg:
            return f"完整性校验失败：解密恢复大小与元数据不符 ({msg})"
        return f"数据或参数异常: {msg}"
    if isinstance(e, OSError):
        winerror = getattr(e, 'winerror', None)
        if winerror == 112:
            return "磁盘空间不足：存储目标所在磁盘已满 (WinError 112)"
        elif winerror == 206:
            return "路径超长：文件路径超出 Windows 最大长度限制 (WinError 206)"
        return f"系统 I/O 错误 [{winerror if winerror else type(e).__name__}]: {str(e)}"
    return f"未预期异常 [{type(e).__name__}]: {str(e)}"

def safe_close(f_obj):
    if f_obj:
        try:
            f_obj.close()
        except Exception:
            pass

def safe_remove(path):
    if path and os.path.exists(path):
        try:
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            os.remove(path)
        except Exception:
            pass

def sanitize_filename(filename):
    if not isinstance(filename, str):
        filename = str(filename, 'utf-8', errors='replace')
    name = "".join(ch for ch in filename if ch not in '\x00\r\n\t\x1b' and ord(ch) >= 32)
    name = re.sub(r'[<>:"/\\|?*]', '', name).strip().strip('.')
    if not name:
        return "unnamed_decoded"
    base, _ = os.path.splitext(name)
    if base.upper() in WIN_RESERVED_NAMES:
        name = f"safe_{name}"
    return name

def get_safe_win_path(path):
    if os.name != 'nt':
        return os.path.normpath(os.path.abspath(path))
    path = os.path.normpath(os.path.abspath(path))
    if path.startswith('\\\\?\\'):
        return path
    if path.startswith('\\\\'):
        return '\\\\?\\UNC\\' + path[2:]
    return '\\\\?\\' + path

def force_replace(src, dst):
    src = get_safe_win_path(src)
    dst = get_safe_win_path(dst)
    last_err = None
    for attempt in range(3):
        try:
            if os.path.exists(dst):
                try:
                    orig_mode = stat.S_IMODE(os.stat(dst).st_mode)
                    os.chmod(dst, orig_mode | stat.S_IWRITE)
                except Exception:
                    pass
            os.replace(src, dst)
            return
        except (PermissionError, OSError) as e:
            last_err = e
            time.sleep(0.05)
        except Exception as e:
            last_err = e
            break
    logger.error(f"文件替换执行失败 {src} -> {dst}: {str(last_err)}")

def compute_file_blake2b(path):
    safe_p = get_safe_win_path(path)
    hasher = hashlib.blake2b(digest_size=32)
    with open(safe_p, 'rb', buffering=IO_BUFFER_SIZE) as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.digest()

def read_exact(f, n):
    data = bytearray(n)
    view = memoryview(data)
    pos = 0
    while pos < n:
        r = f.readinto(view[pos:])
        if not r:
            raise ValueError("文件流意外终止，数据截断")
        pos += r
    return bytes(data)
