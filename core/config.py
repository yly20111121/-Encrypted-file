import os
import sys
import logging
from logging.handlers import RotatingFileHandler

CORE_VAULT_VERSION = "9.0.1"
APP_DIR = os.path.dirname(os.path.realpath(sys.argv[0])) if sys.argv and sys.argv[0] else os.getcwd()
LOG_PATH = os.path.join(APP_DIR, 'crypto_operation.log')

logger = logging.getLogger("CoreVault_901")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

try:
    rf_handler = RotatingFileHandler(LOG_PATH, maxBytes=10*1024*1024, backupCount=3, encoding='utf-8')
    rf_handler.setFormatter(formatter)
    logger.addHandler(rf_handler)
except Exception:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

CHUNK_SIZE = 4 * 1024 * 1024
IO_BUFFER_SIZE = 8 * 1024 * 1024
MAX_CHUNK_PLAIN_LEN = CHUNK_SIZE
MAX_CHUNK_CIPHER_LEN = CHUNK_SIZE + 16 + 256
MAX_WRAP_DEK_LEN = 512
MAX_META_LEN = 4096

MAGIC_SFK_V1 = b"SFK\x01\x00"
MAGIC_ECC_V1 = b"SAECC"
MAGIC_CHACHA_V1 = b"SACH\x01"
MAGIC_V4 = b"SAES\x05"
MAGIC_V3 = b"SAES\x04"
MAGIC_V2 = b"SAES\x03"
MAGIC_V1 = b"SAES\x02"
MAGIC_ZSTD_V1 = b"SAZ1\x01"     # AES-GCM + 流式压缩协议头
MAGIC_ZCHACHA_V1 = b"SAZC\x01"  # ChaCha20-Poly1305 + 流式压缩协议头
MAGIC_HW_V1 = b"SAHW\x01"       # 物理硬件钥匙绑定协议头

SALT_SIZE = 16
SCRYPT_N_V3 = 2**18
SCRYPT_N_V2 = 2**17  
SCRYPT_N_V1 = 2**14
SCRYPT_N_SFK = 2**14
CACHE_TIMEOUT_SECS = 900
KEYFILE_MAX_SIZE = 500 * 1024 * 1024

WIN_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
}

VOLATILE_EXTENSIONS = {
    '.log', '.tmp', '.sqlite', '.db', '.dat', '.txt', '.ini', 
    '.json', '.xml', '.yaml', '.yml', '.toml', '.csv', '.md', 
    '.conf', '.cfg', '.env', '.properties'
}
