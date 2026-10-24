import os
import sys

# Ensure repository root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import unittest
from PySide6.QtWidgets import QApplication

# Ensure QApplication exists for Qt-based workers
app = QApplication.instance() or QApplication([])

from core.config import MAGIC_V4, MAGIC_V3, MAGIC_CHACHA_V1
from core.vault import CredentialVault
from core.worker import CryptoWorker
from core.compression import StreamCompression
from core.memory import zero_bytes

class TestCoreVaultCrypto(unittest.TestCase):
    def setUp(self):
        self.test_file = os.path.abspath("test_sample_payload.txt")
        self.plain_data = b"Core Vault 9.0.1 High-Assurance Cryptography Verification Block!" * 20
        with open(self.test_file, "wb") as f:
            f.write(self.plain_data)
        self.vault = CredentialVault()
        self.vault.unlock("TestPassword_2026_Secure!")

    def tearDown(self):
        for p in [self.test_file, self.test_file + ".enc"]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass

    def test_stream_compression(self):
        compressed = StreamCompression.compress_chunk(self.plain_data)
        self.assertLess(len(compressed), len(self.plain_data))
        decompressed = StreamCompression.decompress_chunk(compressed)
        self.assertEqual(decompressed, self.plain_data)

    def test_v4_encryption_decryption(self):
        worker_enc = CryptoWorker(
            mode='encrypt', enc_type='saes', enc_ver=4,
            queue=[(self.test_file, len(self.plain_data))],
            vault=self.vault, shred=False, overwrite_strat='overwrite', allow_v0=False
        )
        enc_path = worker_enc._process_single(self.test_file, len(self.plain_data))
        self.assertTrue(os.path.exists(enc_path))

        with open(enc_path, 'rb') as f:
            magic = f.read(5)
        self.assertEqual(magic, MAGIC_V4)

        worker_dec = CryptoWorker(
            mode='decrypt', enc_type='saes', enc_ver=4,
            queue=[(enc_path, os.path.getsize(enc_path))],
            vault=self.vault, shred=False, overwrite_strat='overwrite', allow_v0=False
        )
        dec_path = worker_dec._process_single(enc_path, os.path.getsize(enc_path))
        with open(dec_path, 'rb') as f:
            dec_data = f.read()
        self.assertEqual(dec_data, self.plain_data)

    def test_v3_encryption_decryption(self):
        worker_enc = CryptoWorker(
            mode='encrypt', enc_type='saes', enc_ver=3,
            queue=[(self.test_file, len(self.plain_data))],
            vault=self.vault, shred=False, overwrite_strat='overwrite', allow_v0=False
        )
        enc_path = worker_enc._process_single(self.test_file, len(self.plain_data))
        self.assertTrue(os.path.exists(enc_path))

        with open(enc_path, 'rb') as f:
            magic = f.read(5)
        self.assertEqual(magic, MAGIC_V3)

        worker_dec = CryptoWorker(
            mode='decrypt', enc_type='saes', enc_ver=3,
            queue=[(enc_path, os.path.getsize(enc_path))],
            vault=self.vault, shred=False, overwrite_strat='overwrite', allow_v0=False
        )
        dec_path = worker_dec._process_single(enc_path, os.path.getsize(enc_path))
        with open(dec_path, 'rb') as f:
            dec_data = f.read()
        self.assertEqual(dec_data, self.plain_data)

    def test_memory_zeroing(self):
        ba = bytearray(b"HighlySensitiveSecretKeyMaterial")
        zero_bytes(ba)
        self.assertEqual(ba, bytearray(len(ba)))

if __name__ == '__main__':
    unittest.main()
