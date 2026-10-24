import os
import sys

# Ensure repository root is on sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import unittest
from PySide6.QtWidgets import QApplication

app = QApplication.instance() or QApplication([])

from core.config import MAGIC_HW_V1
from core.vault import CredentialVault
from core.hardware import HardwareTokenManager
from core.worker import CryptoWorker

class TestHardwareTokenLock(unittest.TestCase):
    def setUp(self):
        self.test_file = os.path.abspath("test_hw_token_payload.txt")
        self.plain_data = b"Hardware-Bound Security Test Vector (USB Physical Token)" * 15
        with open(self.test_file, "wb") as f:
            f.write(self.plain_data)
        self.vault = CredentialVault()
        self.vault.unlock("HW_Bound_SecretPass_2026")
        self.mock_serial = "U_TOKEN_ABCD1234"

    def tearDown(self):
        for p in [self.test_file, self.test_file + ".enc"]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass

    def test_hardware_token_encryption_and_blocking(self):
        # 1. Encrypt with hardware lock bound
        worker_enc = CryptoWorker(
            mode='encrypt', enc_type='saes', enc_ver=4,
            queue=[(self.test_file, len(self.plain_data))],
            vault=self.vault, shred=False, overwrite_strat='overwrite', allow_v0=False,
            hw_serial=self.mock_serial
        )
        enc_path = worker_enc._process_single(self.test_file, len(self.plain_data))
        self.assertTrue(os.path.exists(enc_path))

        # Check MAGIC_HW_V1 container header
        with open(enc_path, 'rb') as f:
            magic = f.read(5)
        self.assertEqual(magic, MAGIC_HW_V1)

        # 2. Test decryption when token is NOT plugged in (MUST BLOCK)
        orig_verify = HardwareTokenManager.verify_token_present
        HardwareTokenManager.verify_token_present = lambda s: (False, None)
        try:
            worker_dec_fail = CryptoWorker(
                mode='decrypt', enc_type='saes', enc_ver=4,
                queue=[(enc_path, os.path.getsize(enc_path))],
                vault=self.vault, shred=False, overwrite_strat='overwrite', allow_v0=False
            )
            with self.assertRaises(ValueError):
                worker_dec_fail._process_single(enc_path, os.path.getsize(enc_path))
        finally:
            HardwareTokenManager.verify_token_present = orig_verify

        # 3. Test decryption when token IS plugged in (MUST SUCCEED)
        HardwareTokenManager.verify_token_present = lambda s: (True, {'drive': 'E:\\', 'label': 'TokenDrive', 'serial': s})
        try:
            worker_dec_ok = CryptoWorker(
                mode='decrypt', enc_type='saes', enc_ver=4,
                queue=[(enc_path, os.path.getsize(enc_path))],
                vault=self.vault, shred=False, overwrite_strat='overwrite', allow_v0=False
            )
            dec_path = worker_dec_ok._process_single(enc_path, os.path.getsize(enc_path))
            with open(dec_path, 'rb') as f:
                dec_data = f.read()
            self.assertEqual(dec_data, self.plain_data)
        finally:
            HardwareTokenManager.verify_token_present = orig_verify

if __name__ == '__main__':
    unittest.main()
