import os
import json
import time

class ResumeManager:
    """
    大文件断点续加/续解检查点管理器
    在临时文件伴随保存已完成块的进度与哈希记录，实现秒级断点恢复
    """
    @staticmethod
    def get_checkpoint_path(target_path):
        return target_path + ".saes_checkpoint"

    @classmethod
    def save_checkpoint(cls, target_path, mode, enc_type, completed_bytes, total_bytes, chunks_count):
        chk_p = cls.get_checkpoint_path(target_path)
        try:
            data = {
                "target": target_path,
                "mode": mode,
                "enc_type": enc_type,
                "completed_bytes": completed_bytes,
                "total_bytes": total_bytes,
                "chunks_count": chunks_count,
                "updated_at": time.time()
            }
            with open(chk_p, 'w', encoding='utf-8') as f:
                json.dump(data, f)
        except Exception:
            pass

    @classmethod
    def load_checkpoint(cls, target_path, mode, enc_type, total_bytes):
        chk_p = cls.get_checkpoint_path(target_path)
        if not os.path.exists(chk_p):
            return None
        try:
            with open(chk_p, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if (data.get("mode") == mode and 
                data.get("enc_type") == enc_type and 
                data.get("total_bytes") == total_bytes and
                data.get("completed_bytes", 0) > 0):
                return data
        except Exception:
            pass
        return None

    @classmethod
    def clear_checkpoint(cls, target_path):
        chk_p = cls.get_checkpoint_path(target_path)
        if os.path.exists(chk_p):
            try:
                os.remove(chk_p)
            except Exception:
                pass
