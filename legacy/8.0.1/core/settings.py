import os
import json
from core.config import APP_DIR

class ConfigManager:
    SETTINGS_FILE = os.path.join(APP_DIR, 'saes_settings.json')
    DEFAULT_CONFIG = {
        "shred": False,
        "allow_v0": False,
        "overwrite": "rename",
        "bg_image": "",
        "bg_opacity": 0.45,
        "workers": 4
    }

    @classmethod
    def load(cls):
        try:
            if os.path.exists(cls.SETTINGS_FILE):
                with open(cls.SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                    res = cls.DEFAULT_CONFIG.copy()
                    res.update(cfg)
                    try:
                        res["bg_opacity"] = max(0.0, min(1.0, float(res.get("bg_opacity", 0.45))))
                    except (ValueError, TypeError):
                        res["bg_opacity"] = 0.45
                    return res
        except Exception:
            pass
        return cls.DEFAULT_CONFIG.copy()

    @classmethod
    def save(cls, data):
        try:
            cfg = cls.load()
            cfg.update(data)
            try:
                cfg["bg_opacity"] = max(0.0, min(1.0, float(cfg.get("bg_opacity", 0.45))))
            except (ValueError, TypeError):
                cfg["bg_opacity"] = 0.45
            with open(cls.SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, indent=4)
        except Exception:
            pass
