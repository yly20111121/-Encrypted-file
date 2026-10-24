import os
import ctypes
from ctypes import wintypes
import struct

class HardwareTokenManager:
    """
    Windows 物理存储介质硬件令牌管理器
    支持 U 盘 (Removable) 与 USB 移动硬盘 / 外接移动固态硬盘 (BusTypeUsb)
    通过读取外接物理存储设备的只读硬件卷序列号 (Volume Serial Number) 作为不可篡改的硬件锁绑定因子
    """
    @staticmethod
    def get_removable_drives():
        """
        枚举当前系统上挂载的所有存储介质
        优先返回 U 盘、USB 移动硬盘、移动存储设备，其次返回本地非系统盘
        """
        drives = []
        if os.name != 'nt':
            return drives
        try:
            k32 = ctypes.windll.kernel32
            bitmask = k32.GetLogicalDrives()
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if bitmask & 1:
                    drive_root = f"{letter}:\\"
                    dtype = k32.GetDriveTypeW(drive_root)
                    # 仅扫描有效存储卷: DRIVE_REMOVABLE (2), DRIVE_FIXED (3), DRIVE_REMOTE (4)
                    if dtype in (2, 3, 4):
                        name_buf = ctypes.create_unicode_buffer(260)
                        fs_buf = ctypes.create_unicode_buffer(260)
                        serial_num = wintypes.DWORD()
                        res = k32.GetVolumeInformationW(
                            drive_root, name_buf, 260, ctypes.byref(serial_num),
                            None, None, fs_buf, 260
                        )
                        if res and serial_num.value:
                            serial_hex = f"{serial_num.value:08X}"
                            vol_label = name_buf.value or ("可移动存储" if dtype == 2 else "本地存储")
                            is_usb = (dtype == 2)
                            dev_desc = "U盘 / 可移动磁盘" if dtype == 2 else "本地存储"
                            
                            # 若为固定磁盘，深入检测是否为 USB 外接移动硬盘 / 移动 SSD
                            if dtype == 3:
                                h = k32.CreateFileW(f"\\\\.\\{letter}:", 0, 1 | 2, None, 3, 0, None)
                                if h != -1 and h != 0:
                                    try:
                                        query = struct.pack('III', 0, 0, 0) # StorageDeviceProperty, PropertyStandardQuery
                                        buf = ctypes.create_string_buffer(1024)
                                        bytes_ret = wintypes.DWORD()
                                        if k32.DeviceIoControl(h, 0x002D1400, query, len(query), buf, len(buf), ctypes.byref(bytes_ret), None):
                                            bus_type = struct.unpack_from('I', buf.raw, 28)[0]
                                            removable = bool(buf.raw[8])
                                            if bus_type == 7 or removable: # BusTypeUsb = 7
                                                is_usb = True
                                                dev_desc = "USB 移动硬盘 / 外接存储"
                                    except Exception:
                                        pass
                                    finally:
                                        k32.CloseHandle(h)
                                        
                            is_sys = (letter.upper() == 'C')
                            if not is_usb and not is_sys:
                                dev_desc = "本地分区"
                            elif is_sys:
                                dev_desc = "系统盘 (C:)"

                            drives.append({
                                "drive": drive_root,
                                "label": vol_label,
                                "serial": serial_hex,
                                "fs": fs_buf.value,
                                "type_desc": dev_desc,
                                "is_usb": is_usb,
                                "is_system": is_sys
                            })
                bitmask >>= 1
        except Exception:
            pass

        # 排序：外接 USB 介质/U盘/移动硬盘排在最前，非系统存储盘次之，系统盘 C 盘最后
        drives.sort(key=lambda x: (not x["is_usb"], x["is_system"]))
        return drives

    @staticmethod
    def verify_token_present(expected_serial):
        """
        全盘核验指定的物理硬件序列号设备当前是否已接入电脑
        支持跨盘符接入（如插入不同 USB 口盘符发生变化，只要序列号一致均能识别）
        """
        if not expected_serial:
            return True, None
        expected = expected_serial.strip().upper()
        drives = HardwareTokenManager.get_removable_drives()
        for d in drives:
            if d["serial"].upper() == expected:
                return True, d
        return False, None
