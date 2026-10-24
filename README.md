# Core Vault 9.0.1 - 工业级高安全文件加密工作台

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![PySide6](https://img.shields.io/badge/GUI-PySide6%20Qt6-41CD52.svg?logo=qt&logoColor=white)](https://pypi.org/project/PySide6/)
[![Cryptography](https://img.shields.io/badge/Crypto-AES--GCM%20%7C%20ChaCha20-orange.svg)](https://cryptography.io/)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011-0078D6.svg?logo=windows&logoColor=white)](https://microsoft.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Core Vault 9.0.1** 是一款专为 Windows 环境打造的**零信任高保密架构**文件加密系统。  
> 融合 **AES-256-GCM / ChaCha20-Poly1305** 高性能带认证密码学、**物理 U 盘 / USB 移动硬盘硬件锁绑定**、**Windows VirtualLock 物理内存加锁盾**与 **WinUI 3 Mica 现代化流体视觉**，抵御侧信道分析、物理内存转储与暴力破解。

---

## 🌟 核心特性 (Key Features)

### 1. 🔑 物理硬件锁深度绑定 (Hardware Token USB Lock)
* **双模物理介质支持**：基于 Windows 存储栈 IOCTL（`IOCTL_STORAGE_QUERY_PROPERTY`），全面适配传统可移动 U 盘（`DRIVE_REMOVABLE`）与各类 USB 移动硬盘、移动固态 SSD（`BusTypeUsb`）。
* **加密物理锁死**：加密时文件头部写入 `SAHW\x01` 专用容器头，并将设备唯一只读硬件卷序列号注入密钥派生（HKDF/Scrypt）。
* **解密物理阻断**：在任何电脑解密该文件时，**必须插着绑定的这只硬件设备**；未插设备直接物理阻断，拔出即触发安全熔断。

### 2. 🗜️ 实时流式分块压缩 (Stream Chunk Compression)
* **线速实时压缩**：内置 4MB 分块流式 Deflate 压缩引擎，与加解密管道无缝并行，显著降低密文体积并大幅提升大文件 I/O 吞吐。
* **零内存开销**：单块恒定 4MB，杜绝大文件处理时的内存暴涨（OOM）。

### 3. 🧠 零信任内存保险箱与物理 RAM 锁盾 (MemoryShield)
* **防磁盘交换**：调用 Windows 内核 API（`VirtualAlloc` + `VirtualLock`），将口令与解密主密钥常驻物理 RAM，禁止操作系统交换到 `pagefile.sys` 虚拟内存盘。
* **物理写零销毁**：凭据到期（默认 15 分钟）或任务中断时，使用 `ctypes.memset` 原地以 `0x00` 强力擦除内存残留。

### 4. ⚡ 强力多核心并发与智能测速 (Multi-Worker Concurrency)
* **动态线程池**：支持 1~8 核心并行加解密调度，配合高可读性 Worker 咬合卡槽，实时展示单核心任务状态。
* **智能遥测**：毫秒级采样真实 I/O 速率，动态平滑预测任务剩余耗时（ETA）。

### 5. 🪟 现代化 WinUI 3 极简云母视觉 (Modern Mica UI)
* **高 DPI 无边框全向拉伸**：底层挂接 Windows 原生 `WM_NCHITTEST` 消息，四周 8px 边缘与四个对角线支持硬件级平滑拖拽调整窗口大小。
* **自由拉伸日志区**：内置垂直 `QSplitter` 分割条，支持按需随心拖拽扩大/缩小日志面板。
* **双模式主题**：支持极夜深色与日光浅色动态切换，以及自定义背景图与透明度暗化遮罩。

### 6. 🔄 100% 历史版本全向下兼容 (Full Backward Compatibility)
* 内置全协议自适应探测引擎，完美无缝解密自 V0.0.1 至今的所有历史格式（V0、V1、V2、V3、V4、SFK V1、ECC V1、ChaCha20）。历史文件解密无需插入硬件锁，输入原本密码即可还原。

---

## 🏗️ 仓库架构一览 (Repository Structure)

```
-Encrypted-file/
├── core/                        # 核心引擎与安全盾
│   ├── config.py                # 协议魔数、参数常量与统一日志器
│   ├── compression.py           # 4MB 流式分块压缩引擎
│   ├── hardware.py              # Windows 物理硬件锁 (U盘/移动硬盘) 驱动器管理器
│   ├── memory.py                # Windows VirtualLock 物理内存盾与 zero_bytes
│   ├── resume_mgr.py            # 大文件断点续加/续解检查点管理器
│   ├── settings.py              # 配置持久化管理器 (saes_settings.json)
│   ├── utils.py                 # 长路径突破、BLAKE2b 计算、安全覆写落盘
│   ├── vault.py                 # CredentialVault 内存凭据保险箱
│   └── worker.py                # 异步加解密、文件扫描与并发调度线程
├── ui/                          # WinUI 3 现代化流体前端
│   ├── components.py            # 现代化自定义控件 (DropArea, CustomSwitchRow 等)
│   ├── dialogs.py               # 硬件锁选择绑定弹窗、安全密码输入确认弹窗
│   ├── main_window.py           # 核心无边框主窗体 (自由拖拽调整大小、分割条)
│   ├── monitor_panel.py         # 性能看板与 8 核心 Worker 咬合卡槽
│   └── styles.py                # WinUI 3 Fluent / Mica 磨砂玻璃 QSS 样式表
├── docs/                        # 技术文档与规格说明书
│   ├── ARCHITECTURE.md          # 总体架构设计与安全威胁模型
│   ├── PROTOCOL_SPECS.md        # V0 ~ V4、SFK、ECC、ChaCha 协议格式规范
│   └── HARDWARE_TOKEN.md        # 物理硬件钥匙使用与技术指南
├── legacy/                      # 历史版本代码归档 (0.0.1 ~ 8.0.1)
│   ├── 文件加密0.0.1.py
│   ├── 1.0.1.py / 2.0.1.py / 2.0.2.py
│   ├── 文件加密3.0.1.py / 文件加密4.0.1.py
│   ├── 7.0.2.py (工业稳定单脚本版)
│   ├── 8.0.1/ (模块化早期版本)
│   └── README.md                # 历史版本演进与技术说明
├── tests/                       # 自动化测试套件
│   ├── test_crypto.py           # 密码学与加解密测试
│   └── test_hardware.py         # 硬件锁绑定与物理阻断测试
├── .gitignore                   # Git 忽略配置
├── CoreVault_9.0.1.spec         # PyInstaller 独立单文件打包配置文件
├── requirements.txt             # 生产依赖说明
├── main.py                      # 统一标准启动入口
└── 9.0.1.py                     # 版本启动入口
```

---

## 🚀 快速上手 (Quick Start)

### 1. 安装环境与运行
```bash
# 1. 克隆本仓库
git clone https://github.com/yly20111121/-Encrypted-file.git
cd -Encrypted-file

# 2. 安装 Python 核心依赖 (建议 Python 3.10+)
pip install -r requirements.txt

# 3. 点火启动
python main.py
```

### 2. 独立可执行程序打包 (Standalone Packaging)
仓库内附带优化配置好的 `CoreVault_9.0.1.spec`，可直接生成无需 Python 环境的单文件可执行程序：
```bash
pyinstaller CoreVault_9.0.1.spec --clean --noconfirm
```
打包输出物将生成在 `dist/CoreVault_9.0.1.exe`，支持独立分发与开箱即用。

---

## ⚙️ 密码学与技术指标 (Specifications)

| 指标维度 | 技术实现参数 |
| :--- | :--- |
| **主要加密算法** | AES-256-GCM (NIST SP 800-38D) / ChaCha20-Poly1305 (RFC 8439) |
| **密钥派生函数** | Scrypt ($N=262144, r=8, p=1$, ~256MB 内存强制防 ASIC 破解) |
| **流式分块单位** | 4MB 流式区块 (实时带认证 AAD 防篡改与重放) |
| **硬件锁绑定** | 物理卷序列号 + Windows IOCTL 设备属性深度嵌入 KDF 盐 |
| **非对称加密** | Curve25519 (X25519 ECDH) 密钥协商 |
| **内存防转储** | Windows `VirtualAlloc` + `VirtualLock` 物理内存驻留盾 |
| **原文件清理** | 物理全零覆盖 (`0x00`) + `fsync` 强制物理扇区落盘后安全删除 |

---

## 📖 扩展阅读与文档
* [系统架构设计与安全模型 (ARCHITECTURE.md)](docs/ARCHITECTURE.md)
* [全版本协议魔数与格式规范 (PROTOCOL_SPECS.md)](docs/PROTOCOL_SPECS.md)
* [物理硬件锁详细使用指南 (HARDWARE_TOKEN.md)](docs/HARDWARE_TOKEN.md)
* [历史版本代码归档说明 (legacy/README.md)](legacy/README.md)

---

## 📄 开源许可证 (License)
本项目依据 [MIT License](LICENSE) 开源发布。
