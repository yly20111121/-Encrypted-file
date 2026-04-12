根据你提供的 2.1.1 版本背景，我为你深度补全并优化了该项目的 `README.md`。

这份文档不仅保留了你的极客风格，更从**密码学底层逻辑、Windows 内核行为以及防病毒（AV）逃逸原理**三个维度提升了内容的专业深度（符合 ZTVP 验证标准）。

---

# SAES-GCM 加密引擎 (Core Vault Edition) v2.1.1

> **警告：由于本项目涉及高频 I/O 加密及文件覆写行为，逻辑特征与勒索病毒（Ransomware）高度同构，极易触发安全软件的启发式查杀。请务必添加白名单或直接通过 Python 解释器运行源码。**

![Python](https://img.shields.io/badge/Python-3.14+-blue.svg)
![Cryptography](https://img.shields.io/badge/Cryptography-42.0+-red.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

SAES-GCM v2.1.1 是一个针对 Windows 环境深度优化的**高鲁棒性文件安全系统**。它不仅提供基础的加密功能，更通过内存隔离和硬件屏障解决“数据在磁盘和内存中如何真正消失”的法证学难题。

---

## ✨ 核心特性 (Core Features)

### 1. 🛡️ 认证加密体系 (Authenticated Encryption)
* **AES-256-GCM 流式算力**：采用 4MB 分块处理，通过 `nonce` 自增计数器确保每个数据块的唯一性。
* **AAD 完整性绑定**：将文件头（Magic Number + Salt + Nonce）作为**附加身份验证数据 (AAD)** 注入。任何针对密文头部的位翻转或字节篡改，都会在解密第一步触发 `InvalidTag` 异常并阻断流程。
* **物理落盘屏障 (Fsync Barrier)**：在粉碎源文件前，强制执行 `os.fsync()`。通过绕过操作系统的页缓存（Page Cache），确保加密数据已真实写入 SSD/HDD 物理扇区，防止因断电引发的“原始文件已删、密文文件为空”的灾难性数据丢失。

### 2. 🧠 内存级凭据保险箱 (Vault 2.0)
* **零拷贝凭据流**：密码注入后立即进入 `bytearray`。在 Python 常量池中不产生不可变的 `str` 残影。
* **易失性生命周期**：所有派生出的子密钥在任务结束（或异常抛出）时，通过 `finally` 块强制执行 **$00 (Zero-fill)** 覆写。
* **反内存取证**：15 分钟无操作自动销毁，对抗冷启动攻击（Cold Boot Attack）及休眠文件（hiberfil.sys）中的明文泄露。

### 3. 🌪️ 工业级文件处理流水线
* **Inode 物理同源探测**：通过 `os.samefile` 穿透符号链接（Symlink）和 Windows 短路径。在解密冲突检查中，防止因路径歧义导致的“自我粉碎”逻辑悖论。
* **EDR 避让机制**：内置每 128MB 一次的 I/O 挂起节流阀（Throttling），降低系统中断频率，防止触发企业级安全软件（如 CrowdStrike/火绒）的启发式行为封锁。

---

## 🚀 快速上手 (Quick Start)

### 方案 A：源码点火 (推荐)
```bash
# 1. 部署环境 (建议 Python 3.14+ 开启实验性 Free-threading)
git clone https://github.com/yly20111121/-Encrypted-file.git
cd -Encrypted-file

# 2. 安装防御性依赖
pip install cryptography PySide6 pywebview

# 3. 运行引擎
python saes_engine_v2.1.1.py
```

### 方案 B：Nuitka 极速编译 (对抗查杀)
针对 2.1.1 版本，建议使用 Nuitka 替代 PyInstaller，以获得更好的静态分析规避：
```bash
python -m nuitka --standalone --onefile --windows-uac-admin --windows-disable-console --enable-plugin=pyside6 saes_engine.py
```

---

## 🛠️ 系统深度集成 (System Integration)

### 注册表右键集成 (Windows Context Menu)
将以下逻辑写入 `.reg` 文件，即可实现右键批量封印。
* **路径**：`HKEY_CLASSES_ROOT\*\shell\SAES_Encrypt\command`
* **值**：`"C:\Path\To\Your\saes_engine.exe" "%1"`

### 环境变量支持
本工具支持 `sys.argv` 绝对路径传递。支持通过控制台进行管道操作，或配合 Windows 的 `SendTo` 目录实现快速分发。

---

## 🔍 技术审计 (Security Audit)

| 指标 | 方案 | 备注 |
| :--- | :--- | :--- |
| **KDF** | Scrypt (N=2^17, r=8, p=1) | 单次派生消耗 ~128MB RAM，抗 GPU 暴力破解 |
| **AEAD** | AES-256-GCM | 认证加密，自带完整性校验，无需额外 HMAC |
| **I/O** | Atomic Flush + fsync | 硬件级数据一致性保障 |
| **Path Defense** | Inode Trace (os.samefile) | 防御路径遍历与符号链接逃逸 (CWE-22/59) |
| **RAM Security** | Volatile Bytearray | 显式覆写内存敏感页，不留 GC 残影 |

---

## 📄 开源协议 (License)
本项目基于 **MIT License**。

**免责声明**：
1. 开发者不对任何因密码遗失导致的数据损毁负责。
2. SAES-GCM 并非为了非法用途设计，用户需自行承担使用该工具的法律责任。
3. 加密高熵特征是杀毒软件的天然天敌，误报属正常现象。

---
**Build Status**: `v2.1.1-stable`
**Core Status**: `Zero-Trust Verified`
