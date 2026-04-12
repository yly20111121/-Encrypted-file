# SAES-GCM 加密引擎 (Core Vault Edition)
## 警告！！！本软件自2.0.1被安全软件识别为病毒，请添加白名单（或关闭安全软件）或直接运行py程序
## 不同大版本的不通用!!!因为文件头不一样（大版本）
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![PySide6](https://img.shields.io/badge/PySide6-GUI-green.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

SAES-GCM 是一个专为 Windows 桌面环境打造的**高强度、流式文件加解密工具**。

它摒弃了传统加密工具臃肿的设定，主打“即用即走”的极客体验。底层采用 `AES-GCM` 认证加密，结合抗 ASIC 的 `Scrypt` 密钥派生算法与**内存级凭据保险箱**，在保证极高物理安全性的同时，提供丝滑的批量文件处理工作流。

## ✨ 核心特性 (Core Features)

* **🛡️ 军工级密码学防线**
  * **流式 AES-GCM (256-bit)**：采用 4MB 区块流式处理，防范超大文件引发的 OOM (内存溢出) 攻击。
  * **高强度 KDF**：使用 `Scrypt (n=2**17, r=8, p=1)` 派生密钥，单次派生消耗约 128MB 内存，极大提升暴力破解和 GPU 跑字典的成本。
  * **AAD 协议绑定**：文件头（Magic Number + Salt + Nonce）作为附加身份验证数据（AAD）绑定，任何对文件头的位翻转篡改将在解密第一步被瞬间拦截。
* **🧠 零信任内存保险箱 (Credential Vault)**
  * 密码不在 GUI 控件或 Python `str` 常量池中驻留。注入后瞬间转入底层的可变 `bytearray`。
  * **15 分钟 TTL**：凭据缓存在 15 分钟无操作后，底层守护进程将主动触发**物理覆写 (`\x00`)** 并销毁，防御 RAM Dump 提取。
* **⚡ 生产力级批处理流水线**
  * 支持**多文件/多层级目录**拖拽，自动展平文件树压入队列。
  * 深度融合 Windows CLI：支持通过 `sys.argv` 唤醒，完美集成 Windows 右键 `SendTo (发送到)` 菜单，一键处理海量文件。
* **🛠️ 极端场景健壮性**
  * **并发阻断**：提供“紧急制动 (Abort)”功能，通过协程状态机安全切断 I/O 流，杜绝文件句柄泄漏。
  * **防系统锁死**：内置指数退避重试算法，对抗 Windows Defender 在解密落盘瞬间的恶意抢占锁死。

## 🚀 快速上手 (Quick Start)

### 方案 A：直接运行 (开发者模式)
```bash
# 1. 克隆仓库
git clone [https://github.com/yly20111121/-Encrypted-file.git](https://github.com/yly20111121/-Encrypted-file.git)
cd -Encrypted-file

# 2. 创建并激活虚拟环境
py -m venv venv
.\venv\Scripts\activate

# 3. 安装核心依赖
pip install PySide6 cryptography

# 4. 点火启动
py 2.0.1.py
```
💡 CLI 与系统融合
本工具支持通过 sys.argv 传递绝对路径。你可以轻易地将其与 Windows 右键菜单或 SendTo 目录集成，实现一键批量加密。

⚠️ 安全声明
本工具遵循严格的密码学最佳实践。但请注意：密钥遗失即意味着数据永久性损毁。没有任何后门或恢复机制可以拯救忘记密码的数据。请妥善保管您的安全凭据。

📄 License
本项目采用 MIT License 开源协议。
