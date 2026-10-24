# Core Vault 9.0.1 架构设计与工程规范 (System Architecture)

Core Vault 9.0.1 是专为 Windows 平台打造的高性能、零信任安全架构的文件加密工具。本文档详述其底层内核架构、安全模型与模块划分。

---

## 🏛️ 总体分层架构 (Layered Architecture)

```
┌────────────────────────────────────────────────────────────────────────┐
│                        用户交互层 (Presentation UI)                     │
│  - MainWindow: WinUI 3 Mica/Fluent 磨砂玻璃无边框窗口 (WM_NCHITTEST 缩放)│
│  - PerformanceDashboard: 8 核心 Worker 状态矩阵、吞吐测速与智能 ETA   │
│  - QSplitter: 垂直自由可拉伸日志面板                                    │
│  - ThemeManager: 极夜深色 (Dark) / 日光浅色 (Light) 动态 QSS            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ 异步 Qt 信号与槽 (Signals / Slots)
┌───────────────────────────────────▼────────────────────────────────────┐
│                        任务调度与流水线 (Async Pipeline)                │
│  - CryptoWorker: 多线程并行加解密调度引擎 (动态核心绑定)                 │
│  - FileScannerWorker: 异步递归扫描与魔数协议嗅探分流                   │
│  - KeyfileHasherWorker: BLAKE2b 文件锁并行异步哈希计算                 │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                        核心引擎与安全盾 (Core Security)                 │
│  - MemoryShield: Windows VirtualLock / VirtualAlloc 物理 RAM 锁盾      │
│  - CredentialVault: 零信任口令暂存箱 (TTL 超时自动物理写零覆写)        │
│  - HardwareTokenManager: 物理 U 盘 / USB 移动硬盘只读硬件卷序列号绑定    │
│  - StreamCompression: 4MB 实时流式分块压缩 (zlib Deflate)               │
│  - ResumeManager: 大文件断点续加/续解检查点系统                        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                        密码学底层 (Cryptographic Primitives)           │
│  - 对称加密: AES-256-GCM / ChaCha20-Poly1305 (AEAD 带认证加密)         │
│  - 密钥派生: Scrypt (N=2^18, r=8, p=1) / HKDF-SHA256                   │
│  - 非对称加密: X25519 椭圆曲线 Diffie-Hellman 密钥协商                 │
│  - 哈希校验: BLAKE2b (64-byte)                                         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ 核心安全模型与防护机制

### 1. 物理内存加锁盾 (MemoryShield & VirtualLock)
* **防内存换页攻击**：Windows 系统在内存紧张时会将内存页置换至磁盘上的 `pagefile.sys` 或 `hiberfil.sys`。Core Vault 调用 Windows 内核 API `VirtualAlloc(MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)` 并执行 `VirtualLock`，强制口令及解密密钥常驻物理 RAM，禁止换页写入磁盘。
* **物理写零擦除 (`zero_bytes`)**：当口令凭据超时（默认 15 分钟）或用户手动锁定、任务终止时，不仅清空 Python 引用，更通过 `ctypes.memset` 直接将底层内存覆写为 `0x00`。

### 2. 物理硬件锁安全容器 (`MAGIC_HW_V1`)
* **设备级物理绑定**：支持将任意可移动 U 盘（`DRIVE_REMOVABLE`）或 USB 移动硬盘（`BusTypeUsb`）绑定为硬件钥匙。
* **不可剥离特性**：文件头包装 `SAHW\x01` 容器，记录硬件卷序列号；同时派生密钥时将该硬件序列号深度混入 HKDF 派生盐，即使攻击者用 Hex 编辑器强行篡改或删除文件头，解密时仍会因 Tag Mismatch 无法解密。
* **拔出紧急制动**：后台心跳检测（Heartbeat）持续探测硬件插入状态，加解密过程中若硬件被强行拔出，流水线立即触发安全熔断并销毁内存密钥。

### 3. 流式分块与 OOM 防御
* **4MB 分块流式处理**：无论处理 100MB 还是 100GB 的超大文件，内存占用始终恒定在极低水平，彻底杜绝单次读取大文件导致的内存溢出（OOM）崩溃或系统卡顿。
* **带认证关联数据 (AAD)**：每一个分块包含专属的递增 Nonce 计数器，严格防止密文重放、分块交换或截断攻击。

### 4. 工业级 Windows 长路径与长文件名兼容
* 全面适配 Windows `\\?\` 长路径前缀，无惧超过 260 字符（MAX_PATH）的深层目录结构，规避 Windows 经典路径溢出异常。
