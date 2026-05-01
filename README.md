# SAES-GCM 加密引擎 (Core Vault Edition)

## ⚠️ 风险预警
* **安全拦截**：由于本工具涉及底层二进制流操作与文件改写，打包版本（exe）极易被 Windows Defender 或 360 识别为“启发式病毒”。请**添加白名单**，或推荐直接通过 **Python 源码运行**以获得最高安全性。
* **版本兼容性**：**不同大版本协议不通用**。本引擎（v3.0.1）采用动态协议识别，能够向上兼容解密 V0、V1 及 V2 格式，但加密时默认采用最新的 V3 安全标准。

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![PySide6](https://img.shields.io/badge/PySide6-6.4+-green.svg)
![Cryptography](https://img.shields.io/badge/Cryptography-41.0+-orange.svg)

SAES-GCM 3.0 是一款专为 Windows 环境设计的**高强度、零信任架构**文件加密工具。它不仅提供 AES-GCM 级别的数学安全性，更针对操作系统层面的侧信道攻击、内存提取和文件残留进行了深度加固。

---

## ✨ 3.0.1 版本核心进化 (What's New)

### 🛡️ 协议层：V3 安全架构
* **Scrypt 指数级增强**：加密默认采用 `N=2^17` 参数，单次派生强制占用约 128MB 内存，彻底封杀硬件加速破解的可能性。
* **多版本回溯解密**：内置协议自动探测引擎，支持 V0.0.1 (PBKDF2)、V1.0.1 (Scrypt N=14) 及 V2.0.2 历史文件的无缝解密。
* **全元数据加密**：文件名、原始文件大小等敏感信息全部压入加密 Meta 块中，外部无法通过 `.enc` 文件得知原始文件性质。

### 🧠 零信任内存保险箱 (Credential Vault)
* **物理覆写注销**：凭据不仅在 TTL 到期后失效，还会触发底层 `bytearray` 的物理覆盖（`\x00`），防止内存镜像中的密钥残留。
* **安全熔断机制**：在批量任务中，一旦发生凭据校验失败（InvalidTag），系统将立即触发“流水线熔断”，停止后续所有任务。

### 🛠️ 工业级 I/O 处理
* **长路径突破**：全面适配 Windows `\\?\` 长路径协议，支持超过 255 字符的深度目录访问。
* **文件粉碎 (Shred)**：提供“头尾覆盖”粉碎模式，在删除原文件前对物理扇区进行强制覆写。
* **智能过滤引擎**：自动识别已加密/未加密状态，防止“二次加密”导致的逻辑混乱。

---

## 🚀 部署指南

### 推荐方案：源码运行
1.  **环境准备**：
    ```bash
    git clone [https://github.com/yly20111121/-Encrypted-file.git](https://github.com/yly20111121/-Encrypted-file.git)
    cd -Encrypted-file
    pip install PySide6 cryptography
    ```
2.  **点火启动**：
    ```bash
    python "文件加密3.0.1.py"
    ```

### 集成到 Windows 右键菜单
将脚本或打包后的 exe 创建快捷方式，放入 `shell:sendto` 文件夹中。之后只需在文件上右键选择“发送到”，即可瞬间装载任务队列。

---

## ⚙️ 技术规格 (Technical Specs)

| 维度 | 技术实现 |
| :--- | :--- |
| **对称加密** | AES-256-GCM (Authenticated Encryption) |
| **密钥派生 (KDF)** | Scrypt (N=131072, r=8, p=1) |
| **分块大小** | 4MB 流式区块 (防 OOM 攻击) |
| **冲突策略** | 询问 / 自动重命名 / 跳过 / 覆盖 |
| **身份验证** | AAD 绑定文件头（Magic + Salt + Nonce） |
| **删除算法** | 同步覆写 + fsync 强制落盘 |

---

## ⚠️ 重要声明
1.  **无后门设计**：本工具不设任何恢复机制。若密码丢失，没有任何手段可以找回数据。
2.  **残留清理**：程序启动时会自动检测上次运行残留的 `.tmp` 文件并提示清理，请务必关注。
3.  **开发者建议**：在大规模处理前，请先在少量样本上测试密码一致性。

**License**: [MIT License](https://opensource.org/licenses/MIT)
