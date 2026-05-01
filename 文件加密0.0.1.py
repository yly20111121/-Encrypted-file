import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag

# ================= 核心常量配置 =================
CHUNK_SIZE = 4 * 1024 * 1024          # 数据块大小：4MB
SALT_SIZE = 16                        # 盐值长度：16 Bytes
NONCE_SIZE = 12                       # Nonce 长度：12 Bytes (AES-GCM 标准)
LENGTH_FIELD_SIZE = 4                 # 加密块长度字段大小：4 Bytes
MAC_TAG_SIZE = 16                     # 认证标签长度：16 Bytes
MAX_ENC_LEN = CHUNK_SIZE + MAC_TAG_SIZE # 加密后最大长度防 OOM

def get_key(password: str, salt: bytes) -> bytes:
    """使用 PBKDF2HMAC 从密码派生 256-bit (32 bytes) 密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return kdf.derive(password.encode())

def encrypt_file(input_path: str, output_path: str, password: str):
    success = False
    try:
        salt = os.urandom(SALT_SIZE)
        key = get_key(password, salt)
        aesgcm = AESGCM(key)
        
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(salt)
            chunk_index = 0
            
            print(f"[*] 开始加密: {input_path}")
            
            # 【建议方案】预读缓冲法：读取当前块
            current_chunk = f_in.read(CHUNK_SIZE)
            
            # 处理空文件的边界情况
            if not current_chunk:
                is_last = b'\x01'
                nonce = os.urandom(NONCE_SIZE)
                aad = chunk_index.to_bytes(8, 'big') + is_last
                enc_data = aesgcm.encrypt(nonce, b'', aad)
                f_out.write(is_last + len(enc_data).to_bytes(LENGTH_FIELD_SIZE, 'big') + nonce + enc_data)
            else:
                while current_chunk:
                    # 尝试预读下一个块
                    next_chunk = f_in.read(CHUNK_SIZE)
                    
                    # 若预读为空，说明当前块即为文件的最后一块
                    is_last = b'\x01' if not next_chunk else b'\x00'
                    nonce = os.urandom(NONCE_SIZE)
                    
                    aad = chunk_index.to_bytes(8, 'big') + is_last
                    enc_data = aesgcm.encrypt(nonce, current_chunk, aad)
                    
                    f_out.write(is_last + len(enc_data).to_bytes(LENGTH_FIELD_SIZE, 'big') + nonce + enc_data)
                    chunk_index += 1
                    
                    print(f"\r[*] 进度: 加密中... 已处理数据块: {chunk_index}", end="")
                    
                    # 滚动缓冲区
                    current_chunk = next_chunk
            
        print(f"\n[+] 加密成功！文件已保存为: {output_path}")
        success = True

    except Exception as e:
        print(f"\n[-] 加密失败: {e}")
    finally:
        # 文件句柄释放后进行异常清理
        if not success and os.path.exists(output_path):
            os.remove(output_path)
            print(f"[*] 已清理未完成的文件: {output_path}")

def decrypt_file(input_path: str, output_path: str, password: str):
    success = False
    try:
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            salt = f_in.read(SALT_SIZE)
            if len(salt) < SALT_SIZE:
                raise ValueError("文件格式错误或为空。")
                
            key = get_key(password, salt)
            aesgcm = AESGCM(key)
            
            chunk_index = 0
            last_chunk_seen = False
            
            print(f"[*] 开始解密: {input_path}")
            
            while True:
                is_last_byte = f_in.read(1)
                
                if not is_last_byte:
                    if not last_chunk_seen:
                        raise ValueError("致命错误: 文件尾部被异常截断或损坏！")
                    break
                
                # 读取长度字段
                enc_len_bytes = f_in.read(LENGTH_FIELD_SIZE)
                if len(enc_len_bytes) != LENGTH_FIELD_SIZE:
                    raise ValueError("致命错误: 无法读取完整的块长度信息。")
                enc_len = int.from_bytes(enc_len_bytes, 'big')
                
                # 【建议方案】防 OOM 校验
                if enc_len > MAX_ENC_LEN or enc_len < MAC_TAG_SIZE:
                    raise ValueError(f"致命错误: 异常的数据块长度 ({enc_len} bytes)，文件已被篡改！")
                
                nonce = f_in.read(NONCE_SIZE)
                enc_data = f_in.read(enc_len)
                
                if len(enc_data) != enc_len or len(nonce) != NONCE_SIZE:
                    raise ValueError("致命错误: 数据块不完整，文件已损坏。")
                
                aad = chunk_index.to_bytes(8, 'big') + is_last_byte
                
                try:
                    dec_data = aesgcm.decrypt(nonce, enc_data, aad)
                except InvalidTag:
                    raise ValueError(f"密码错误，或数据块 {chunk_index} 已被恶意篡改！")
                    
                f_out.write(dec_data)
                
                if is_last_byte == b'\x01':
                    last_chunk_seen = True
                    
                chunk_index += 1
                print(f"\r[*] 进度: 解密中... 已处理数据块: {chunk_index}", end="")
                
        print(f"\n[+] 解密成功！文件已还原为: {output_path}")
        success = True

    except Exception as e:
        print(f"\n[-] 解密失败: {e}")
    finally:
        # 文件句柄释放后进行异常清理
        if not success and os.path.exists(output_path):
            os.remove(output_path)
            print(f"[*] 已清理解密失败的残余文件: {output_path}")

def prompt_overwrite(path: str) -> bool:
    """检查文件是否存在并询问是否覆盖"""
    if os.path.exists(path):
        choice = input(f"[*] 目标文件已存在: {path}\n是否覆盖? (y/n): ").strip().lower()
        if choice != 'y':
            print("[-] 操作已取消。")
            return False
    return True

def main():
    while True:
        print("\n" + "="*40)
        print("  流式安全加解密工具 (支持超大文件)")
        print("="*40)
        print("1. 加密文件")
        print("2. 解密文件")
        print("3. 退出")
        print("="*40)
        
        choice = input("请选择操作 (1/2/3): ").strip()

        if choice == '1':
            path = input("请输入要加密的文件路径: ").strip('\"\'')
            if not os.path.isfile(path):
                print("[-] 错误: 找不到该源文件！")
                continue
            
            output_path = path + '.enc'
            if not prompt_overwrite(output_path):
                continue
            
            pwd = getpass("设置加密密码(此处自动隐藏): ")
            pwd_confirm = getpass("再次输入密码(此处自动隐藏): ")
            
            if pwd != pwd_confirm:
                print("[-] 错误: 两次密码不一致！")
                continue
            
            encrypt_file(path, output_path, pwd)

        elif choice == '2':
            path = input("请输入要解密的文件路径 (.enc): ").strip('\"\'')
            if not os.path.isfile(path):
                print("[-] 错误: 找不到该源文件！")
                continue
            
            if path.endswith('.enc'):
                output_path = path[:-4]
            else:
                output_path = path + '.dec'
                
            if not prompt_overwrite(output_path):
                continue
            
            pwd = getpass("输入解密密码(此处自动隐藏): ")
            decrypt_file(path, output_path, pwd)

        elif choice == '3':
            print("程序已退出。")
            break
            
        else:
            print("[-] 无效选项。")

if __name__ == "__main__":
    main()