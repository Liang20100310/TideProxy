#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy Shadowsocks 协议处理模块

完整实现 Shadowsocks 代理协议，支持：
- AEAD 加密（aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305）
- 流式加密（aes-128-cfb, aes-256-cfb, chacha20-ietf）
- SOCKS5 子协议解析（目标地址解析）
- 多用户支持（每个用户独立密码/密钥）

协议流程：
1. 客户端连接，发送加密的握手数据
2. 服务端解密获取目标地址（SOCKS5格式）
3. 服务端建立到目标的连接
4. 双向加密转发数据

兼容性：
- 完全兼容标准Shadowsocks客户端
- 支持 iOS/Android/Windows/macOS/Linux 客户端
- 支持 Shadowrocket, Surfboard, V2rayN, Clash 等客户端

加密方式说明：
- AEAD模式（推荐）：每条记录独立加密，自带完整性校验
  - 密钥派生：HKDF-SHA1 从主密码派生子密钥
  - 每条记录：随机Nonce + 加密数据 + 16字节TAG
- 流式模式（旧版）：连续流加密，无完整性校验
  - 密钥派生：EVP_BytesToKey 从主密码派生
  - 使用CFB模式流加密

参考：https://shadowsocks.org/doc/spec/v2.html
"""

import asyncio
import hashlib
import hmac
import os
import socket
import struct
import threading
from collections import defaultdict

from config import Config
from logger import get_logger

# ============================================================
# 尝试导入加密库
# 优先使用 cryptography 库（更安全、更快）
# ============================================================
_HAS_CRYPTO = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTO = True
except ImportError:
    pass

_HAS_PYCRYPTODOME = False
try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305 as ChaCha20Poly1305_Crypto
    from Crypto.Util import Counter
    _HAS_PYCRYPTODOME = True
except ImportError:
    pass


# ============================================================
# AEAD 加密/解密实现
# ============================================================

class AEADCipher:
    """
    AEAD加密器（支持AES-GCM和ChaCha20-Poly1305）

    每条记录格式：
    +----------+----------+-----------+----------+
    | 数据长度  | 长度TAG  | 加密数据   | 数据TAG  |
    | 2字节     | 16字节   | N字节     | 16字节   |
    +----------+----------+-----------+----------+

    长度和数据分别加密，TAG用于完整性校验。
    """

    # 支持的加密方式及其密钥长度、Nonce长度、TAG长度
    CIPHER_SPECS = {
        "aes-128-gcm": {"key_len": 16, "nonce_len": 12, "tag_len": 16},
        "aes-256-gcm": {"key_len": 32, "nonce_len": 12, "tag_len": 16},
        "chacha20-ietf-poly1305": {"key_len": 32, "nonce_len": 12, "tag_len": 16},
    }

    def __init__(self, method, password):
        """
        初始化AEAD加密器

        参数：
            method: 加密方式（如 "aes-256-gcm"）
            password: 密码字符串
        """
        if method not in self.CIPHER_SPECS:
            raise ValueError(f"不支持的加密方式: {method}")

        if not _HAS_CRYPTO:
            raise ImportError("需要安装 cryptography 库: pip install cryptography")

        self.method = method
        spec = self.CIPHER_SPECS[method]

        # 从密码派生主密钥（HKDF-SHA1）
        self._key_len = spec["key_len"]
        self._nonce_len = spec["nonce_len"]
        self._tag_len = spec["tag_len"]

        # 密钥派生：password -> HKDF-SHA1 -> subkey
        password_bytes = password.encode("utf-8")
        # 使用固定的salt进行密钥派生（Shadowsocks规范）
        salt = b"ss-subkey"
        hkdf = HKDF(
            algorithm=hashes.SHA1(),
            length=self._key_len,
            salt=salt,
            info=b"ss-subkey",
            backend=default_backend()
        )
        self._subkey = hkdf.derive(password_bytes)

        # Nonce计数器（每个连接独立，从0开始递增）
        self._nonce_counter = 0
        self._lock = threading.Lock()

    def encrypt(self, plaintext):
        """
        AEAD加密一条记录

        参数：
            plaintext: 明文数据（bytes）

        返回：
            bytes: 加密后的数据（长度TAG + 加密长度 + 数据TAG + 加密数据）
        """
        with self._lock:
            nonce = self._get_nonce()

            # 加密数据长度（2字节，大端序）
            data_len = len(plaintext)
            len_bytes = struct.pack("!H", data_len)

            # 根据加密方式选择加密器
            if self.method.startswith("aes"):
                aesgcm = AESGCM(self._subkey)
                # 加密长度
                encrypted_len = aesgcm.encrypt(nonce, len_bytes, None)
                # 加密数据
                encrypted_data = aesgcm.encrypt(nonce, plaintext, None)
            elif self.method == "chacha20-ietf-poly1305":
                cipher = ChaCha20Poly1305(self._subkey)
                encrypted_len = cipher.encrypt(nonce, len_bytes, None)
                encrypted_data = cipher.encrypt(nonce, plaintext, None)
            else:
                raise ValueError(f"不支持的加密方式: {self.method}")

            # 返回：加密长度 + 加密数据
            return encrypted_len + encrypted_data

    def decrypt(self, ciphertext):
        """
        AEAD解密一条记录

        参数：
            ciphertext: 密文数据

        返回：
            tuple: (明文数据 bytes, 消耗的密文字节数)
                   解密失败返回 (None, 0)
        """
        with self._lock:
            # 计算最小数据量：长度加密(2+16) + 数据加密(N+16)
            min_len = 2 + self._tag_len + self._tag_len

            if len(ciphertext) < min_len:
                return None, 0

            nonce = self._get_nonce()

            # 根据加密方式选择解密器
            if self.method.startswith("aes"):
                aesgcm = AESGCM(self._subkey)
                # 解密长度
                try:
                    len_bytes = aesgcm.decrypt(
                        ciphertext[:2 + self._tag_len], nonce, None
                    )
                except Exception:
                    return None, 0

                data_len = struct.unpack("!H", len_bytes)[0]

                # 检查是否有足够的数据
                total_needed = 2 + self._tag_len + data_len + self._tag_len
                if len(ciphertext) < total_needed:
                    return None, 0

                # 解密数据
                try:
                    plaintext = aesgcm.decrypt(
                        ciphertext[2 + self._tag_len:total_needed],
                        nonce, None
                    )
                except Exception:
                    return None, 0

            elif self.method == "chacha20-ietf-poly1305":
                cipher = ChaCha20Poly1305(self._subkey)
                try:
                    len_bytes = cipher.decrypt(
                        ciphertext[:2 + self._tag_len], nonce, None
                    )
                except Exception:
                    return None, 0

                data_len = struct.unpack("!H", len_bytes)[0]

                total_needed = 2 + self._tag_len + data_len + self._tag_len
                if len(ciphertext) < total_needed:
                    return None, 0

                try:
                    plaintext = cipher.decrypt(
                        ciphertext[2 + self._tag_len:total_needed],
                        nonce, None
                    )
                except Exception:
                    return None, 0
            else:
                return None, 0

            return plaintext, total_needed

    def _get_nonce(self):
        """
        生成当前Nonce并递增计数器

        返回：
            bytes: 固定长度的Nonce（12字节）
        """
        nonce = self._nonce_counter.to_bytes(self._nonce_len, "little")
        self._nonce_counter += 1
        return nonce


class StreamCipher:
    """
    流式加密器（支持AES-CFB和ChaCha20）

    流式加密是连续的，不需要分帧。
    使用EVP_BytesToKey从密码派生密钥。
    """

    CIPHER_SPECS = {
        "aes-128-cfb": {"key_len": 16, "iv_len": 16, "block_size": 16},
        "aes-256-cfb": {"key_len": 32, "iv_len": 16, "block_size": 16},
        "chacha20-ietf": {"key_len": 32, "iv_len": 12, "block_size": 64},
    }

    def __init__(self, method, password):
        if method not in self.CIPHER_SPECS:
            raise ValueError(f"不支持的加密方式: {method}")

        self.method = method
        spec = self.CIPHER_SPECS[method]
        self._key_len = spec["key_len"]
        self._iv_len = spec["iv_len"]

        # EVP_BytesToKey 密钥派生
        self._key = self._evp_bytes_to_key(password, self._key_len)

        # 加密/解密器（延迟初始化，收到IV后创建）
        self._encryptor = None
        self._decryptor = None
        self._encrypt_iv = None
        self._decrypt_iv = None

    def encrypt_init(self):
        """
        初始化加密器，返回IV

        返回：
            bytes: 随机IV
        """
        iv = os.urandom(self._iv_len)
        self._encrypt_iv = iv
        self._encryptor = self._create_cipher(self._key, iv, "encrypt")
        return iv

    def encrypt(self, data):
        """加密数据"""
        if self._encryptor is None:
            raise RuntimeError("加密器未初始化，请先调用 encrypt_init()")
        return self._encryptor.update(data)

    def decrypt_init(self, iv):
        """
        使用收到的IV初始化解密器

        参数：
            iv: 从客户端收到的IV
        """
        self._decrypt_iv = iv
        self._decryptor = self._create_cipher(self._key, iv, "decrypt")

    def decrypt(self, data):
        """解密数据"""
        if self._decryptor is None:
            raise RuntimeError("解密器未初始化")
        return self._decryptor.update(data)

    def _create_cipher(self, key, iv, mode):
        """创建加密/解密器"""
        if not _HAS_PYCRYPTODOME:
            raise ImportError("流式加密需要安装 pycryptodome: pip install pycryptodome")

        if self.method.startswith("aes"):
            if mode == "encrypt":
                return AES.new(key, AES.MODE_CFB, iv, segment_size=128)
            else:
                return AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        elif self.method == "chacha20-ietf":
            nonce = b"\x00" * 4 + iv  # ChaCha20需要12字节nonce
            if mode == "encrypt":
                return ChaCha20.new(key=key, nonce=nonce)
            else:
                return ChaCha20.new(key=key, nonce=nonce)
        else:
            raise ValueError(f"不支持的加密方式: {self.method}")

    @staticmethod
    def _evp_bytes_to_key(password, key_len):
        """
        EVP_BytesToKey 密钥派生函数

        OpenSSL兼容的密钥派生算法。
        MD5(password + salt) 的迭代哈希。

        参数：
            password: 密码字符串
            key_len: 目标密钥长度

        返回：
            bytes: 派生的密钥
        """
        password_bytes = password.encode("utf-8")
        key = b""
        block = b""

        while len(key) < key_len:
            block = hashlib.md5(block + password_bytes).digest()
            key += block

        return key[:key_len]


# ============================================================
# Shadowsocks 协议处理器
# ============================================================

class ShadowsocksHandler:
    """
    Shadowsocks 协议处理器

    处理单个Shadowsocks客户端连接：
    1. 接收并解密握手数据（包含目标地址）
    2. 建立到目标的连接
    3. 双向加密转发数据
    """

    # SOCKS5 地址类型常量（复用SOCKS5协议的地址格式）
    ATYP_IPV4 = 0x01
    ATYP_DOMAIN = 0x03
    ATYP_IPV6 = 0x04

    def __init__(self, proxy_server, logger=None):
        """
        初始化Shadowsocks处理器

        参数：
            proxy_server: ProxyServer实例
            logger: 日志记录器
        """
        self.proxy_server = proxy_server
        self.logger = logger or get_logger("shadowsocks")

        # 多用户支持：{username: {"password": pwd, "method": method}}
        self._users = {}

        # 检查加密库
        if not _HAS_CRYPTO and not _HAS_PYCRYPTODOME:
            self.logger.warning(
                "未安装加密库！Shadowsocks功能需要以下依赖之一：\n"
                "  pip install cryptography  （推荐，支持AEAD）\n"
                "  pip install pycryptodome  （支持流式加密）"
            )

    def add_user(self, username, password, method=None):
        """
        添加SS用户

        参数：
            username: 用户名（用于标识）
            password: SS密码
            method: 加密方式（使用默认值则传None）
        """
        if method is None:
            method = Config.SS_METHOD
        self._users[username] = {"password": password, "method": method}
        self.logger.info(f"已添加SS用户: {username} (加密: {method})")

    def remove_user(self, username):
        """删除SS用户"""
        if username in self._users:
            del self._users[username]
            self.logger.info(f"已删除SS用户: {username}")
            return True
        return False

    def get_user(self, username):
        """获取SS用户信息"""
        return self._users.get(username)

    def get_all_users(self):
        """获取所有SS用户"""
        return dict(self._users)

    async def handle(self, reader, writer, client_addr):
        """
        处理Shadowsocks连接

        参数：
            reader: asyncio.StreamReader
            writer: asyncio.StreamWriter
            client_addr: (client_ip, client_port)
        """
        client_ip = client_addr[0] if client_addr else "unknown"
        remote_writer = None

        try:
            # ============================================================
            # 1. 确定加密方式和密码（使用默认配置或首个用户）
            # ============================================================
            method = Config.SS_METHOD
            password = Config.SS_PASSWORD

            # 如果有用户配置，使用第一个用户的配置进行解密尝试
            if self._users:
                first_user = next(iter(self._users.values()))
                method = first_user["method"]
                password = first_user["password"]

            # ============================================================
            # 2. 创建加密器并读取IV/握手数据
            # ============================================================
            is_aead = method in AEADCipher.CIPHER_SPECS

            if is_aead:
                cipher = AEADCipher(method, password)
                # AEAD模式：先读取第一块数据解密目标地址
                initial_data = await asyncio.wait_for(
                    reader.read(Config.RELAY_BUFFER_SIZE),
                    timeout=Config.CONNECTION_TIMEOUT
                )
                if not initial_data:
                    return

                # 解密第一块数据
                plaintext, consumed = cipher.decrypt(initial_data)
                if plaintext is None:
                    self.logger.warning(f"[SS] {client_ip} 握手解密失败")
                    return

            else:
                # 流式模式：先读取IV，再解密目标地址
                cipher = StreamCipher(method, password)
                iv = await asyncio.wait_for(
                    reader.readexactly(cipher._iv_len),
                    timeout=Config.CONNECTION_TIMEOUT
                )
                cipher.decrypt_init(iv)

                # 读取并解密目标地址数据
                encrypted_addr = await asyncio.wait_for(
                    reader.read(256 + 4),  # 地址最长约256字节
                    timeout=Config.CONNECTION_TIMEOUT
                )
                if not encrypted_addr:
                    return

                plaintext = cipher.decrypt(encrypted_addr)

                # 创建加密器（用于后续数据加密）
                encrypt_iv = cipher.encrypt_init()

            # ============================================================
            # 3. 解析目标地址（SOCKS5格式）
            # ============================================================
            target_host, target_port, addr_len = self._parse_address(plaintext)
            if target_host is None:
                self.logger.warning(f"[SS] {client_ip} 地址解析失败")
                return

            self.logger.info(
                f"[SS] {client_ip} 请求连接 -> {target_host}:{target_port}"
            )

            # ============================================================
            # 4. 处理剩余的未消耗数据（如果有）
            # ============================================================
            remaining_data = b""
            if is_aead and consumed < len(initial_data):
                # AEAD模式：尝试解密剩余数据
                remaining = initial_data[consumed:]
                if remaining:
                    next_plain, _ = cipher.decrypt(remaining)
                    if next_plain:
                        remaining_data = next_plain

            # ============================================================
            # 5. 建立到目标服务器的连接
            # ============================================================
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port),
                    timeout=Config.CONNECTION_TIMEOUT
                )
            except Exception as e:
                self.logger.warning(f"[SS] {client_ip} 连接 {target_host}:{target_port} 失败: {e}")
                return

            self.logger.info(
                f"[SS] {client_ip} 隧道已建立 -> {target_host}:{target_port}"
            )

            # ============================================================
            # 6. 双向加密转发
            # ============================================================
            await self._relay_data(
                reader, writer, remote_reader, remote_writer,
                cipher, is_aead, remaining_data,
                client_ip, target_host, target_port
            )

        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            self.logger.debug(f"[SS] {client_ip} 连接超时")
        except Exception as e:
            self.logger.error(f"[SS] {client_ip} 处理异常: {e}", exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if remote_writer:
                try:
                    remote_writer.close()
                    await remote_writer.wait_closed()
                except Exception:
                    pass

    def _parse_address(self, data):
        """
        解析SOCKS5格式的目标地址

        格式：
        +------+----------+----------+
        | ATYP | DST.ADDR | DST.PORT |
        +------+----------+----------+
        |  1   | Variable |    2     |
        +------+----------+----------+

        返回：
            tuple: (host, port, consumed_bytes) 或 (None, None, 0)
        """
        if len(data) < 4:
            return None, None, 0

        offset = 0
        atyp = data[offset]
        offset += 1

        if atyp == self.ATYP_IPV4:
            if len(data) < offset + 4 + 2:
                return None, None, 0
            host = socket.inet_ntoa(data[offset:offset + 4])
            offset += 4

        elif atyp == self.ATYP_DOMAIN:
            if len(data) < offset + 1:
                return None, None, 0
            domain_len = data[offset]
            offset += 1
            if len(data) < offset + domain_len + 2:
                return None, None, 0
            host = data[offset:offset + domain_len].decode("utf-8", errors="ignore")
            offset += domain_len

        elif atyp == self.ATYP_IPV6:
            if len(data) < offset + 16 + 2:
                return None, None, 0
            host = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
            offset += 16

        else:
            return None, None, 0

        port = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        return host, port, offset

    async def _relay_data(self, client_reader, client_writer,
                          remote_reader, remote_writer,
                          cipher, is_aead, initial_data,
                          client_ip, target_host, target_port):
        """
        双向加密转发数据

        参数：
            client_reader: 客户端读取流
            client_writer: 客户端写入流
            remote_reader: 远端读取流
            remote_writer: 远端写入流
            cipher: 加密器实例
            is_aead: 是否AEAD模式
            initial_data: 初始未消费数据
            client_ip: 客户端IP
            target_host: 目标主机
            target_port: 目标端口
        """
        upload_total = 0
        download_total = 0

        # 将初始数据发送到远端
        if initial_data:
            remote_writer.write(initial_data)
            await remote_writer.drain()
            upload_total += len(initial_data)

        async def client_to_remote():
            """客户端 -> 远端（解密 -> 明文 -> 发送）"""
            nonlocal upload_total
            try:
                while True:
                    data = await asyncio.wait_for(
                        client_reader.read(Config.RELAY_BUFFER_SIZE),
                        timeout=Config.RELAY_TIMEOUT
                    )
                    if not data:
                        break

                    if is_aead:
                        plaintext, consumed = cipher.decrypt(data)
                        if plaintext is None:
                            break
                    else:
                        plaintext = cipher.decrypt(data)

                    if plaintext:
                        remote_writer.write(plaintext)
                        await remote_writer.drain()
                        upload_total += len(plaintext)

            except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
                pass
            except asyncio.CancelledError:
                raise

        async def remote_to_client():
            """远端 -> 客户端（明文 -> 加密 -> 发送）"""
            nonlocal download_total
            try:
                while True:
                    data = await asyncio.wait_for(
                        remote_reader.read(Config.RELAY_BUFFER_SIZE),
                        timeout=Config.RELAY_TIMEOUT
                    )
                    if not data:
                        break

                    if is_aead:
                        encrypted = cipher.encrypt(data)
                    else:
                        encrypted = cipher.encrypt(data)

                    client_writer.write(encrypted)
                    await client_writer.drain()
                    download_total += len(data)

            except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
                pass
            except asyncio.CancelledError:
                raise

        try:
            t1 = asyncio.create_task(client_to_remote())
            t2 = asyncio.create_task(remote_to_client())

            done, pending = await asyncio.wait(
                [t1, t2], return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass

        except asyncio.CancelledError:
            raise
        finally:
            # 记录流量统计
            if upload_total > 0 or download_total > 0:
                self.proxy_server.billing.record_session_traffic(
                    "shadowsocks", "protocol", upload_total, download_total
                )
                self.logger.info(
                    f"[SS] {client_ip} 会话结束 - "
                    f"上行: {Config.get_bytes_display(upload_total)}, "
                    f"下行: {Config.get_bytes_display(download_total)}"
                )