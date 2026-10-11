#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy SOCKS5 协议处理模块

完整实现 SOCKS5 代理协议（RFC 1928），支持：
- 无认证模式
- 用户名/密码认证（RFC 1929）
- CONNECT 命令（TCP连接代理）
- IPv4 / 域名 / IPv6 地址类型

协议流程：
1. 客户端发送认证方法协商请求
2. 服务端选择认证方法
3. 如果选择用户名/密码认证，进行认证交互
4. 客户端发送连接请求（CONNECT命令）
5. 服务端建立到目标的连接并返回结果
6. 双向转发数据

实现参考：
- RFC 1928: SOCKS Protocol Version 5
- RFC 1929: Username/Password Authentication for SOCKS V5
"""

import asyncio
import struct
import socket

from config import Config
from logger import get_logger


class SOCKS5Handler:
    """
    SOCKS5 协议处理器

    处理单个SOCKS5客户端连接的完整生命周期：
    1. 认证协商
    2. 用户认证（可选）
    3. 代理请求处理
    4. 数据转发
    """

    # ============================================================
    # SOCKS5 协议常量定义
    # ============================================================

    # SOCKS 协议版本号
    SOCKS_VERSION = 0x05

    # 认证方法
    AUTH_NONE = 0x00          # 无需认证
    AUTH_USERNAME = 0x02      # 用户名/密码认证
    AUTH_NO_ACCEPTABLE = 0xFF # 无可接受的认证方法

    # 请求命令
    CMD_CONNECT = 0x01       # CONNECT（TCP连接）
    CMD_BIND = 0x02          # BIND（绑定）
    CMD_UDP = 0x03           # UDP ASSOCIATE（UDP转发）

    # 地址类型
    ATYP_IPV4 = 0x01         # IPv4 地址（4字节）
    ATYP_DOMAIN = 0x03       # 域名（1字节长度 + 域名字符串）
    ATYP_IPV6 = 0x04         # IPv6 地址（16字节）

    # 响应状态码
    REP_SUCCESS = 0x00           # 成功
    REP_GENERAL_FAILURE = 0x01   # 一般性失败
    REP_NOT_ALLOWED = 0x02       # 规则不允许
    REP_NET_UNREACHABLE = 0x03   # 网络不可达
    REP_HOST_UNREACHABLE = 0x04  # 主机不可达
    REP_REFUSED = 0x05           # 连接被拒绝
    REP_CMD_NOT_SUPPORTED = 0x07 # 命令不支持
    REP_ATYP_NOT_SUPPORTED = 0x08 # 地址类型不支持

    def __init__(self, proxy_server, logger=None):
        """
        初始化SOCKS5处理器

        参数：
            proxy_server: ProxyServer 实例，提供对各子系统的访问
            logger: 可选的日志记录器
        """
        self.proxy_server = proxy_server
        self.logger = logger or get_logger("socks5")

    async def handle(self, reader, writer, client_addr):
        """
        处理SOCKS5连接的完整生命周期

        参数：
            reader: asyncio.StreamReader，客户端读取流
            writer: asyncio.StreamWriter，客户端写入流
            client_addr: 客户端地址元组 (ip, port)
        """
        client_ip = client_addr[0] if client_addr else "unknown"
        remote_writer = None
        account_type = None
        identifier = None

        try:
            # ============================================================
            # 第一阶段：认证方法协商
            # 客户端发送支持的认证方法列表，服务端选择一种
            # ============================================================
            auth_method = await self._handle_auth_negotiation(reader, writer, client_ip)
            if auth_method is None:
                return

            # ============================================================
            # 第二阶段：用户认证（如果需要）
            # ============================================================
            if auth_method == self.AUTH_USERNAME:
                auth_result = await self._handle_username_auth(
                    reader, writer, client_ip
                )
                if auth_result is None:
                    return
                identifier, account_type = auth_result

            # ============================================================
            # 第三阶段：处理代理请求
            # ============================================================
            target_host, target_port = await self._handle_request(
                reader, writer, client_ip
            )
            if target_host is None:
                return

            # ============================================================
            # 第四阶段：建立到目标服务器的连接
            # ============================================================
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port),
                    timeout=Config.CONNECTION_TIMEOUT
                )
            except asyncio.TimeoutError:
                self.logger.warning(f"[SOCKS5] {client_ip} 连接 {target_host}:{target_port} 超时")
                self._send_error_response(writer, self.REP_HOST_UNREACHABLE)
                return
            except (OSError, socket.gaierror) as e:
                self.logger.warning(f"[SOCKS5] {client_ip} 无法连接 {target_host}:{target_port}: {e}")
                self._send_error_response(writer, self.REP_HOST_UNREACHABLE)
                return

            remote_writer_ref = remote_writer

            # 发送成功响应
            self._send_success_response(writer, remote_writer)
            self.logger.info(
                f"[SOCKS5] {client_ip} 已建立隧道 -> {target_host}:{target_port}"
            )

            # ============================================================
            # 第五阶段：双向数据转发
            # ============================================================
            await self._relay_data(
                reader, writer, remote_reader, remote_writer,
                client_ip, target_host, target_port,
                identifier, account_type
            )

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.error(f"[SOCKS5] {client_ip} 处理异常: {e}", exc_info=True)
        finally:
            # 确保关闭所有连接
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

    async def _handle_auth_negotiation(self, reader, writer, client_ip):
        """
        处理认证方法协商

        协议格式（客户端 -> 服务端）：
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+

        响应格式（服务端 -> 客户端）：
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+

        返回：
            int 或 None: 选择的认证方法，None 表示协商失败
        """
        try:
            # 读取版本号和方法数量
            header = await asyncio.wait_for(
                reader.readexactly(2),
                timeout=Config.CONNECTION_TIMEOUT
            )

            version = header[0]
            n_methods = header[1]

            # 验证版本号
            if version != self.SOCKS_VERSION:
                self.logger.warning(f"[SOCKS5] {client_ip} 版本不匹配: {version}")
                return None

            # 读取客户端支持的认证方法列表
            methods_data = await asyncio.wait_for(
                reader.readexactly(n_methods),
                timeout=Config.CONNECTION_TIMEOUT
            )
            methods = set(methods_data)

            # ============================================================
            # 选择认证方法
            # 优先使用用户名/密码认证（如果有用户数据）
            # 否则使用无认证模式
            # ============================================================
            if Config.BILLING_ENABLED and self.AUTH_USERNAME in methods:
                # 启用计费系统时，要求用户名/密码认证
                selected_method = self.AUTH_USERNAME
            elif self.AUTH_NONE in methods:
                selected_method = self.AUTH_NONE
            else:
                # 没有可接受的认证方法
                writer.write(bytes([self.SOCKS_VERSION, self.AUTH_NO_ACCEPTABLE]))
                await writer.drain()
                self.logger.warning(f"[SOCKS5] {client_ip} 无可接受的认证方法")
                return None

            # 发送认证方法选择响应
            writer.write(bytes([self.SOCKS_VERSION, selected_method]))
            await writer.drain()

            return selected_method

        except asyncio.TimeoutError:
            self.logger.warning(f"[SOCKS5] {client_ip} 认证协商超时")
            return None
        except Exception as e:
            self.logger.error(f"[SOCKS5] {client_ip} 认证协商异常: {e}")
            return None

    async def _handle_username_auth(self, reader, writer, client_ip):
        """
        处理用户名/密码认证

        请求格式（RFC 1929）：
        +----+------+----------+------+----------+
        |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        +----+------+----------+------+----------+
        | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        +----+------+----------+------+----------+

        响应格式：
        +----+--------+
        |VER | STATUS |
        +----+--------+
        | 1  |   1    |
        +----+--------+

        返回：
            tuple (identifier, account_type) 或 None（认证失败）
        """
        try:
            # 读取认证版本号
            auth_version = await asyncio.wait_for(
                reader.readexactly(1),
                timeout=Config.CONNECTION_TIMEOUT
            )

            if auth_version[0] != 0x01:
                self.logger.warning(f"[SOCKS5] {client_ip} 认证版本不匹配")
                writer.write(bytes([0x01, 0x01]))  # 认证失败
                await writer.drain()
                return None

            # 读取用户名
            ulen = (await asyncio.wait_for(
                reader.readexactly(1),
                timeout=Config.CONNECTION_TIMEOUT
            ))[0]
            username = (await asyncio.wait_for(
                reader.readexactly(ulen),
                timeout=Config.CONNECTION_TIMEOUT
            )).decode("utf-8")

            # 读取密码
            plen = (await asyncio.wait_for(
                reader.readexactly(1),
                timeout=Config.CONNECTION_TIMEOUT
            ))[0]
            password = (await asyncio.wait_for(
                reader.readexactly(plen),
                timeout=Config.CONNECTION_TIMEOUT
            )).decode("utf-8")

            # ============================================================
            # 验证用户凭证
            # ============================================================

            # 尝试激活码认证
            activation_result = self.proxy_server.activation_mgr.authenticate(
                username, client_ip
            )
            if activation_result[0]:
                # 激活码认证成功（激活码放在username字段，password留空）
                writer.write(bytes([0x01, 0x00]))  # 认证成功
                await writer.drain()
                self.logger.info(f"[SOCKS5] {client_ip} 激活码认证成功: {username[:8]}***")
                return (username, "activation")

            # 尝试记名账号认证
            account_result = self.proxy_server.account_mgr.authenticate(
                username, password, client_ip
            )
            if account_result[0]:
                writer.write(bytes([0x01, 0x00]))  # 认证成功
                await writer.drain()
                self.logger.info(f"[SOCKS5] {client_ip} 账号认证成功: {username}")
                return (username, "account")

            # 认证失败
            writer.write(bytes([0x01, 0x01]))  # 认证失败
            await writer.drain()
            self.logger.warning(
                f"[SOCKS5] {client_ip} 认证失败: {username} "
                f"- 激活码: {activation_result[1]}, 账号: {account_result[1]}"
            )
            return None

        except asyncio.TimeoutError:
            self.logger.warning(f"[SOCKS5] {client_ip} 用户认证超时")
            return None
        except Exception as e:
            self.logger.error(f"[SOCKS5] {client_ip} 用户认证异常: {e}")
            return None

    async def _handle_request(self, reader, writer, client_ip):
        """
        处理SOCKS5代理请求

        请求格式：
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

        返回：
            tuple (target_host, target_port) 或 (None, None)
        """
        try:
            # 读取请求头部（版本、命令、保留字节、地址类型）
            req_header = await asyncio.wait_for(
                reader.readexactly(4),
                timeout=Config.CONNECTION_TIMEOUT
            )

            version = req_header[0]
            command = req_header[1]
            address_type = req_header[3]

            # 验证版本号
            if version != self.SOCKS_VERSION:
                self.logger.warning(f"[SOCKS5] {client_ip} 请求版本不匹配")
                return None, None

            # 目前仅支持 CONNECT 命令
            if command != self.CMD_CONNECT:
                self.logger.warning(f"[SOCKS5] {client_ip} 不支持的命令: {command}")
                self._send_error_response(writer, self.REP_CMD_NOT_SUPPORTED)
                return None, None

            # ============================================================
            # 解析目标地址
            # ============================================================
            if address_type == self.ATYP_IPV4:
                # IPv4 地址：4字节
                addr_data = await asyncio.wait_for(
                    reader.readexactly(4),
                    timeout=Config.CONNECTION_TIMEOUT
                )
                target_host = socket.inet_ntoa(addr_data)

            elif address_type == self.ATYP_DOMAIN:
                # 域名：1字节长度 + 域名字符串
                domain_len = (await asyncio.wait_for(
                    reader.readexactly(1),
                    timeout=Config.CONNECTION_TIMEOUT
                ))[0]
                target_host = (await asyncio.wait_for(
                    reader.readexactly(domain_len),
                    timeout=Config.CONNECTION_TIMEOUT
                )).decode("utf-8")

            elif address_type == self.ATYP_IPV6:
                # IPv6 地址：16字节
                addr_data = await asyncio.wait_for(
                    reader.readexactly(16),
                    timeout=Config.CONNECTION_TIMEOUT
                )
                target_host = socket.inet_ntop(socket.AF_INET6, addr_data)

            else:
                self.logger.warning(f"[SOCKS5] {client_ip} 不支持的地址类型: {address_type}")
                self._send_error_response(writer, self.REP_ATYP_NOT_SUPPORTED)
                return None, None

            # 读取目标端口（2字节，网络字节序）
            port_data = await asyncio.wait_for(
                reader.readexactly(2),
                timeout=Config.CONNECTION_TIMEOUT
            )
            target_port = struct.unpack("!H", port_data)[0]

            self.logger.info(
                f"[SOCKS5] {client_ip} 请求连接 -> {target_host}:{target_port}"
            )

            return target_host, target_port

        except asyncio.TimeoutError:
            self.logger.warning(f"[SOCKS5] {client_ip} 读取请求超时")
            return None, None
        except Exception as e:
            self.logger.error(f"[SOCKS5] {client_ip} 解析请求异常: {e}")
            return None, None

    def _send_error_response(self, writer, rep_code):
        """
        发送SOCKS5错误响应

        参数：
            writer: 客户端写入流
            rep_code: 响应状态码
        """
        try:
            response = bytes([
                self.SOCKS_VERSION,
                rep_code,
                0x00,  # 保留字节
                self.ATYP_IPV4,  # 地址类型
                0x00, 0x00, 0x00, 0x00,  # 绑定地址（0.0.0.0）
                0x00, 0x00  # 绑定端口（0）
            ])
            writer.write(response)
        except Exception:
            pass

    def _send_success_response(self, writer, remote_writer):
        """
        发送SOCKS5成功响应

        响应格式：
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

        参数：
            writer: 客户端写入流
            remote_writer: 远端连接的写入流（用于获取绑定地址）
        """
        try:
            # 获取绑定的地址信息
            sock = remote_writer.get_extra_info("socket")
            if sock:
                bind_addr = sock.getsockname()
                if len(bind_addr) == 2:
                    addr_bytes = socket.inet_aton(bind_addr[0])
                    atyp = self.ATYP_IPV4
                else:
                    addr_bytes = socket.inet_pton(socket.AF_INET6, bind_addr[0])
                    atyp = self.ATYP_IPV6
                port_bytes = struct.pack("!H", bind_addr[1])
            else:
                addr_bytes = bytes(4)
                atyp = self.ATYP_IPV4
                port_bytes = bytes(2)

            response = bytes([
                self.SOCKS_VERSION,
                self.REP_SUCCESS,
                0x00,
                atyp
            ]) + addr_bytes + port_bytes

            writer.write(response)
        except Exception:
            # 使用默认响应
            response = bytes([
                self.SOCKS_VERSION,
                self.REP_SUCCESS,
                0x00,
                self.ATYP_IPV4,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ])
            writer.write(response)

    async def _relay_data(self, client_reader, client_writer,
                          remote_reader, remote_writer,
                          client_ip, target_host, target_port,
                          identifier, account_type):
        """
        双向数据转发

        在客户端和远端服务器之间双向转发数据，同时：
        - 统计上行和下行流量
        - 检查带宽限制
        - 检查流量额度

        参数：
            client_reader: 客户端读取流
            client_writer: 客户端写入流
            remote_reader: 远端读取流
            remote_writer: 远端写入流
            client_ip: 客户端IP
            target_host: 目标主机
            target_port: 目标端口
            identifier: 用户标识（可选）
            account_type: 账户类型（可选）
        """
        upload_total = 0
        download_total = 0

        async def forward(src_reader, dst_writer, direction):
            """单向数据转发"""
            nonlocal upload_total, download_total

            try:
                while True:
                    data = await asyncio.wait_for(
                        src_reader.read(Config.RELAY_BUFFER_SIZE),
                        timeout=Config.RELAY_TIMEOUT
                    )
                    if not data:
                        break

                    dst_writer.write(data)
                    await dst_writer.drain()

                    # 统计流量
                    data_len = len(data)
                    if direction == "upload":
                        upload_total += data_len
                    else:
                        download_total += data_len

                    # 实时记录流量（用于计费系统）
                    if identifier and account_type and Config.BILLING_ENABLED:
                        self.proxy_server.billing.record_traffic(
                            identifier, account_type,
                            data_len if direction == "upload" else 0,
                            data_len if direction == "download" else 0
                        )

            except asyncio.TimeoutError:
                pass  # 空闲超时，正常断开
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass  # 连接已断开
            except asyncio.CancelledError:
                raise

        try:
            # 启动双向转发
            task_upload = asyncio.create_task(
                forward(client_reader, remote_writer, "upload")
            )
            task_download = asyncio.create_task(
                forward(remote_reader, client_writer, "download")
            )

            # 等待任一方向断开
            done, pending = await asyncio.wait(
                [task_upload, task_download],
                return_when=asyncio.FIRST_COMPLETED
            )

            # 取消剩余任务
            for task in pending:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.debug(f"[SOCKS5] {client_ip} 转发异常: {e}")
        finally:
            # 记录本次会话的流量统计
            if identifier and account_type and (upload_total > 0 or download_total > 0):
                self.proxy_server.billing.record_session_traffic(
                    identifier, account_type, upload_total, download_total
                )
                self.logger.info(
                    f"[SOCKS5] {client_ip} 会话结束 - "
                    f"上行: {Config.get_bytes_display(upload_total)}, "
                    f"下行: {Config.get_bytes_display(download_total)}"
                )