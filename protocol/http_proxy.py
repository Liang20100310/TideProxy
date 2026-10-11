#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy HTTP/HTTPS代理协议处理模块

实现HTTP代理协议，支持：
- HTTP CONNECT 方法（HTTPS隧道代理）
- 普通HTTP请求代理（GET/POST等）
- Proxy-Authorization 头部认证
- 流量统计和带宽控制

协议说明：
- CONNECT方法：客户端发送 CONNECT host:port 请求，服务端建立TCP隧道
- 普通HTTP请求：客户端发送完整HTTP请求，服务端转发到目标服务器
"""

import asyncio
import base64
import re

from config import Config
from logger import get_logger


class HTTPProxyHandler:
    """
    HTTP代理协议处理器

    处理单个HTTP代理客户端连接的完整生命周期：
    1. 读取HTTP请求行
    2. 解析请求头部
    3. 用户认证（如果需要）
    4. 建立到目标的连接
    5. 转发数据
    """

    def __init__(self, proxy_server, logger=None):
        """
        初始化HTTP代理处理器

        参数：
            proxy_server: ProxyServer 实例
            logger: 可选的日志记录器
        """
        self.proxy_server = proxy_server
        self.logger = logger or get_logger("http_proxy")

    async def handle(self, reader, writer, client_addr):
        """
        处理HTTP代理连接的完整生命周期

        参数：
            reader: asyncio.StreamReader
            writer: asyncio.StreamWriter
            client_addr: 客户端地址元组 (ip, port)
        """
        client_ip = client_addr[0] if client_addr else "unknown"
        remote_writer = None
        identifier = None
        account_type = None

        try:
            # ============================================================
            # 读取第一行数据（请求行或CONNECT方法）
            # ============================================================
            first_line = await asyncio.wait_for(
                reader.readline(),
                timeout=Config.CONNECTION_TIMEOUT
            )

            if not first_line:
                return

            first_line_str = first_line.decode("utf-8", errors="ignore").strip()
            self.logger.debug(f"[HTTP] {client_ip} 请求: {first_line_str}")

            # ============================================================
            # 解析请求头部（读取到空行为止）
            # ============================================================
            headers = {}
            buffer = first_line

            while True:
                line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=Config.CONNECTION_TIMEOUT
                )
                if not line or line == b"\r\n" or line == b"\n":
                    break

                # 解析头部字段
                try:
                    line_str = line.decode("utf-8", errors="ignore").strip()
                    if ":" in line_str:
                        key, value = line_str.split(":", 1)
                        headers[key.strip().lower()] = value.strip()
                except Exception:
                    pass

            # ============================================================
            # 处理CONNECT方法（HTTPS隧道代理）
            # ============================================================
            if first_line_str.upper().startswith("CONNECT "):
                await self._handle_connect(
                    first_line_str, headers, reader, writer, client_ip
                )
                return

            # ============================================================
            # 处理普通HTTP请求代理
            # ============================================================
            await self._handle_http_request(
                first_line_str, headers, reader, writer, client_ip
            )

        except asyncio.TimeoutError:
            self.logger.warning(f"[HTTP] {client_ip} 请求读取超时")
        except (ConnectionResetError, BrokenPipeError):
            self.logger.debug(f"[HTTP] {client_ip} 连接已重置")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.error(f"[HTTP] {client_ip} 处理异常: {e}", exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(self, request_line, headers, reader, writer, client_ip):
        """
        处理CONNECT方法请求（HTTPS隧道代理）

        CONNECT请求格式：
        CONNECT host:port HTTP/1.1
        Host: host:port
        [Proxy-Authorization: Basic xxx]

        成功响应：
        HTTP/1.1 200 Connection Established

        参数：
            request_line: 请求行字符串
            headers: 请求头字典
            reader: 客户端读取流
            writer: 客户端写入流
            client_ip: 客户端IP
        """
        identifier = None
        account_type = None
        remote_writer = None

        try:
            # ============================================================
            # 解析目标地址
            # ============================================================
            parts = request_line.split()
            if len(parts) < 2:
                self._send_error_response(writer, 400, "Bad Request")
                return

            target = parts[1]
            if ":" in target:
                host, port_str = target.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    self._send_error_response(writer, 400, "Bad Request")
                    return
            else:
                host = target
                port = 443  # HTTPS默认端口

            # ============================================================
            # 用户认证（检查Proxy-Authorization头部）
            # ============================================================
            if Config.BILLING_ENABLED:
                auth_header = headers.get("proxy-authorization", "")
                if auth_header:
                    auth_result = self._authenticate(auth_header, client_ip)
                    if auth_result is None:
                        self._send_auth_required(writer)
                        return
                    identifier, account_type = auth_result
                else:
                    # 需要认证但没有提供
                    self._send_auth_required(writer)
                    return

            # ============================================================
            # 建立到目标服务器的连接
            # ============================================================
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=Config.CONNECTION_TIMEOUT
                )
            except asyncio.TimeoutError:
                self.logger.warning(f"[HTTP] {client_ip} 连接 {host}:{port} 超时")
                self._send_error_response(writer, 504, "Gateway Timeout")
                return
            except (OSError, Exception) as e:
                self.logger.warning(f"[HTTP] {client_ip} 无法连接 {host}:{port}: {e}")
                self._send_error_response(writer, 502, "Bad Gateway")
                return

            # ============================================================
            # 发送成功响应
            # ============================================================
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            self.logger.info(
                f"[HTTP-CONNECT] {client_ip} 已建立隧道 -> {host}:{port}"
            )

            # ============================================================
            # 双向数据转发
            # ============================================================
            await self._relay_data(
                reader, writer, remote_reader, remote_writer,
                client_ip, host, port, identifier, account_type
            )

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.error(f"[HTTP-CONNECT] {client_ip} 异常: {e}")
        finally:
            if remote_writer:
                try:
                    remote_writer.close()
                    await remote_writer.wait_closed()
                except Exception:
                    pass

    async def _handle_http_request(self, request_line, headers,
                                   reader, writer, client_ip):
        """
        处理普通HTTP请求代理

        将客户端的HTTP请求转发到目标服务器，并将响应返回给客户端。

        参数：
            request_line: 请求行字符串（如 "GET http://example.com/ HTTP/1.1"）
            headers: 请求头字典
            reader: 客户端读取流
            writer: 客户端写入流
            client_ip: 客户端IP
        """
        identifier = None
        account_type = None
        remote_writer = None

        try:
            # ============================================================
            # 解析请求行
            # ============================================================
            parts = request_line.split()
            if len(parts) < 3:
                self._send_error_response(writer, 400, "Bad Request")
                return

            method = parts[0]
            url = parts[1]
            http_version = parts[2]

            # ============================================================
            # 从URL中提取目标主机和端口
            # ============================================================
            host = None
            port = 80

            # 移除URL中的协议前缀
            if url.startswith("http://"):
                url = url[7:]
            elif url.startswith("https://"):
                url = url[8:]
                port = 443

            # 提取主机和端口
            if "/" in url:
                host_port = url.split("/", 1)[0]
            else:
                host_port = url

            if ":" in host_port:
                host, port_str = host_port.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    self._send_error_response(writer, 400, "Bad Request")
                    return
            else:
                host = host_port

            if not host:
                self._send_error_response(writer, 400, "Bad Request")
                return

            # ============================================================
            # 用户认证
            # ============================================================
            if Config.BILLING_ENABLED:
                auth_header = headers.get("proxy-authorization", "")
                if auth_header:
                    auth_result = self._authenticate(auth_header, client_ip)
                    if auth_result is None:
                        self._send_auth_required(writer)
                        return
                    identifier, account_type = auth_result
                else:
                    self._send_auth_required(writer)
                    return

            # ============================================================
            # 建立到目标服务器的连接
            # ============================================================
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=Config.CONNECTION_TIMEOUT
                )
            except asyncio.TimeoutError:
                self._send_error_response(writer, 504, "Gateway Timeout")
                return
            except (OSError, Exception) as e:
                self.logger.warning(f"[HTTP] {client_ip} 无法连接 {host}:{port}: {e}")
                self._send_error_response(writer, 502, "Bad Gateway")
                return

            # ============================================================
            # 重构并转发请求到目标服务器
            # ============================================================
            # 构建新的请求行（移除代理相关的URL格式）
            path = "/" + url.split("/", 1)[1] if "/" in url else "/"
            new_request_line = f"{method} {path} {http_version}\r\n"

            # 转发请求行
            remote_writer.write(new_request_line.encode("utf-8"))

            # 转发头部（排除代理相关的头部）
            for key, value in headers.items():
                if key.lower() not in ("proxy-connection", "proxy-authorization"):
                    header_line = f"{key}: {value}\r\n"
                    remote_writer.write(header_line.encode("utf-8"))

            # 结束头部
            remote_writer.write(b"\r\n")
            await remote_writer.drain()

            self.logger.info(
                f"[HTTP] {client_ip} {method} -> {host}:{port}{path}"
            )

            # ============================================================
            # 双向数据转发
            # ============================================================
            await self._relay_data(
                reader, writer, remote_reader, remote_writer,
                client_ip, host, port, identifier, account_type
            )

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.error(f"[HTTP] {client_ip} 请求处理异常: {e}")
        finally:
            if remote_writer:
                try:
                    remote_writer.close()
                    await remote_writer.wait_closed()
                except Exception:
                    pass

    def _authenticate(self, auth_header, client_ip):
        """
        处理Proxy-Authorization认证

        支持Basic认证格式：
        Proxy-Authorization: Basic base64(username:password)

        参数：
            auth_header: Authorization头部值
            client_ip: 客户端IP

        返回：
            tuple (identifier, account_type) 或 None（认证失败）
        """
        try:
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != "basic":
                self.logger.warning(f"[HTTP] {client_ip} 不支持的认证格式")
                return None

            # 解码Base64编码的凭证
            decoded = base64.b64decode(parts[1]).decode("utf-8")
            if ":" not in decoded:
                return None

            username, password = decoded.split(":", 1)

            # 尝试激活码认证（激活码放在username字段，password留空）
            activation_result = self.proxy_server.activation_mgr.authenticate(
                username, client_ip
            )
            if activation_result[0]:
                self.logger.info(f"[HTTP] {client_ip} 激活码认证成功: {username[:8]}***")
                return (username, "activation")

            # 尝试记名账号认证
            account_result = self.proxy_server.account_mgr.authenticate(
                username, password, client_ip
            )
            if account_result[0]:
                self.logger.info(f"[HTTP] {client_ip} 账号认证成功: {username}")
                return (username, "account")

            # 认证失败
            self.logger.warning(
                f"[HTTP] {client_ip} 认证失败: {username} "
                f"- 激活码: {activation_result[1]}, 账号: {account_result[1]}"
            )
            return None

        except Exception as e:
            self.logger.error(f"[HTTP] {client_ip} 认证解析异常: {e}")
            return None

    def _send_error_response(self, writer, status_code, reason):
        """
        发送HTTP错误响应

        参数：
            writer: 客户端写入流
            status_code: HTTP状态码
            reason: 状态原因短语
        """
        try:
            response = (
                f"HTTP/1.1 {status_code} {reason}\r\n"
                f"Content-Length: 0\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            writer.write(response.encode("utf-8"))
        except Exception:
            pass

    def _send_auth_required(self, writer):
        """
        发送407 Proxy Authentication Required响应

        参数：
            writer: 客户端写入流
        """
        try:
            response = (
                "HTTP/1.1 407 Proxy Authentication Required\r\n"
                "Proxy-Authenticate: Basic realm=\"TideProxy\"\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            writer.write(response.encode("utf-8"))
        except Exception:
            pass

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

                    # 实时记录流量
                    if identifier and account_type and Config.BILLING_ENABLED:
                        self.proxy_server.billing.record_traffic(
                            identifier, account_type,
                            data_len if direction == "upload" else 0,
                            data_len if direction == "download" else 0
                        )

            except asyncio.TimeoutError:
                pass
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            except asyncio.CancelledError:
                raise

        try:
            task_upload = asyncio.create_task(
                forward(client_reader, remote_writer, "upload")
            )
            task_download = asyncio.create_task(
                forward(remote_reader, client_writer, "download")
            )

            done, pending = await asyncio.wait(
                [task_upload, task_download],
                return_when=asyncio.FIRST_COMPLETED
            )

            for task in pending:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.debug(f"[HTTP] {client_ip} 转发异常: {e}")
        finally:
            if identifier and account_type and (upload_total > 0 or download_total > 0):
                self.proxy_server.billing.record_session_traffic(
                    identifier, account_type, upload_total, download_total
                )
                self.logger.info(
                    f"[HTTP] {client_ip} 会话结束 - "
                    f"上行: {Config.get_bytes_display(upload_total)}, "
                    f"下行: {Config.get_bytes_display(download_total)}"
                )