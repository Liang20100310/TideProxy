#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy 代理服务器模块

核心TCP代理服务器，负责：
- 监听客户端连接
- 协议自动检测（SOCKS5 / HTTP）
- 连接数限制
- 防火墙检查
- 连接生命周期管理

支持的协议：
- SOCKS5（完整实现，含认证）
- HTTP/HTTPS CONNECT 代理（含认证）
"""

import asyncio
import socket

from config import Config
from logger import get_logger
from protocol.socks5 import SOCKS5Handler
from protocol.http_proxy import HTTPProxyHandler

# 尝试导入新增协议模块（可选依赖）
_HAS_SS = False
_HAS_VMESS = False
_HAS_WS = False
_HAS_SUB = False

try:
    from protocol.shadowsocks import ShadowsocksHandler
    _HAS_SS = True
except ImportError:
    pass

try:
    from protocol.vmess import VMessHandler
    _HAS_VMESS = True
except ImportError:
    pass

try:
    from protocol.websocket import WebSocketHandler
    _HAS_WS = True
except ImportError:
    pass

try:
    from protocol.subscription import SubscriptionServer
    _HAS_SUB = True
except ImportError:
    pass


class ProxyServer:
    """
    TideProxy 核心代理服务器

    使用 asyncio 实现高并发TCP连接处理。
    自动检测客户端协议类型（SOCKS5/HTTP）并分发到对应的处理器。
    """

    def __init__(self, account_mgr, activation_mgr, mac_bind, billing, firewall):
        """
        初始化代理服务器

        参数：
            account_mgr: 记名账号管理器
            activation_mgr: 激活码管理器
            mac_bind: MAC绑定管理器
            billing: 计费系统
            firewall: 防火墙
        """
        self.logger = get_logger("server")

        # ============================================================
        # 子系统引用
        # ============================================================
        self.account_mgr = account_mgr
        self.activation_mgr = activation_mgr
        self.mac_bind = mac_bind
        self.billing = billing
        self.firewall = firewall

        # ============================================================
        # 协议处理器（基础）
        # ============================================================
        self.socks5_handler = SOCKS5Handler(self, self.logger)
        self.http_handler = HTTPProxyHandler(self, self.logger)

        # ============================================================
        # 多协议处理器（新增，可选）
        # ============================================================
        self.ss_handler = None
        self.vmess_handler = None
        self.ws_handler = None
        self.sub_server = None

        # Shadowsocks处理器
        if _HAS_SS and Config.SS_ENABLED:
            self.ss_handler = ShadowsocksHandler(self, self.logger)
            self.logger.info("Shadowsocks协议处理器已加载")

        # VMess处理器
        if _HAS_VMESS and Config.VMESS_ENABLED:
            self.vmess_handler = VMessHandler(self, self.logger)
            self.logger.info("VMess协议处理器已加载")

        # WebSocket传输层
        if _HAS_WS and Config.WS_ENABLED:
            self.ws_handler = WebSocketHandler(self, self.logger)
            self.logger.info("WebSocket传输层已加载")

        # 订阅服务
        if _HAS_SUB and Config.SUB_ENABLED:
            self.sub_server = SubscriptionServer(
                self, self.ss_handler, self.vmess_handler
            )
            self.logger.info("订阅服务已加载")

        # ============================================================
        # 服务器状态
        # ============================================================
        self._server = None        # asyncio.Server 实例
        self._running = False      # 服务器运行状态
        self._active_connections = set()  # 活跃连接集合

        # ============================================================
        # 连接计数器
        # ============================================================
        self._total_connections = 0      # 历史总连接数
        self._rejected_connections = 0   # 被拒绝的连接数

    async def start(self):
        """
        启动代理服务器

        开始监听指定地址和端口，接受客户端连接。
        此方法会一直运行直到服务器被停止。
        """
        try:
            self._server = await asyncio.start_server(
                self._handle_connection,
                Config.PROXY_HOST,
                Config.PROXY_PORT,
                # 设置socket选项
                reuse_address=True,
            )

            self._running = True

            self.logger.info(
                f"代理服务器已启动 - "
                f"监听 {Config.PROXY_HOST}:{Config.PROXY_PORT}"
            )

            # 获取实际监听地址（用于显示绑定的端口）
            addrs = ", ".join(
                str(sock.getsockname())
                for sock in self._server.sockets
            )
            self.logger.info(f"监听地址: {addrs}")

            # ============================================================
            # 启动多协议服务器（新增）
            # ============================================================
            extra_tasks = []

            # Shadowsocks 独立服务器
            if self.ss_handler and Config.SS_ENABLED:
                ss_task = asyncio.create_task(
                    self._start_extra_server(
                        Config.SS_HOST, Config.SS_PORT,
                        self.ss_handler.handle, "Shadowsocks"
                    ),
                    name="shadowsocks_server"
                )
                extra_tasks.append(ss_task)

            # VMess 独立服务器
            if self.vmess_handler and Config.VMESS_ENABLED:
                vmess_task = asyncio.create_task(
                    self._start_extra_server(
                        Config.VMESS_HOST, Config.VMESS_PORT,
                        self.vmess_handler.handle, "VMess"
                    ),
                    name="vmess_server"
                )
                extra_tasks.append(vmess_task)

            # WebSocket 传输服务器
            if self.ws_handler and Config.WS_ENABLED:
                ws_task = asyncio.create_task(
                    self._start_extra_server(
                        Config.WS_HOST, Config.WS_PORT,
                        self.ws_handler.handle, "WebSocket"
                    ),
                    name="websocket_server"
                )
                extra_tasks.append(ws_task)

            # 订阅服务
            if self.sub_server and Config.SUB_ENABLED:
                sub_task = asyncio.create_task(
                    self.sub_server.start(),
                    name="subscription_server"
                )
                extra_tasks.append(sub_task)

            # 持续运行主服务器和所有附加服务器
            async with self._server:
                if extra_tasks:
                    await asyncio.gather(
                        self._server.serve_forever(),
                        *extra_tasks,
                        return_exceptions=True
                    )
                else:
                    await self._server.serve_forever()

        except OSError as e:
            self.logger.error(f"代理服务器启动失败: {e}")
            raise
        except asyncio.CancelledError:
            self.logger.info("代理服务器任务已取消")
        except Exception as e:
            self.logger.error(f"代理服务器异常: {e}", exc_info=True)
            raise

    async def stop(self):
        """
        停止代理服务器

        优雅地关闭服务器：
        1. 停止接受新连接
        2. 等待现有连接完成
        3. 释放资源
        """
        self._running = False

        if self._server:
            self.logger.info("正在停止代理服务器...")
            self._server.close()

            try:
                await asyncio.wait_for(
                    self._server.wait_closed(),
                    timeout=10.0
                )
            except asyncio.TimeoutError:
                self.logger.warning("等待服务器关闭超时")

        # 关闭所有活跃连接
        if self._active_connections:
            self.logger.info(f"正在关闭 {len(self._active_connections)} 个活跃连接...")
            for writer in list(self._active_connections):
                try:
                    writer.close()
                except Exception:
                    pass

        self.logger.info(
            f"代理服务器已停止 - "
            f"总连接: {self._total_connections}, "
            f"拒绝: {self._rejected_connections}"
        )

    async def _handle_connection(self, reader, writer):
        """
        处理新的客户端连接

        连接处理流程：
        1. 获取客户端地址信息
        2. 防火墙检查（IP黑白名单）
        3. 连接频率检查
        4. 最大连接数检查
        5. 协议检测和分发

        参数：
            reader: asyncio.StreamReader
            writer: asyncio.StreamWriter
        """
        # 获取客户端地址
        peername = writer.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"
        client_port = peername[1] if peername else 0
        client_addr = (client_ip, client_port)

        self._total_connections += 1

        # ============================================================
        # 防火墙检查
        # ============================================================
        if not self.firewall.check_ip(client_ip):
            self._rejected_connections += 1
            self.logger.warning(f"[连接] {client_ip}:{client_port} 被防火墙拒绝（IP规则）")
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        if not self.firewall.check_rate_limit(client_ip):
            self._rejected_connections += 1
            self.logger.warning(f"[连接] {client_ip}:{client_port} 被防火墙拒绝（频率限制）")
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        # ============================================================
        # 最大连接数检查
        # ============================================================
        if len(self._active_connections) >= Config.MAX_CONNECTIONS:
            self._rejected_connections += 1
            self.logger.warning(
                f"[连接] {client_ip}:{client_port} 被拒绝 - "
                f"已达最大连接数 ({Config.MAX_CONNECTIONS})"
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        # ============================================================
        # 注册活跃连接
        # ============================================================
        self._active_connections.add(writer)

        try:
            # ============================================================
            # 协议检测
            # ============================================================
            protocol = await self._detect_protocol(reader, client_ip)

            if protocol == "socks5":
                await self.socks5_handler.handle(reader, writer, client_addr)
            elif protocol == "http":
                await self.http_handler.handle(reader, writer, client_addr)
            else:
                self.logger.warning(
                    f"[连接] {client_ip}:{client_port} 无法识别协议"
                )

        except asyncio.CancelledError:
            raise
        except (ConnectionResetError, BrokenPipeError):
            self.logger.debug(f"[连接] {client_ip}:{client_port} 连接已重置")
        except Exception as e:
            self.logger.error(
                f"[连接] {client_ip}:{client_port} 处理异常: {e}",
                exc_info=True
            )
        finally:
            # 移除活跃连接记录
            self._active_connections.discard(writer)
            # 确保关闭连接
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _detect_protocol(self, reader, client_ip):
        """
        检测客户端连接的协议类型

        通过读取第一个字节来判断：
        - 0x05 -> SOCKS5
        - 其他 -> HTTP

        参数：
            reader: asyncio.StreamReader
            client_ip: 客户端IP（用于日志）

        返回：
            str: "socks5" 或 "http"
        """
        try:
            # 读取第一个字节（非阻塞，带超时）
            first_byte = await asyncio.wait_for(
                reader.readexactly(1),
                timeout=Config.CONNECTION_TIMEOUT
            )

            if not first_byte:
                return "unknown"

            # SOCKS5 版本号为 0x05
            if first_byte[0] == 0x05:
                self.logger.debug(f"[协议] {client_ip} 检测为 SOCKS5")
                return "socks5"
            else:
                self.logger.debug(f"[协议] {client_ip} 检测为 HTTP")
                return "http"

        except asyncio.TimeoutError:
            self.logger.warning(f"[协议] {client_ip} 协议检测超时")
            return "unknown"
        except Exception as e:
            self.logger.debug(f"[协议] {client_ip} 协议检测失败: {e}")
            return "unknown"

    async def _start_extra_server(self, host, port, handler, name):
        """
        启动附加协议服务器

        参数：
            host: 监听地址
            port: 监听端口
            handler: 连接处理协程
            name: 协议名称（用于日志）
        """
        try:
            server = await asyncio.start_server(
                handler, host, port, reuse_address=True
            )
            self.logger.info(f"{name} 服务器已启动 - 监听 {host}:{port}")

            async with server:
                await server.serve_forever()

        except OSError as e:
            self.logger.error(f"{name} 服务器启动失败: {e}")
        except asyncio.CancelledError:
            self.logger.info(f"{name} 服务器已停止")
        except Exception as e:
            self.logger.error(f"{name} 服务器异常: {e}", exc_info=True)

    def get_status(self):
        """
        获取服务器状态信息

        返回：
            dict: 服务器状态
        """
        status = {
            "running": self._running,
            "listen_addr": f"{Config.PROXY_HOST}:{Config.PROXY_PORT}",
            "active_connections": len(self._active_connections),
            "max_connections": Config.MAX_CONNECTIONS,
            "total_connections": self._total_connections,
            "rejected_connections": self._rejected_connections,
            "billing_enabled": Config.BILLING_ENABLED,
            # 多协议状态（新增）
            "shadowsocks": {
                "enabled": Config.SS_ENABLED,
                "addr": f"{Config.SS_HOST}:{Config.SS_PORT}" if Config.SS_ENABLED else "未启用",
                "method": Config.SS_METHOD,
                "users": len(self.ss_handler.get_all_users()) if self.ss_handler else 0,
            },
            "vmess": {
                "enabled": Config.VMESS_ENABLED,
                "addr": f"{Config.VMESS_HOST}:{Config.VMESS_PORT}" if Config.VMESS_ENABLED else "未启用",
                "users": len(self.vmess_handler.get_all_users()) if self.vmess_handler else 0,
            },
            "websocket": {
                "enabled": Config.WS_ENABLED,
                "addr": f"{Config.WS_HOST}:{Config.WS_PORT}" if Config.WS_ENABLED else "未启用",
                "path": Config.WS_PATH,
            },
            "subscription": {
                "enabled": Config.SUB_ENABLED,
                "addr": f"{Config.SUB_HOST}:{Config.SUB_PORT}" if Config.SUB_ENABLED else "未启用",
            },
        }
        return status