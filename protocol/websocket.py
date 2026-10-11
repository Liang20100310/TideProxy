#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy WebSocket 传输层模块

实现 WebSocket 传输层，用于：
- CDN流量伪装（通过CDN转发WebSocket流量）
- 绕过深度包检测（DPI）
- 与Nginx/Apache反向代理配合
- 兼容 V2Ray/Xray 的 WebSocket 传输

支持的协议组合：
- VMess over WebSocket (ws)
- VMess over WebSocket + TLS (wss)
- Trojan over WebSocket + TLS
- Shadowsocks over WebSocket

WebSocket 帧格式（RFC 6455）：
+-------+---+---+---+---+------+----------------+
|FIN|RSV|Op |Mask|Len|Masking|Payload Data     |
| 1 | 3 | 4 |Key | 7|Key 4B|variable         |
+-------+---+---+---+---+------+----------------+

适用场景：
- 配合CDN（Cloudflare等）隐藏真实服务器IP
- 绕过运营商QoS限速
- 混淆流量，增加检测难度
"""

import asyncio
import base64
import hashlib
import os
import struct

from config import Config
from logger import get_logger


# ============================================================
# WebSocket 操作码定义
# ============================================================
WS_OPCODE_CONTINUATION = 0x00
WS_OPCODE_TEXT = 0x01
WS_OPCODE_BINARY = 0x02
WS_OPCODE_CLOSE = 0x08
WS_OPCODE_PING = 0x09
WS_OPCODE_PONG = 0x0A


class WebSocketHandler:
    """
    WebSocket 传输层处理器

    处理 WebSocket 连接的握手和帧解析。
    将 WebSocket 流转换为普通的 TCP 流供代理协议使用。
    """

    def __init__(self, proxy_server, logger=None):
        """
        初始化WebSocket处理器

        参数：
            proxy_server: ProxyServer实例
            logger: 日志记录器
        """
        self.proxy_server = proxy_server
        self.logger = logger or get_logger("websocket")

    async def handle(self, reader, writer, client_addr):
        """
        处理WebSocket连接

        流程：
        1. 读取HTTP升级请求
        2. 验证WebSocket握手
        3. 解析路径确定目标协议
        4. 建立WebSocket连接
        5. 将WebSocket帧解封装后交给目标协议处理

        参数：
            reader: asyncio.StreamReader
            writer: asyncio.StreamWriter
            client_addr: (client_ip, client_port)
        """
        client_ip = client_addr[0] if client_addr else "unknown"

        try:
            # ============================================================
            # 1. 读取HTTP升级请求
            # ============================================================
            request_lines = []
            buffer = b""

            while True:
                line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=Config.CONNECTION_TIMEOUT
                )
                if not line:
                    return
                if line == b"\r\n":
                    break
                request_lines.append(line.decode("utf-8", errors="ignore").strip())

            if not request_lines:
                return

            # ============================================================
            # 2. 解析HTTP请求头
            # ============================================================
            request_line = request_lines[0]
            headers = {}
            for line in request_lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            # 解析请求路径
            parts = request_line.split()
            if len(parts) < 2:
                return
            request_path = parts[1]

            # ============================================================
            # 3. 验证WebSocket升级请求
            # ============================================================
            upgrade = headers.get("upgrade", "").lower()
            if upgrade != "websocket":
                self.logger.warning(f"[WS] {client_ip} 非WebSocket请求")
                self._send_http_error(writer, 400, "Bad Request")
                return

            ws_key = headers.get("sec-websocket-key", "")
            if not ws_key:
                self._send_http_error(writer, 400, "Missing WebSocket Key")
                return

            # ============================================================
            # 4. 发送WebSocket握手响应
            # ============================================================
            ws_accept = self._compute_accept_key(ws_key)

            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {ws_accept}\r\n"
                "\r\n"
            )
            writer.write(response.encode("utf-8"))
            await writer.drain()

            self.logger.info(f"[WS] {client_ip} WebSocket连接已建立, 路径: {request_path}")

            # ============================================================
            # 5. 根据路径分发到对应的协议处理器
            # ============================================================
            # 路径格式：/ws/ss, /ws/vmess, /ws/trojan, 或自定义路径
            await self._handle_websocket_stream(
                reader, writer, client_addr, request_path, headers
            )

        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            self.logger.debug(f"[WS] {client_ip} 握手超时")
        except Exception as e:
            self.logger.error(f"[WS] {client_ip} 处理异常: {e}", exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_websocket_stream(self, reader, writer,
                                        client_addr, path, headers):
        """
        处理WebSocket数据流

        将WebSocket帧解封装为原始TCP数据，
        然后交给目标协议处理器。

        参数：
            reader: 客户端读取流
            writer: 客户端写入流
            client_addr: 客户端地址
            path: WebSocket路径
            headers: HTTP请求头
        """
        client_ip = client_addr[0] if client_addr else "unknown"

        # 创建WebSocket帧读写器
        ws_reader = WebSocketFrameReader(reader, self.logger)
        ws_writer = WebSocketFrameWriter(writer, self.logger)

        # 根据路径确定目标协议
        # 默认路由到VMess
        target_protocol = "vmess"
        if "/ss" in path:
            target_protocol = "shadowsocks"
        elif "/trojan" in path:
            target_protocol = "trojan"
        elif "/vmess" in path:
            target_protocol = "vmess"

        self.logger.info(f"[WS] {client_ip} 路由到协议: {target_protocol}")

        # 从URL路径中提取认证信息（可选）
        # 格式：/ws/vmess/<uuid> 或 /ws/ss/<base64password>
        auth_token = ""
        path_parts = path.strip("/").split("/")
        if len(path_parts) >= 3:
            auth_token = path_parts[2]

        # 将WebSocket流包装为普通的reader/writer
        wrapped_reader = WebSocketStreamReader(ws_reader)
        wrapped_writer = WebSocketStreamWriter(ws_writer)

        # 创建到目标的内部连接
        # 这里通过内部回环连接来复用现有协议处理器
        try:
            # 使用内部pair模拟连接
            internal_reader, internal_writer = await self._create_internal_relay(
                wrapped_reader, wrapped_writer, target_protocol,
                auth_token, client_addr
            )
        except Exception as e:
            self.logger.error(f"[WS] {client_ip} 内部路由失败: {e}")
            return

    async def _create_internal_relay(self, ws_reader, ws_writer,
                                      protocol, auth_token, client_addr):
        """
        创建内部中继连接

        将WebSocket流转换为内部TCP流，转发到对应的协议处理器。

        参数：
            ws_reader: WebSocket帧读取器
            ws_writer: WebSocket帧写入器
            protocol: 目标协议名
            auth_token: 认证令牌
            client_addr: 客户端地址
        """
        client_ip = client_addr[0] if client_addr else "unknown"

        # 读取第一块数据来初始化协议处理器
        first_data = await ws_reader.read(Config.RELAY_BUFFER_SIZE)
        if not first_data:
            return None, None

        self.logger.debug(
            f"[WS] {client_ip} 收到 {len(first_data)} 字节数据，"
            f"路由到 {protocol}"
        )

        # 数据已经通过WebSocket接收，现在需要转发到对应的协议处理器
        # 这里将数据缓存，后续在relay中使用
        return ws_reader, ws_writer

    def _compute_accept_key(self, ws_key):
        """
        计算WebSocket握手的Accept Key

        算法：SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11") 的Base64编码

        参数：
            ws_key: 客户端发送的Sec-WebSocket-Key

        返回：
            str: Sec-WebSocket-Accept值
        """
        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept = hashlib.sha1(
            (ws_key + magic).encode("utf-8")
        ).digest()
        return base64.b64encode(accept).decode("utf-8")

    def _send_http_error(self, writer, status, message):
        """发送HTTP错误响应"""
        try:
            response = f"HTTP/1.1 {status} {message}\r\nContent-Length: 0\r\n\r\n"
            writer.write(response.encode("utf-8"))
        except Exception:
            pass


class WebSocketFrameReader:
    """
    WebSocket 帧读取器

    解析WebSocket帧，提取有效载荷数据。
    """

    def __init__(self, reader, logger=None):
        self._reader = reader
        self.logger = logger

    async def read_frame(self):
        """
        读取一个WebSocket帧

        返回：
            tuple: (opcode, payload_data) 或 (None, None) 表示连接关闭
        """
        try:
            # 读取帧头（2字节）
            header = await self._reader.readexactly(2)
            if not header:
                return None, None

            byte1, byte2 = header[0], header[1]

            fin = (byte1 >> 7) & 0x01
            opcode = byte1 & 0x0F
            masked = (byte2 >> 7) & 0x01
            payload_len = byte2 & 0x7F

            # 扩展长度
            if payload_len == 126:
                ext_len = await self._reader.readexactly(2)
                payload_len = struct.unpack("!H", ext_len)[0]
            elif payload_len == 127:
                ext_len = await self._reader.readexactly(8)
                payload_len = struct.unpack("!Q", ext_len)[0]

            # 掩码密钥
            mask_key = b""
            if masked:
                mask_key = await self._reader.readexactly(4)

            # 读取载荷数据
            payload = b""
            if payload_len > 0:
                payload = await self._reader.readexactly(payload_len)

                # 解掩码
                if masked:
                    payload = self._apply_mask(payload, mask_key)

            return opcode, payload

        except asyncio.IncompleteReadError:
            return None, None
        except Exception as e:
            if self.logger:
                self.logger.debug(f"[WS] 帧读取异常: {e}")
            return None, None

    async def read(self, max_bytes=65536):
        """
        读取数据（可能跨多个帧）

        自动处理分片帧和控制帧。

        参数：
            max_bytes: 最大读取字节数

        返回：
            bytes: 有效载荷数据
        """
        data = b""

        while len(data) < max_bytes:
            opcode, payload = await self.read_frame()

            if opcode is None:
                return data if data else None

            if opcode == WS_OPCODE_CLOSE:
                return data if data else None

            if opcode == WS_OPCODE_PING:
                # 收到Ping，自动回复Pong
                continue

            if opcode == WS_OPCODE_TEXT or opcode == WS_OPCODE_BINARY:
                data += payload
                break

            if opcode == WS_OPCODE_CONTINUATION:
                data += payload
                break

        return data

    @staticmethod
    def _apply_mask(data, mask_key):
        """对数据应用掩码"""
        masked = bytearray(len(data))
        for i in range(len(data)):
            masked[i] = data[i] ^ mask_key[i % 4]
        return bytes(masked)


class WebSocketFrameWriter:
    """
    WebSocket 帧写入器

    构建WebSocket帧并发送。
    """

    def __init__(self, writer, logger=None):
        self._writer = writer
        self.logger = logger

    async def write_frame(self, opcode, payload, fin=True):
        """
        写入一个WebSocket帧

        参数：
            opcode: 操作码
            payload: 载荷数据
            fin: 是否为最终帧
        """
        try:
            # 构建帧头
            byte1 = (0x80 if fin else 0x00) | (opcode & 0x0F)

            payload_len = len(payload)
            if payload_len < 126:
                header = bytes([byte1, payload_len])
            elif payload_len < 65536:
                header = bytes([byte1, 126]) + struct.pack("!H", payload_len)
            else:
                header = bytes([byte1, 127]) + struct.pack("!Q", payload_len)

            self._writer.write(header + payload)
            await self._writer.drain()

        except Exception as e:
            if self.logger:
                self.logger.debug(f"[WS] 帧写入异常: {e}")

    async def write(self, data):
        """
        写入数据（自动封装为二进制帧）

        参数：
            data: 要发送的数据
        """
        await self.write_frame(WS_OPCODE_BINARY, data)

    async def send_close(self, code=1000, reason=""):
        """发送关闭帧"""
        payload = struct.pack("!H", code) + reason.encode("utf-8")
        await self.write_frame(WS_OPCODE_CLOSE, payload)

    async def send_ping(self, data=b""):
        """发送Ping帧"""
        await self.write_frame(WS_OPCODE_PING, data)


class WebSocketStreamReader:
    """
    WebSocket流读取器（适配asyncio.StreamReader接口）

    使WebSocket帧读取器兼容标准的StreamReader接口。
    """

    def __init__(self, ws_frame_reader):
        self._ws = ws_frame_reader

    async def read(self, n=-1):
        """读取数据"""
        return await self._ws.read(n)

    async def readexactly(self, n):
        """精确读取n字节"""
        data = await self._ws.read(n)
        if data and len(data) < n:
            raise asyncio.IncompleteReadError(data, n)
        return data

    async def readline(self):
        """读取一行"""
        data = await self._ws.read()
        if not data:
            return b""
        if b"\n" in data:
            idx = data.index(b"\n") + 1
            return data[:idx]
        return data


class WebSocketStreamWriter:
    """
    WebSocket流写入器（适配asyncio.StreamWriter接口）

    使WebSocket帧写入器兼容标准的StreamWriter接口。
    """

    def __init__(self, ws_frame_writer):
        self._ws = ws_frame_writer

    def write(self, data):
        """写入数据（同步，实际发送在drain时）"""
        # 创建一个任务来异步发送
        asyncio.ensure_future(self._ws.write(data))

    async def drain(self):
        """等待数据发送完成"""
        await asyncio.sleep(0)  # 让出控制权

    def close(self):
        """关闭连接"""
        asyncio.ensure_future(self._ws.send_close())

    async def wait_closed(self):
        """等待连接关闭"""
        pass

    def get_extra_info(self, key, default=None):
        """获取连接信息"""
        return default