#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy HTTP API管理接口模块

提供HTTP REST API管理接口，支持：
- 通过HTTP POST请求执行所有管理员命令
- API密钥鉴权（X-Admin-Key Header）
- JSON格式请求和响应
- 访问日志记录
- 频率限制

API特性：
- 独立端口，与代理端口分离
- 所有操作与本地CLI完全对齐
- 返回统一JSON格式（状态码、消息、数据）
"""

import asyncio
import json
import time
from collections import defaultdict
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

from config import Config
from logger import get_logger


class APIRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP API 请求处理器

    处理所有API请求：
    - 验证API密钥
    - 解析JSON请求体
    - 执行对应的管理命令
    - 返回JSON格式结果
    """

    # 类级别的引用，由APIServer在启动时设置
    admin_cli = None
    logger = None

    # 访问频率记录
    _access_records = defaultdict(list)
    _lock = threading.Lock()

    def do_POST(self):
        """
        处理POST请求

        流程：
        1. 验证API密钥
        2. 检查频率限制
        3. 解析请求体
        4. 执行管理命令
        5. 返回JSON结果
        """
        client_ip = self.client_address[0]

        # ============================================================
        # 验证API密钥
        # ============================================================
        api_key = self.headers.get("X-Admin-Key", "")
        if api_key != Config.API_ADMIN_KEY:
            self.logger.warning(
                f"[API] 鉴权失败 - IP: {client_ip}, 密钥: {api_key[:8]}..."
            )
            self._send_json_response(403, "API密钥无效", None)
            return

        # ============================================================
        # 检查频率限制
        # ============================================================
        if not self._check_rate_limit(client_ip):
            self.logger.warning(f"[API] 频率超限 - IP: {client_ip}")
            self._send_json_response(429, "请求频率超限，请稍后再试", None)
            return

        # ============================================================
        # 读取并解析请求体
        # ============================================================
        content_length = int(self.headers.get("Content-Length", 0))

        if content_length > Config.API_MAX_BODY_SIZE:
            self._send_json_response(413, "请求体过大", None)
            return

        if content_length == 0:
            self._send_json_response(400, "请求体为空", None)
            return

        try:
            body = self.rfile.read(content_length)
            request_data = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self.logger.warning(f"[API] JSON解析失败 - IP: {client_ip}: {e}")
            self._send_json_response(400, "JSON格式错误", None)
            return

        # ============================================================
        # 获取命令字符串
        # ============================================================
        command = request_data.get("command", "")
        if not command:
            self._send_json_response(400, "缺少command字段", None)
            return

        # ============================================================
        # 记录API访问日志
        # ============================================================
        self.logger.info(
            f"[API] IP: {client_ip} | 命令: {command}"
        )

        # ============================================================
        # 执行管理命令
        # ============================================================
        try:
            result = self.admin_cli.execute_command(command)

            # 判断执行结果
            if result.startswith("[错误]"):
                self._send_json_response(400, result, None)
            else:
                self._send_json_response(200, "执行成功", {"output": result})

            # 记录执行结果
            self.logger.info(
                f"[API] IP: {client_ip} | 命令: {command} | 结果: 成功"
            )

        except Exception as e:
            self.logger.error(
                f"[API] 命令执行异常 - IP: {client_ip}, 命令: {command}: {e}"
            )
            self._send_json_response(500, f"命令执行异常: {str(e)}", None)

    def do_GET(self):
        """
        处理GET请求

        仅提供简单的状态检查接口
        """
        api_key = self.headers.get("X-Admin-Key", "")
        if api_key != Config.API_ADMIN_KEY:
            self._send_json_response(403, "API密钥无效", None)
            return

        # 健康检查
        if self.path == "/health":
            self._send_json_response(200, "TideProxy API 运行正常", {
                "version": "1.0.0",
                "status": "running",
                "timestamp": datetime.now().isoformat()
            })
        else:
            self._send_json_response(404, "接口不存在，请使用POST方法发送命令", None)

    def _send_json_response(self, status_code, message, data):
        """
        发送JSON格式响应

        参数：
            status_code: HTTP状态码
            message: 响应消息
            data: 响应数据（可选）
        """
        response = {
            "code": status_code,
            "message": message,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        if data is not None:
            response["data"] = data

        response_body = json.dumps(response, ensure_ascii=False, indent=2).encode("utf-8")

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def _check_rate_limit(self, client_ip):
        """
        检查客户端请求频率

        参数：
            client_ip: 客户端IP

        返回：
            bool: True 允许请求，False 频率超限
        """
        with self._lock:
            now = time.time()
            cutoff = now - 60  # 一分钟前

            # 清理过期记录
            self._access_records[client_ip] = [
                t for t in self._access_records[client_ip]
                if t > cutoff
            ]

            # 检查频率
            if len(self._access_records[client_ip]) >= Config.API_RATE_LIMIT:
                return False

            # 记录本次访问
            self._access_records[client_ip].append(now)
            return True

    def log_message(self, format, *args):
        """覆盖默认日志输出，使用TideProxy日志系统"""
        pass  # 已在do_POST中记录日志，不需要默认日志


class AdminAPIServer:
    """
    TideProxy HTTP API服务器

    独立的HTTP服务，提供管理API接口。
    使用线程运行HTTP服务器，避免阻塞asyncio事件循环。
    """

    def __init__(self, account_mgr, activation_mgr, mac_bind,
                 billing, firewall, csv_manager):
        """
        初始化API服务器

        参数：
            account_mgr: 记名账号管理器
            activation_mgr: 激活码管理器
            mac_bind: MAC绑定管理器
            billing: 计费系统
            firewall: 防火墙
            csv_manager: CSV数据管理器
        """
        self.logger = get_logger("api_server")

        # ============================================================
        # 创建内部CLI实例（供API调用）
        # ============================================================
        from admin.cli import AdminCLI
        self._admin_cli = AdminCLI(
            account_mgr, activation_mgr, mac_bind,
            billing, firewall, csv_manager, None, self
        )

        # ============================================================
        # 设置请求处理器的类属性
        # ============================================================
        APIRequestHandler.admin_cli = self._admin_cli
        APIRequestHandler.logger = self.logger

        # ============================================================
        # HTTP服务器实例
        # ============================================================
        self._server = None
        self._thread = None
        self._running = False

    async def start(self):
        """
        启动API服务器

        在单独的线程中运行HTTP服务器，
        避免阻塞asyncio事件循环。
        """
        try:
            self._server = HTTPServer(
                (Config.API_HOST, Config.API_PORT),
                APIRequestHandler
            )

            self._running = True

            # 在线程中运行HTTP服务器
            self._thread = threading.Thread(
                target=self._run_server,
                daemon=True,
                name="api_server"
            )
            self._thread.start()

            self.logger.info(
                f"HTTP API服务已启动 - "
                f"监听 {Config.API_HOST}:{Config.API_PORT}"
            )
            self.logger.info(
                f"API访问密钥: {Config.API_ADMIN_KEY[:8]}***"
            )

            # 保持运行
            while self._running:
                await asyncio.sleep(1)

        except OSError as e:
            self.logger.error(f"API服务启动失败: {e}")
            raise
        except asyncio.CancelledError:
            self.logger.info("API服务任务已取消")
        except Exception as e:
            self.logger.error(f"API服务异常: {e}", exc_info=True)

    async def stop(self):
        """
        停止API服务器
        """
        self._running = False

        if self._server:
            self.logger.info("正在停止HTTP API服务...")
            self._server.shutdown()
            self._server.server_close()

        self.logger.info("HTTP API服务已停止")

    def _run_server(self):
        """
        运行HTTP服务器（在线程中执行）
        """
        try:
            self._server.serve_forever()
        except Exception as e:
            if self._running:
                self.logger.error(f"API服务器运行异常: {e}")

    def get_status(self):
        """
        获取API服务器状态

        返回：
            dict: 状态信息
        """
        return {
            "running": self._running,
            "listen_addr": f"{Config.API_HOST}:{Config.API_PORT}",
            "rate_limit": Config.API_RATE_LIMIT
        }