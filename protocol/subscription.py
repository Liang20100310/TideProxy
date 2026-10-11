#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy 订阅服务模块

提供多格式代理订阅服务，自动生成各平台客户端配置文件。

支持的订阅格式：
1. Clash / Clash Meta（YAML格式）
   - 适用：Clash for Windows, ClashX, Clash Verge, mihomo
   - 平台：Windows, macOS, Linux

2. Hiddify（JSON格式）
   - 适用：Hiddify Next, HiddifyNG
   - 平台：Windows, macOS, Linux, Android

3. SIP008（JSON格式）
   - 适用：Shadowsocks标准订阅
   - 平台：iOS (Shadowrocket), Android (影梭)

4. V2RayN / Base64（纯文本Base64格式）
   - 适用：V2rayN, V2rayNG, NekoBox
   - 平台：Windows, Android

5. Surge（配置文件格式）
   - 适用：Surge 5, Quantumult X
   - 平台：iOS, macOS

6. 通用URI格式
   - ss:// shadowsocks链接
   - vmess:// vmess链接
   - trojan:// trojan链接

平台兼容性矩阵：
┌─────────────┬────────────┬───────────┬───────────┬──────────┐
│  平台       │ 推荐客户端  │ 订阅格式   │ 支持协议   │ 备注     │
├─────────────┼────────────┼───────────┼───────────┼──────────┤
│ Windows     │ Clash Verge│ Clash     │ SS/VMess  │ 原生VPN  │
│             │ V2rayN     │ V2RayN    │ VMess/SS  │ PPTP/L2TP│
│             │ Hiddify    │ Hiddify   │ 全部      │          │
├─────────────┼────────────┼───────────┼───────────┼──────────┤
│ macOS       │ ClashX Pro │ Clash     │ SS/VMess  │ 原生VPN  │
│             │ Surge 5    │ Surge     │ SS/VMess  │ IKEv2    │
│             │ Shadowrocket│SIP008    │ 全部      │ SS/VMess │
├─────────────┼────────────┼───────────┼───────────┼──────────┤
│ iOS         │ Shadowrocket│SIP008    │ 全部      │ 原生VPN  │
│             │ QuantumultX│ QX格式    │ SS/VMess  │ IKEv2    │
│             │ Surge      │ Surge     │ SS/VMess  │          │
│             │ Hiddify    │ Hiddify   │ 全部      │          │
├─────────────┼────────────┼───────────┼───────────┼──────────┤
│ Android     │ V2rayNG    │ V2RayN    │ VMess/SS  │ 原生VPN  │
│             │ Clash Meta │ Clash     │ 全部      │          │
│             │ Hiddify    │ Hiddify   │ 全部      │          │
│             │ NekoBox    │ V2RayN    │ SS/VMess  │          │
├─────────────┼────────────┼───────────┼───────────┼──────────┤
│ WindowsPhone│ 内置VPN    │ -         │ PPTP/L2TP │ 有限支持  │
│             │            │           │ IKEv2     │          │
├─────────────┼────────────┼───────────┼───────────┼──────────┤
│ BlackBerry  │ 内置VPN    │ -         │ IKEv2     │ BB10/OS  │
└─────────────┴────────────┴───────────┴───────────┴──────────┘
"""

import asyncio
import base64
import json
import os
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

from config import Config
from logger import get_logger


class SubscriptionHandler(BaseHTTPRequestHandler):
    """
    HTTP请求处理器

    处理订阅链接的HTTP GET请求，返回对应格式的配置。
    """

    # 类级别引用，由SubscriptionServer设置
    sub_server = None
    logger = None

    def do_GET(self):
        """处理GET请求"""
        path = self.path

        # ============================================================
        # 验证订阅令牌
        # ============================================================
        token = self._extract_token(path)
        if not token or token != Config.SUB_SECRET:
            self._send_response(403, "text/plain", "Invalid token")
            self.logger.warning(f"[订阅] 鉴权失败 - IP: {self.client_address[0]}")
            return

        self.logger.info(f"[订阅] 请求 - IP: {self.client_address[0]}, 路径: {path}")

        # ============================================================
        # 根据路径返回对应格式的订阅
        # ============================================================
        if "/clash" in path or "/clash.meta" in path:
            content = self.sub_server.generate_clash_config()
            self._send_response(200, "text/yaml", content)

        elif "/surge" in path:
            content = self.sub_server.generate_surge_config()
            self._send_response(200, "text/plain", content)

        elif "/sip008" in path or "/ss" in path:
            content = self.sub_server.generate_sip008_config()
            self._send_response(200, "application/json", content)

        elif "/v2ray" in path or "/base64" in path:
            content = self.sub_server.generate_v2ray_config()
            self._send_response(200, "text/plain", content)

        elif "/hiddify" in path:
            content = self.sub_server.generate_hiddify_config()
            self._send_response(200, "application/json", content)

        elif "/uri" in path:
            content = self.sub_server.generate_uri_list()
            self._send_response(200, "text/plain", content)

        else:
            # 返回可用的订阅链接列表
            content = self.sub_server.generate_index_page()
            self._send_response(200, "text/html; charset=utf-8", content)

    def do_POST(self):
        """POST请求重定向到GET"""
        self.do_GET()

    def _extract_token(self, path):
        """从路径中提取令牌"""
        # 格式：/sub/<token>/clash 或 /sub?token=xxx
        parts = path.strip("/").split("/")
        if len(parts) >= 2:
            return parts[1] if len(parts) > 1 else ""

        if "?" in path:
            query = path.split("?", 1)[1]
            for param in query.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    if key == "token":
                        return value

        return ""

    def _send_response(self, status, content_type, body):
        """发送HTTP响应"""
        if isinstance(body, str):
            body = body.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """覆盖默认日志"""
        pass


class SubscriptionServer:
    """
    订阅服务服务器

    生成各平台客户端的代理配置文件。
    """

    def __init__(self, proxy_server, ss_handler=None, vmess_handler=None):
        """
        初始化订阅服务

        参数：
            proxy_server: ProxyServer实例
            ss_handler: Shadowsocks处理器
            vmess_handler: VMess处理器
        """
        self.logger = get_logger("subscription")
        self.proxy_server = proxy_server
        self.ss_handler = ss_handler
        self.vmess_handler = vmess_handler

        self._server = None
        self._thread = None
        self._running = False

        # 设置请求处理器的类引用
        SubscriptionHandler.sub_server = self
        SubscriptionHandler.logger = self.logger

    async def start(self):
        """启动订阅服务"""
        try:
            self._server = HTTPServer(
                (Config.SUB_HOST, Config.SUB_PORT),
                SubscriptionHandler
            )
            self._running = True

            self._thread = threading.Thread(
                target=self._run_server, daemon=True, name="sub_server"
            )
            self._thread.start()

            self.logger.info(
                f"订阅服务已启动 - "
                f"http://{Config.SUB_HOST}:{Config.SUB_PORT}{Config.SUB_PATH}"
            )

            while self._running:
                await asyncio.sleep(1)

        except OSError as e:
            self.logger.error(f"订阅服务启动失败: {e}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"订阅服务异常: {e}", exc_info=True)

    async def stop(self):
        """停止订阅服务"""
        self._running = False
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        self.logger.info("订阅服务已停止")

    def _run_server(self):
        """运行HTTP服务器"""
        try:
            self._server.serve_forever()
        except Exception:
            pass

    # ================================================================
    # 配置生成方法
    # ================================================================

    def _get_server_info(self):
        """获取服务器连接信息"""
        addr = Config.SUB_SERVER_ADDR or "your-server.com"
        return {
            "addr": addr,
            "ss_port": Config.SS_PORT if Config.SS_ENABLED else 0,
            "vmess_port": Config.VMESS_PORT if Config.VMESS_ENABLED else 0,
            "trojan_port": Config.TROJAN_PORT if Config.TROJAN_ENABLED else 0,
            "ws_port": Config.WS_PORT if Config.WS_ENABLED else 0,
            "ws_path": Config.WS_PATH,
            "name": Config.SUB_SERVER_NAME,
        }

    def generate_clash_config(self):
        """
        生成 Clash / Clash Meta 配置

        返回YAML格式的完整Clash配置文件。
        """
        info = self._get_server_info()
        proxies = []
        proxy_groups = []

        # --- Shadowsocks 代理节点 ---
        if Config.SS_ENABLED and self.ss_handler:
            for username, user_info in self.ss_handler.get_all_users().items():
                proxies.append({
                    "name": f"SS-{username}",
                    "type": "ss",
                    "server": info["addr"],
                    "port": info["ss_port"],
                    "cipher": user_info["method"],
                    "password": user_info["password"],
                    "udp": True,
                })

        # --- VMess 代理节点 ---
        if Config.VMESS_ENABLED and self.vmess_handler:
            for username, user_info in self.vmess_handler.get_all_users().items():
                proxies.append({
                    "name": f"VMess-{username}",
                    "type": "vmess",
                    "server": info["addr"],
                    "port": info["vmess_port"],
                    "uuid": user_info["uuid"],
                    "alterId": user_info["alter_id"],
                    "cipher": user_info["security"],
                    "udp": True,
                })

                # WebSocket传输节点
                if Config.WS_ENABLED:
                    proxies.append({
                        "name": f"VMess-WS-{username}",
                        "type": "vmess",
                        "server": info["addr"],
                        "port": info["ws_port"],
                        "uuid": user_info["uuid"],
                        "alterId": user_info["alter_id"],
                        "cipher": user_info["security"],
                        "network": "ws",
                        "ws-opts": {
                            "path": info["ws_path"],
                        },
                        "udp": True,
                    })

        # --- 代理组 ---
        all_proxy_names = [p["name"] for p in proxies]

        proxy_groups = [
            {
                "name": "Proxy",
                "type": "select",
                "proxies": ["DIRECT"] + all_proxy_names,
            },
            {
                "name": "Auto",
                "type": "url-test",
                "proxies": all_proxy_names,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
            },
        ]

        # --- 构建完整配置 ---
        config = {
            "mixed-port": 7890,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "info",
            "external-controller": "127.0.0.1:9090",
            "proxies": proxies,
            "proxy-groups": proxy_groups,
            "rules": [
                "MATCH,DIRECT"
            ]
        }

        # 转换为YAML（手动实现，避免依赖PyYAML）
        return self._dict_to_yaml(config)

    def generate_surge_config(self):
        """
        生成 Surge 配置

        返回Surge兼容的配置文件格式。
        """
        info = self._get_server_info()
        lines = []

        lines.append("[General]")
        lines.append("loglevel = notify")
        lines.append("skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8")
        lines.append("")

        lines.append("[Proxy]")
        lines.append("DIRECT = direct")

        # SS节点
        if Config.SS_ENABLED and self.ss_handler:
            for username, user_info in self.ss_handler.get_all_users().items():
                lines.append(
                    f"SS-{username} = ss, {info['addr']}, {info['ss_port']}, "
                    f"encrypt-method={user_info['method']}, "
                    f"password={user_info['password']}"
                )

        # VMess节点
        if Config.VMESS_ENABLED and self.vmess_handler:
            for username, user_info in self.vmess_handler.get_all_users().items():
                lines.append(
                    f"VMess-{username} = vmess, {info['addr']}, {info['vmess_port']}, "
                    f"username={user_info['uuid']}, "
                    f"tls=false"
                )

        lines.append("")
        lines.append("[Rule]")
        lines.append("FINAL,DIRECT")

        return "\n".join(lines)

    def generate_sip008_config(self):
        """
        生成 SIP008 订阅配置

        JSON格式，兼容Shadowsocks标准订阅。
        """
        info = self._get_server_info()
        servers = []

        if Config.SS_ENABLED and self.ss_handler:
            for username, user_info in self.ss_handler.get_all_users().items():
                servers.append({
                    "server": info["addr"],
                    "server_port": info["ss_port"],
                    "password": user_info["password"],
                    "method": user_info["method"],
                    "remarks": f"TideProxy-SS-{username}",
                })

        config = {
            "version": 1,
            "servers": servers,
        }

        return json.dumps(config, ensure_ascii=False, indent=2)

    def generate_v2ray_config(self):
        """
        生成 V2RayN / Base64 订阅

        返回Base64编码的URI列表。
        """
        uris = []

        # SS链接
        if Config.SS_ENABLED and self.ss_handler:
            info = self._get_server_info()
            for username, user_info in self.ss_handler.get_all_users().items():
                # ss://base64(method:password)@server:port#remark
                method = user_info["method"]
                password = user_info["password"]
                userinfo = base64.b64encode(
                    f"{method}:{password}".encode()
                ).decode()
                uri = (
                    f"ss://{userinfo}@{info['addr']}:{info['ss_port']}"
                    f"#TideProxy-SS-{username}"
                )
                uris.append(uri)

        # VMess链接
        if Config.VMESS_ENABLED and self.vmess_handler:
            info = self._get_server_info()
            for username, user_info in self.vmess_handler.get_all_users().items():
                link = self.vmess_handler.get_vmess_link(
                    username, info["addr"], info["vmess_port"],
                    f"TideProxy-VMess-{username}"
                )
                if link:
                    uris.append(link)

        # Base64编码
        content = "\n".join(uris)
        return base64.b64encode(content.encode()).decode()

    def generate_hiddify_config(self):
        """
        生成 Hiddify 订阅配置

        Hiddify使用JSON格式的代理配置。
        """
        info = self._get_server_info()
        proxies = []

        # SS节点
        if Config.SS_ENABLED and self.ss_handler:
            for username, user_info in self.ss_handler.get_all_users().items():
                proxy = {
                    "type": "ss",
                    "name": f"SS-{username}",
                    "server": info["addr"],
                    "port": info["ss_port"],
                    "cipher": user_info["method"],
                    "password": user_info["password"],
                }
                proxies.append(proxy)

        # VMess节点
        if Config.VMESS_ENABLED and self.vmess_handler:
            for username, user_info in self.vmess_handler.get_all_users().items():
                proxy = {
                    "type": "vmess",
                    "name": f"VMess-{username}",
                    "server": info["addr"],
                    "port": info["vmess_port"],
                    "uuid": user_info["uuid"],
                    "alterId": user_info["alter_id"],
                    "cipher": user_info["security"],
                    "transport": "tcp",
                }
                proxies.append(proxy)

                if Config.WS_ENABLED:
                    ws_proxy = dict(proxy)
                    ws_proxy["name"] = f"VMess-WS-{username}"
                    ws_proxy["port"] = info["ws_port"]
                    ws_proxy["transport"] = "ws"
                    ws_proxy["path"] = info["ws_path"]
                    proxies.append(ws_proxy)

        config = {
            "version": 2,
            "proxies": proxies,
            "rules": [],
        }

        return json.dumps(config, ensure_ascii=False, indent=2)

    def generate_uri_list(self):
        """
        生成通用URI列表

        返回纯文本的代理URI列表，每行一个。
        """
        return self.generate_v2ray_config()

    def generate_index_page(self):
        """
        生成订阅服务首页

        显示所有可用的订阅链接。
        """
        base = f"http://{Config.SUB_HOST}:{Config.SUB_PORT}"
        token = Config.SUB_SECRET

        links = [
            ("Clash / Clash Meta", f"{base}{Config.SUB_PATH}/{token}/clash"),
            ("Surge", f"{base}{Config.SUB_PATH}/{token}/surge"),
            ("SIP008 (Shadowsocks)", f"{base}{Config.SUB_PATH}/{token}/sip008"),
            ("V2RayN / Base64", f"{base}{Config.SUB_PATH}/{token}/v2ray"),
            ("Hiddify", f"{base}{Config.SUB_PATH}/{token}/hiddify"),
            ("通用URI列表", f"{base}{Config.SUB_PATH}/{token}/uri"),
        ]

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>TideProxy 订阅服务</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; max-width: 700px; margin: 50px auto; padding: 20px; }}
        h1 {{ color: #2c3e50; }}
        .link {{ background: #f8f9fa; padding: 12px 16px; margin: 8px 0; border-radius: 8px; border-left: 4px solid #3498db; }}
        .link a {{ color: #2980b9; text-decoration: none; word-break: break-all; }}
        .link a:hover {{ text-decoration: underline; }}
        .label {{ font-weight: bold; color: #2c3e50; display: block; margin-bottom: 4px; }}
        .note {{ color: #7f8c8d; font-size: 14px; margin-top: 30px; }}
    </style>
</head>
<body>
    <h1>🌊 TideProxy 订阅服务</h1>
    <p>选择适合您客户端的订阅链接：</p>
"""

        for name, url in links:
            html += f"""
    <div class="link">
        <span class="label">{name}</span>
        <a href="{url}">{url}</a>
    </div>
"""

        html += f"""
    <p class="note">
        📱 支持平台：Windows / macOS / iOS / Android / Linux<br>
        🔑 需要配置正确的服务器地址和用户信息才能使用
    </p>
</body>
</html>"""

        return html

    def _dict_to_yaml(self, data, indent=0):
        """
        将字典转换为YAML格式（简单实现）

        避免依赖PyYAML库。
        """
        lines = []
        prefix = "  " * indent

        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    lines.append(f"{prefix}{key}:")
                    lines.append(self._dict_to_yaml(value, indent + 1))
                else:
                    lines.append(f"{prefix}{key}: {value}")

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    first = True
                    for key, value in item.items():
                        if first:
                            if isinstance(value, (dict, list)):
                                lines.append(f"{prefix}- {key}:")
                                lines.append(self._dict_to_yaml(value, indent + 2))
                            else:
                                lines.append(f"{prefix}- {key}: {value}")
                            first = False
                        else:
                            if isinstance(value, (dict, list)):
                                lines.append(f"{prefix}  {key}:")
                                lines.append(self._dict_to_yaml(value, indent + 2))
                            else:
                                lines.append(f"{prefix}  {key}: {value}")
                else:
                    lines.append(f"{prefix}- {item}")

        return "\n".join(lines)