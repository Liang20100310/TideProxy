#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy（潮汐代理） - 主入口脚本
作者：Yicheng Liang
协议：GNU General Public License v3.0 (GPL3.0)

本文件是 TideProxy 的唯一入口点。
启动方式：python tideproxy.py [选项]
"""

import argparse
import asyncio
import signal
import sys
import os

# ============================================================
# 将项目根目录加入 Python 路径，确保模块导入正常
# ============================================================
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Config
from logger import setup_logger, get_logger
from csv_manager import CSVManager
from firewall import Firewall
from server import ProxyServer
from billing import BillingSystem
from auth.activation import ActivationCodeManager
from auth.account import UserAccountManager
from auth.mac_bind import MACBindManager
from admin.cli import AdminCLI
from admin.api import AdminAPIServer


def parse_arguments():
    """解析命令行启动参数"""
    parser = argparse.ArgumentParser(
        description="TideProxy（潮汐代理）- 高性能异步代理服务",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  python tideproxy.py                          # 默认配置启动
  python tideproxy.py -p 1080                  # 指定代理端口
  python tideproxy.py --api --api-port 8080    # 启用API服务
  python tideproxy.py --no-cli                 # 无CLI模式（仅API）
        """
    )

    # 代理服务参数
    parser.add_argument(
        "-H", "--host",
        default=None,
        help="代理监听地址（默认：0.0.0.0）"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="代理监听端口（默认：1080）"
    )
    parser.add_argument(
        "--max-conn",
        type=int,
        default=None,
        help="最大并发连接数（默认：500）"
    )

    # API服务参数
    parser.add_argument(
        "--api",
        action="store_true",
        default=False,
        help="启用HTTP API管理服务"
    )
    parser.add_argument(
        "--api-host",
        default=None,
        help="API监听地址（默认：127.0.0.1）"
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=None,
        help="API监听端口（默认：8080）"
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="API访问密钥（默认：tideproxy_admin_2024）"
    )

    # 其他选项
    parser.add_argument(
        "--no-cli",
        action="store_true",
        default=False,
        help="禁用本地命令行管理（仅保留API管理）"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="日志级别（默认：INFO）"
    )

    # Shadowsocks 协议参数
    parser.add_argument(
        "--ss",
        action="store_true",
        default=False,
        help="启用Shadowsocks协议"
    )
    parser.add_argument(
        "--ss-port",
        type=int,
        default=None,
        help="Shadowsocks监听端口（默认：8388）"
    )
    parser.add_argument(
        "--ss-password",
        default=None,
        help="Shadowsocks密码"
    )
    parser.add_argument(
        "--ss-method",
        default=None,
        help="Shadowsocks加密方式（默认：aes-256-gcm）"
    )

    # VMess 协议参数
    parser.add_argument(
        "--vmess",
        action="store_true",
        default=False,
        help="启用VMess协议"
    )
    parser.add_argument(
        "--vmess-port",
        type=int,
        default=None,
        help="VMess监听端口（默认：10001）"
    )
    parser.add_argument(
        "--vmess-uuid",
        default=None,
        help="VMess用户UUID"
    )

    # WebSocket 传输参数
    parser.add_argument(
        "--ws",
        action="store_true",
        default=False,
        help="启用WebSocket传输"
    )
    parser.add_argument(
        "--ws-port",
        type=int,
        default=None,
        help="WebSocket监听端口（默认：10002）"
    )
    parser.add_argument(
        "--ws-path",
        default=None,
        help="WebSocket路径（默认：/tideproxy）"
    )

    # 订阅服务参数
    parser.add_argument(
        "--sub",
        action="store_true",
        default=False,
        help="启用订阅服务"
    )
    parser.add_argument(
        "--sub-port",
        type=int,
        default=None,
        help="订阅服务端口（默认：8081）"
    )
    parser.add_argument(
        "--sub-addr",
        default=None,
        help="对外服务器地址（域名或IP）"
    )
    parser.add_argument(
        "--sub-secret",
        default=None,
        help="订阅访问令牌"
    )

    return parser.parse_args()


def apply_args_to_config(args):
    """将命令行参数应用到全局配置"""
    if args.host is not None:
        Config.PROXY_HOST = args.host
    if args.port is not None:
        Config.PROXY_PORT = args.port
    if args.max_conn is not None:
        Config.MAX_CONNECTIONS = args.max_conn
    if args.api_host is not None:
        Config.API_HOST = args.api_host
    if args.api_port is not None:
        Config.API_PORT = args.api_port
    if args.api_key is not None:
        Config.API_ADMIN_KEY = args.api_key
    if args.log_level is not None:
        Config.LOG_LEVEL = args.log_level

    # Shadowsocks
    if args.ss:
        Config.SS_ENABLED = True
    if args.ss_port is not None:
        Config.SS_PORT = args.ss_port
    if args.ss_password is not None:
        Config.SS_PASSWORD = args.ss_password
    if args.ss_method is not None:
        Config.SS_METHOD = args.ss_method

    # VMess
    if args.vmess:
        Config.VMESS_ENABLED = True
    if args.vmess_port is not None:
        Config.VMESS_PORT = args.vmess_port
    if args.vmess_uuid is not None:
        Config.VMESS_UUID = args.vmess_uuid

    # WebSocket
    if args.ws:
        Config.WS_ENABLED = True
    if args.ws_port is not None:
        Config.WS_PORT = args.ws_port
    if args.ws_path is not None:
        Config.WS_PATH = args.ws_path

    # 订阅服务
    if args.sub:
        Config.SUB_ENABLED = True
    if args.sub_port is not None:
        Config.SUB_PORT = args.sub_port
    if args.sub_addr is not None:
        Config.SUB_SERVER_ADDR = args.sub_addr
    if args.sub_secret is not None:
        Config.SUB_SECRET = args.sub_secret


class TideProxyApplication:
    """
    TideProxy 主应用类

    负责协调所有子系统的初始化、启动和关闭：
    - CSV数据管理器
    - 日志系统
    - 防火墙（IP黑白名单）
    - 计费统计系统
    - 激活码管理器
    - 记名账号管理器
    - MAC绑定管理器
    - 代理服务器
    - HTTP API服务器（可选）
    - 管理员命令行（可选）
    """

    def __init__(self, args):
        """
        初始化主应用

        参数：
            args: 命令行参数对象
        """
        # ============================================================
        # 应用命令行参数到配置
        # ============================================================
        apply_args_to_config(args)

        # ============================================================
        # 初始化日志系统（最先初始化，后续模块都依赖日志）
        # ============================================================
        setup_logger()
        self.logger = get_logger("main")

        # ============================================================
        # 初始化数据目录
        # ============================================================
        Config.init_data_dirs()

        # ============================================================
        # 初始化各子系统
        # ============================================================

        # CSV数据管理器（最基础的数据层）
        self.csv_manager = CSVManager()

        # 计费统计系统
        self.billing = BillingSystem(self.csv_manager)

        # 激活码管理器
        self.activation_mgr = ActivationCodeManager(self.csv_manager, self.billing)

        # 记名账号管理器
        self.account_mgr = UserAccountManager(self.csv_manager, self.billing)

        # MAC绑定管理器
        self.mac_bind = MACBindManager(self.csv_manager)

        # 防火墙（IP黑白名单）
        self.firewall = Firewall(self.csv_manager)

        # 代理服务器
        self.proxy_server = ProxyServer(
            self.account_mgr,
            self.activation_mgr,
            self.mac_bind,
            self.billing,
            self.firewall
        )

        # HTTP API服务器（可选，根据启动参数决定是否启用）
        self.api_server = None
        if args.api:
            self.api_server = AdminAPIServer(
                self.account_mgr,
                self.activation_mgr,
                self.mac_bind,
                self.billing,
                self.firewall,
                self.csv_manager
            )

        # 管理员命令行（可选，根据启动参数决定是否启用）
        self.admin_cli = None
        if not args.no_cli:
            self.admin_cli = AdminCLI(
                self.account_mgr,
                self.activation_mgr,
                self.mac_bind,
                self.billing,
                self.firewall,
                self.csv_manager,
                self.proxy_server,
                self.api_server
            )

        # ============================================================
        # 异步任务集合（用于优雅退出时取消所有任务）
        # ============================================================
        self._tasks: list = []

        self.logger.info("=" * 60)
        self.logger.info("TideProxy（潮汐代理）初始化完成")
        self.logger.info("=" * 60)

    def _print_banner(self):
        """
        打印启动横幅

        显示服务的核心信息，包括监听地址、端口、功能状态等。
        """
        # 多协议状态行
        ss_line = f"开启 {Config.SS_HOST}:{Config.SS_PORT} ({Config.SS_METHOD})" if Config.SS_ENABLED else "关闭"
        vmess_line = f"开启 {Config.VMESS_HOST}:{Config.VMESS_PORT}" if Config.VMESS_ENABLED else "关闭"
        ws_line = f"开启 {Config.WS_HOST}:{Config.WS_PORT}{Config.WS_PATH}" if Config.WS_ENABLED else "关闭"
        sub_line = f"开启 {Config.SUB_HOST}:{Config.SUB_PORT}{Config.SUB_PATH}" if Config.SUB_ENABLED else "关闭"

        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║              TideProxy（潮汐代理）v1.1.0                    ║
║              作者：Yicheng Liang                             ║
║              协议：GNU GPL v3.0                              ║
╠══════════════════════════════════════════════════════════════╣
║  代理地址  ：{Config.PROXY_HOST}:{Config.PROXY_PORT:<20s}      ║
║  最大连接  ：{Config.MAX_CONNECTIONS:<38d}      ║
║  商业计费  ：{'开启' if Config.BILLING_ENABLED else '关闭':<38s}      ║
║  API服务   ：{'开启 ' + Config.API_HOST + ':' + str(Config.API_PORT) if self.api_server else '关闭':<38s}      ║
║  命令行    ：{'开启' if self.admin_cli else '关闭':<38s}      ║
╠══════════════════════════════════════════════════════════════╣
║  Shadowsocks：{ss_line:<36s}      ║
║  VMess      ：{vmess_line:<36s}      ║
║  WebSocket  ：{ws_line:<36s}      ║
║  订阅服务   ：{sub_line:<36s}      ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)

    async def start(self):
        """
        启动所有服务

        按照依赖顺序依次启动各个子系统：
        1. 代理服务器
        2. HTTP API服务器（如果启用）
        3. 管理员命令行（如果启用）
        """
        self._print_banner()

        # ============================================================
        # 启动代理服务器
        # ============================================================
        proxy_task = asyncio.create_task(
            self.proxy_server.start(),
            name="proxy_server"
        )
        self._tasks.append(proxy_task)

        # ============================================================
        # 启动HTTP API服务器（如果启用）
        # ============================================================
        if self.api_server:
            api_task = asyncio.create_task(
                self.api_server.start(),
                name="api_server"
            )
            self._tasks.append(api_task)

        # ============================================================
        # 启动管理员命令行（如果启用）
        # ============================================================
        if self.admin_cli:
            cli_task = asyncio.create_task(
                self.admin_cli.run(),
                name="admin_cli"
            )
            self._tasks.append(cli_task)

        # ============================================================
        # 注册系统信号处理器（用于优雅退出）
        # ============================================================
        loop = asyncio.get_running_loop()

        # 捕获 SIGINT（Ctrl+C）和 SIGTERM（kill 命令）
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))
            except NotImplementedError:
                # Windows 系统可能不支持 add_signal_handler
                pass

        # ============================================================
        # 等待所有任务完成（正常情况下会一直运行）
        # ============================================================
        try:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass

    async def shutdown(self):
        """
        优雅关闭所有服务

        按照启动的逆序关闭各个子系统，确保：
        - 所有活跃连接被安全释放
        - 所有统计数据被持久化
        - 所有资源被正确释放
        """
        self.logger.info("=" * 60)
        self.logger.info("TideProxy 正在优雅关闭...")
        self.logger.info("=" * 60)

        # ============================================================
        # 关闭代理服务器（停止接受新连接，等待现有连接完成）
        # ============================================================
        await self.proxy_server.stop()

        # ============================================================
        # 关闭HTTP API服务器
        # ============================================================
        if self.api_server:
            await self.api_server.stop()

        # ============================================================
        # 取消所有异步任务
        # ============================================================
        for task in self._tasks:
            if not task.done():
                task.cancel()

        # 等待所有任务完成取消操作
        await asyncio.gather(*self._tasks, return_exceptions=True)

        self.logger.info("TideProxy 已安全关闭，再见！")


def ensure_csv_files_exist():
    """
    确保所有CSV数据文件存在

    如果CSV文件不存在，创建带有正确表头的空文件。
    这保证了程序首次运行时不会因为文件缺失而报错。
    """
    # 定义每个CSV文件的表头
    csv_headers = {
        Config.ACCOUNTS_FILE: [
            "username", "password", "balance", "billing_mode",
            "bandwidth_limit", "traffic_limit", "mac_bind_enabled",
            "status", "created_at", "last_login", "total_traffic",
            "total_duration", "mac_address"
        ],
        Config.ACTIVATION_CODES_FILE: [
            "code", "serial_number", "plan_name", "total_traffic",
            "bandwidth_limit", "duration", "duration_unit",
            "mac_bind_enabled", "status", "activated_at",
            "last_access", "mac_address", "used_traffic",
            "used_duration", "created_at"
        ],
        Config.MAC_BINDINGS_FILE: [
            "identifier", "account_type", "mac_address",
            "bound_at", "last_seen"
        ],
        Config.TRAFFIC_LOGS_FILE: [
            "identifier", "account_type", "timestamp",
            "upload_bytes", "download_bytes", "total_bytes",
            "duration_seconds", "avg_bandwidth"
        ],
        Config.IP_WHITELIST_FILE: ["ip_address", "added_at", "note"],
        Config.IP_BLACKLIST_FILE: ["ip_address", "added_at", "reason"],
    }

    for file_path, headers in csv_headers.items():
        if not os.path.exists(file_path):
            # 使用CSV管理器创建带表头的空文件
            import csv
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)


def main():
    """
    程序主入口

    流程：
    1. 解析命令行参数
    2. 确保数据文件存在
    3. 创建应用实例
    4. 运行异步事件循环
    """
    # ============================================================
    # 解析命令行参数
    # ============================================================
    args = parse_arguments()

    # ============================================================
    # 确保所有CSV数据文件存在
    # ============================================================
    ensure_csv_files_exist()

    # ============================================================
    # 创建应用实例并运行
    # ============================================================
    app = TideProxyApplication(args)

    try:
        asyncio.run(app.start())
    except KeyboardInterrupt:
        # 用户按下 Ctrl+C 时的处理
        print("\n[系统] TideProxy 已停止运行")
    except Exception as e:
        # 未预期的异常
        print(f"\n[错误] TideProxy 运行异常：{e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()