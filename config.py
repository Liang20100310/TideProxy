#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy 配置模块

集中管理所有可配置参数，包括：
- 代理服务配置（监听地址、端口、最大连接数）
- API服务配置（监听地址、端口、密钥）
- 数据文件路径（CSV存储位置）
- 日志配置（级别、文件路径、轮转策略）
- 安全配置（黑白名单、连接限制）
- 计费系统配置

所有配置项均为类属性，支持启动时通过命令行参数覆盖。
"""

import os


class Config:
    """
    TideProxy 全局配置类

    所有配置项集中在此类中管理，使用类属性的方式定义。
    启动时可通过命令行参数覆盖默认值。

    配置分组：
    1. 代理服务配置
    2. 管理员API配置
    3. 数据存储路径
    4. 日志配置
    5. 安全配置
    6. 计费系统配置
    7. 管理员命令列表
    """

    # ================================================================
    # 1. 代理服务配置
    # ================================================================

    # 代理服务器监听地址（0.0.0.0 表示监听所有网络接口）
    PROXY_HOST = "0.0.0.0"

    # 代理服务器监听端口
    PROXY_PORT = 1080

    # 最大并发连接数（防止资源耗尽）
    MAX_CONNECTIONS = 500

    # 连接超时时间（秒）
    # 建立连接阶段的超时
    CONNECTION_TIMEOUT = 30

    # 数据转发阶段的空闲超时（秒）
    # 如果在指定时间内没有任何数据传输，连接将被关闭
    RELAY_TIMEOUT = 300

    # 数据转发缓冲区大小（字节）
    # 每次读取数据的最大字节数，影响内存占用和转发效率
    RELAY_BUFFER_SIZE = 65536  # 64KB

    # ================================================================
    # 1.5 多协议代理配置（新增）
    # ================================================================

    # --- Shadowsocks 协议 ---
    SS_ENABLED = False                 # 是否启用Shadowsocks
    SS_HOST = "0.0.0.0"               # SS监听地址
    SS_PORT = 8388                     # SS监听端口
    SS_PASSWORD = "tideproxy_ss"       # SS默认密码
    SS_METHOD = "aes-256-gcm"          # SS加密方式
    # 支持的加密方式：
    #   AEAD（推荐）: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
    #   流式（旧版）: aes-128-cfb, aes-256-cfb, chacha20-ietf
    SS_SUPPORTED_METHODS = [
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
        "aes-128-cfb", "aes-256-cfb", "chacha20-ietf"
    ]

    # --- VMess 协议 ---
    VMESS_ENABLED = False              # 是否启用VMess
    VMESS_HOST = "0.0.0.0"            # VMess监听地址
    VMESS_PORT = 10001                 # VMess监听端口
    VMESS_UUID = ""                    # VMess用户UUID（留空则自动生成）
    VMESS_ALTER_ID = 0                 # VMess AlterID（推荐0，即AEAD）
    VMESS_SECURITY = "auto"           # VMess加密方式（auto/aes-128-gcm/chacha20-poly1305/none）

    # --- WebSocket 传输层 ---
    WS_ENABLED = False                 # 是否启用WebSocket传输
    WS_HOST = "0.0.0.0"              # WS监听地址
    WS_PORT = 10002                    # WS监听端口
    WS_PATH = "/tideproxy"            # WS路径
    WS_TLS_ENABLED = False             # 是否启用TLS（需配置证书）
    WS_TLS_CERT = ""                  # TLS证书路径
    WS_TLS_KEY = ""                   # TLS私钥路径

    # --- Trojan 协议 ---
    TROJAN_ENABLED = False             # 是否启用Trojan
    TROJAN_HOST = "0.0.0.0"           # Trojan监听地址
    TROJAN_PORT = 10003                # Trojan监听端口
    TROJAN_PASSWORD = ""              # Trojan密码
    TROJAN_CERT_PATH = ""             # TLS证书路径（Trojan强制TLS）
    TROJAN_KEY_PATH = ""              # TLS私钥路径

    # --- 订阅服务 ---
    SUB_ENABLED = False                # 是否启用订阅服务
    SUB_HOST = "127.0.0.1"            # 订阅服务监听地址
    SUB_PORT = 8081                    # 订阅服务监听端口
    SUB_PATH = "/sub"                 # 订阅基础路径
    SUB_SECRET = "tideproxy_sub"       # 订阅令牌密钥
    SUB_SERVER_ADDR = ""              # 对外服务器地址（域名或IP）
    SUB_SERVER_NAME = "TideProxy"     # 服务器显示名称
    SUB_CLASH_ENABLED = True           # 生成Clash配置
    SUB_SURGE_ENABLED = True           # 生成Surge配置
    SUB_SIP008_ENABLED = True          # 生成SIP008/SS订阅
    SUB_HIDDIFY_ENABLED = True         # 生成Hiddify配置
    SUB_V2RAY_ENABLED = True           # 生成V2RayN/Base64订阅

    # CSV文件：协议用户配置
    PROTOCOL_USERS_FILE = os.path.join(DATA_DIR, "protocol_users.csv")

    # ================================================================
    # 2. 管理员API配置
    # ================================================================

    # API服务监听地址（默认仅监听本地，安全考虑）
    API_HOST = "127.0.0.1"

    # API服务监听端口
    API_PORT = 8080

    # API访问密钥（所有API请求必须携带此密钥进行鉴权）
    # 生产环境部署时务必修改此密钥！
    API_ADMIN_KEY = "tideproxy_admin_2024"

    # API请求频率限制（每分钟最大请求数，按来源IP限制）
    API_RATE_LIMIT = 60

    # API请求体最大大小（字节，防止恶意大请求）
    API_MAX_BODY_SIZE = 1024 * 1024  # 1MB

    # ================================================================
    # 3. 数据存储路径
    # ================================================================

    # 项目根目录（自动计算，无需手动配置）
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    # 数据文件根目录
    DATA_DIR = os.path.join(BASE_DIR, "data")

    # 记名账号数据文件
    ACCOUNTS_FILE = os.path.join(DATA_DIR, "accounts.csv")

    # 激活码数据文件
    ACTIVATION_CODES_FILE = os.path.join(DATA_DIR, "activation_codes.csv")

    # MAC地址绑定记录文件
    MAC_BINDINGS_FILE = os.path.join(DATA_DIR, "mac_bindings.csv")

    # 流量统计记录文件
    TRAFFIC_LOGS_FILE = os.path.join(DATA_DIR, "traffic_logs.csv")

    # IP白名单文件
    IP_WHITELIST_FILE = os.path.join(DATA_DIR, "ip_whitelist.csv")

    # IP黑名单文件
    IP_BLACKLIST_FILE = os.path.join(DATA_DIR, "ip_blacklist.csv")

    # 套餐档次配置文件
    PLANS_FILE = os.path.join(DATA_DIR, "plans.csv")

    # ================================================================
    # 4. 日志配置
    # ================================================================

    # 日志文件目录
    LOG_DIR = os.path.join(BASE_DIR, "logs")

    # 日志文件名
    LOG_FILE = os.path.join(LOG_DIR, "tideproxy.log")

    # 日志级别（DEBUG / INFO / WARNING / ERROR）
    LOG_LEVEL = "INFO"

    # 日志格式
    LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    # 日期格式
    LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

    # 单个日志文件最大大小（字节）- 超过后自动轮转
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB

    # 保留的历史日志文件数量
    LOG_BACKUP_COUNT = 5

    # ================================================================
    # 5. 安全配置
    # ================================================================

    # 是否启用IP白名单（启用后仅白名单IP可连接）
    IP_WHITELIST_ENABLED = False

    # 是否启用IP黑名单（启用后黑名单IP将被拒绝）
    IP_BLACKLIST_ENABLED = True

    # 单IP最大并发连接数（防止恶意连接）
    MAX_CONNECTIONS_PER_IP = 10

    # 异常高频连接阈值（每分钟连接次数超过此值触发风控记录）
    ABUSE_THRESHOLD = 30

    # 异常连接封锁时间（秒）- 超过阈值后的临时封锁时长
    ABUSE_BLOCK_DURATION = 300  # 5分钟

    # ================================================================
    # 6. 计费系统配置
    # ================================================================

    # 是否启用商业计费系统（关闭后所有用户无需认证即可使用）
    BILLING_ENABLED = True

    # 流量统计精度（秒）- 每隔多少秒记录一次流量统计快照
    BILLING_SNAPSHOT_INTERVAL = 60

    # 流量单位换算
    BYTES_PER_KB = 1024
    BYTES_PER_MB = 1024 * 1024
    BYTES_PER_GB = 1024 * 1024 * 1024

    # ================================================================
    # 7. 管理员命令列表（用于命令解析和帮助显示）
    # ================================================================

    ADMIN_COMMANDS = [
        # 系统控制
        "help", "start", "stop", "restart", "status", "quit", "exit",
        # 激活码管理
        "gen_code", "list_codes", "del_code", "clear_codes",
        "code_info", "export_codes", "import_codes",
        # 套餐管理
        "add_plan", "list_plans", "del_plan", "mod_plan",
        # 记名账号管理
        "add_user", "del_user", "user_info", "list_users",
        "topup", "freeze", "unfreeze", "ban", "unban",
        "reset_pwd", "set_bw", "set_traffic",
        # MAC绑定
        "bind_mac", "unbind_mac", "list_mac",
        # 统计与维护
        "stats", "user_stats", "clear_expired",
        # 计费系统控制
        "billing_on", "billing_off",
        # 系统维护
        "reload_wl", "reload_bl",
        # 多协议管理（新增）
        "proto_status", "proto_enable", "proto_disable",
        "ss_config", "vmess_config", "trojan_config",
        "ws_config", "add_proto_user", "del_proto_user", "list_proto_users",
        "sub_url", "sub_generate", "sub_status",
    ]

    # ================================================================
    # 类方法：辅助工具
    # ================================================================

    @classmethod
    def init_data_dirs(cls):
        """
        初始化数据目录

        确保数据目录和日志目录存在。
        如果目录不存在则自动创建。
        """
        os.makedirs(cls.DATA_DIR, exist_ok=True)
        os.makedirs(cls.LOG_DIR, exist_ok=True)

    @classmethod
    def get_bytes_display(cls, byte_count):
        """
        将字节数转换为人类可读的格式

        参数：
            byte_count: 字节数（整数）

        返回：
            格式化后的字符串，如 "1.50 GB"
        """
        if byte_count < 0:
            return "0 B"
        elif byte_count < cls.BYTES_PER_KB:
            return f"{byte_count} B"
        elif byte_count < cls.BYTES_PER_MB:
            return f"{byte_count / cls.BYTES_PER_KB:.2f} KB"
        elif byte_count < cls.BYTES_PER_GB:
            return f"{byte_count / cls.BYTES_PER_MB:.2f} MB"
        else:
            return f"{byte_count / cls.BYTES_PER_GB:.2f} GB"

    @classmethod
    def get_duration_display(cls, seconds):
        """
        将秒数转换为人类可读的时长格式

        参数：
            seconds: 秒数（整数）

        返回：
            格式化后的字符串，如 "2小时30分钟"
        """
        if seconds < 60:
            return f"{seconds}秒"
        elif seconds < 3600:
            minutes = seconds // 60
            secs = seconds % 60
            return f"{minutes}分{secs}秒"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}小时{minutes}分"