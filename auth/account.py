#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy 记名账号认证管理模块

实现记名用户账号的完整管理：
- 账号创建与删除
- 用户名/密码认证
- 密码修改
- 余额充值与扣费
- 账号状态管理（正常/冻结/过期/封禁）
- 带宽和流量限制配置

记名账号特点：
- 独立用户名+密码登录
- 支持余额充值机制
- 支持流量和带宽时长双计费模式
- 可长期运营使用
"""

import hashlib
from datetime import datetime

from config import Config
from logger import get_logger


class UserAccountManager:
    """
    记名账号管理器

    负责记名账号的创建、认证、管理等全部操作。
    """

    def __init__(self, csv_manager, billing_system):
        """
        初始化账号管理器

        参数：
            csv_manager: CSVManager 实例
            billing_system: BillingSystem 实例
        """
        self.csv_manager = csv_manager
        self.billing = billing_system
        self.logger = get_logger("account")

    def create_account(self, username, password, balance=0,
                       billing_mode="traffic", bandwidth_limit=0,
                       traffic_limit=0, mac_bind_enabled=False):
        """
        创建新的记名账号

        参数：
            username: 用户名（唯一）
            password: 密码（明文，内部会做哈希处理）
            balance: 初始余额
            billing_mode: 计费模式（traffic/bandwidth）
            bandwidth_limit: 带宽限制（字节/秒），0表示不限
            traffic_limit: 流量限制（字节），0表示不限
            mac_bind_enabled: 是否启用MAC绑定

        返回：
            tuple: (bool 是否成功, str 消息)
        """
        # 检查用户名是否已存在
        existing = self.csv_manager.query_one(
            Config.ACCOUNTS_FILE, "username", username
        )
        if existing:
            return False, "用户名已存在"

        # 密码哈希处理（SHA256）
        password_hash = self._hash_password(password)

        # 构建记录
        record = {
            "username": username,
            "password": password_hash,
            "balance": f"{float(balance):.2f}",
            "billing_mode": billing_mode,
            "bandwidth_limit": str(bandwidth_limit),
            "traffic_limit": str(traffic_limit),
            "mac_bind_enabled": str(mac_bind_enabled).lower(),
            "status": "active",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": "",
            "total_traffic": "0",
            "total_duration": "0",
            "mac_address": ""
        }

        self.csv_manager.append(Config.ACCOUNTS_FILE, record)
        self.logger.info(f"已创建账号: {username}")

        return True, "创建成功"

    def authenticate(self, username, password, client_ip=""):
        """
        认证记名账号

        验证流程：
        1. 查找用户名是否存在
        2. 验证密码
        3. 检查账号状态
        4. 检查余额（如果启用计费）
        5. 更新最后登录时间

        参数：
            username: 用户名
            password: 密码（明文）
            client_ip: 客户端IP

        返回：
            tuple: (bool 是否成功, str 消息)
        """
        # 查找账号
        record = self.csv_manager.query_one(
            Config.ACCOUNTS_FILE, "username", username
        )

        if not record:
            return False, "账号不存在"

        # ============================================================
        # 验证密码
        # ============================================================
        stored_hash = record.get("password", "")
        input_hash = self._hash_password(password)

        if stored_hash != input_hash:
            return False, "密码错误"

        # ============================================================
        # 检查账号状态
        # ============================================================
        status = record.get("status", "active")

        if status == "frozen":
            return False, "账号已冻结"

        if status == "banned":
            return False, "账号已被封禁"

        if status == "expired":
            return False, "账号已过期"

        if status == "over_traffic":
            return False, "流量已超额"

        if status != "active":
            return False, f"账号状态异常: {status}"

        # ============================================================
        # 检查余额（如果启用计费）
        # ============================================================
        if Config.BILLING_ENABLED:
            balance = float(record.get("balance", 0))
            if balance <= 0:
                return False, "余额不足"

        # ============================================================
        # 更新最后登录时间
        # ============================================================
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.csv_manager.update(
            Config.ACCOUNTS_FILE,
            "username", username,
            {"last_login": now}
        )

        self.logger.info(f"账号认证成功: {username} (IP: {client_ip})")
        return True, "认证成功"

    def change_password(self, username, old_password, new_password):
        """
        修改账号密码

        参数：
            username: 用户名
            old_password: 旧密码
            new_password: 新密码

        返回：
            tuple: (bool 是否成功, str 消息)
        """
        record = self.csv_manager.query_one(
            Config.ACCOUNTS_FILE, "username", username
        )

        if not record:
            return False, "账号不存在"

        # 验证旧密码
        if record.get("password") != self._hash_password(old_password):
            return False, "旧密码错误"

        # 更新密码
        new_hash = self._hash_password(new_password)
        result = self.csv_manager.update(
            Config.ACCOUNTS_FILE,
            "username", username,
            {"password": new_hash}
        )

        if result:
            self.logger.info(f"账号 {username} 已修改密码")
            return True, "密码修改成功"

        return False, "密码修改失败"

    def admin_reset_password(self, username, new_password):
        """
        管理员重置账号密码

        参数：
            username: 用户名
            new_password: 新密码

        返回：
            bool: 是否操作成功
        """
        new_hash = self._hash_password(new_password)
        result = self.csv_manager.update(
            Config.ACCOUNTS_FILE,
            "username", username,
            {"password": new_hash}
        )
        if result:
            self.logger.info(f"管理员已重置账号 {username} 的密码")
        return result

    def get_account(self, username):
        """
        获取账号信息

        参数：
            username: 用户名

        返回：
            dict 或 None: 账号信息
        """
        return self.csv_manager.query_one(
            Config.ACCOUNTS_FILE, "username", username
        )

    def get_all_accounts(self):
        """
        获取所有账号列表

        返回：
            list[dict]: 所有账号记录
        """
        return self.csv_manager.read(Config.ACCOUNTS_FILE)

    def delete_account(self, username):
        """
        删除账号

        参数：
            username: 用户名

        返回：
            bool: 是否删除成功
        """
        result = self.csv_manager.delete(
            Config.ACCOUNTS_FILE, "username", username
        )
        if result:
            self.logger.info(f"已删除账号: {username}")
        return result

    def freeze_account(self, username):
        """
        冻结账号

        参数：
            username: 用户名

        返回：
            bool: 是否操作成功
        """
        result = self.csv_manager.update(
            Config.ACCOUNTS_FILE,
            "username", username,
            {"status": "frozen"}
        )
        if result:
            self.logger.info(f"已冻结账号: {username}")
        return result

    def unfreeze_account(self, username):
        """
        解冻账号

        参数：
            username: 用户名

        返回：
            bool: 是否操作成功
        """
        result = self.csv_manager.update(
            Config.ACCOUNTS_FILE,
            "username", username,
            {"status": "active"}
        )
        if result:
            self.logger.info(f"已解冻账号: {username}")
        return result

    def ban_account(self, username):
        """
        封禁账号

        参数：
            username: 用户名

        返回：
            bool: 是否操作成功
        """
        result = self.csv_manager.update(
            Config.ACCOUNTS_FILE,
            "username", username,
            {"status": "banned"}
        )
        if result:
            self.logger.info(f"已封禁账号: {username}")
        return result

    def unban_account(self, username):
        """
        解封账号

        参数：
            username: 用户名

        返回：
            bool: 是否操作成功
        """
        result = self.csv_manager.update(
            Config.ACCOUNTS_FILE,
            "username", username,
            {"status": "active"}
        )
        if result:
            self.logger.info(f"已解封账号: {username}")
        return result

    def set_bandwidth_limit(self, username, limit):
        """
        设置账号带宽限制

        参数：
            username: 用户名
            limit: 带宽限制（字节/秒），0表示不限

        返回：
            bool: 是否操作成功
        """
        result = self.csv_manager.update(
            Config.ACCOUNTS_FILE,
            "username", username,
            {"bandwidth_limit": str(limit)}
        )
        if result:
            self.logger.info(f"已设置账号 {username} 带宽限制: {limit} B/s")
        return result

    def set_traffic_limit(self, username, limit):
        """
        设置账号流量限制

        参数：
            username: 用户名
            limit: 流量限制（字节），0表示不限

        返回：
            bool: 是否操作成功
        """
        result = self.csv_manager.update(
            Config.ACCOUNTS_FILE,
            "username", username,
            {"traffic_limit": str(limit)}
        )
        if result:
            self.logger.info(f"已设置账号 {username} 流量限制: {limit} B")
        return result

    def get_account_count(self, status=None):
        """
        获取账号数量

        参数：
            status: 可选，按状态过滤

        返回：
            int: 账号数量
        """
        if status:
            return self.csv_manager.count(
                Config.ACCOUNTS_FILE, "status", status
            )
        return self.csv_manager.count(Config.ACCOUNTS_FILE)

    def _hash_password(self, password):
        """
        密码哈希处理

        使用SHA256对密码进行哈希处理，附加盐值增加安全性。

        参数：
            password: 明文密码

        返回：
            str: 哈希后的密码字符串
        """
        salt = "tideproxy_salt_2024"
        return hashlib.sha256(
            (salt + password).encode("utf-8")
        ).hexdigest()