#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy MAC地址绑定管理模块

实现设备MAC地址绑定功能：
- 绑定MAC地址到激活码/账号
- 验证设备MAC地址
- 查询绑定记录
- 解绑MAC地址

MAC绑定原理：
- 每个激活码/账号可以绑定一个唯一的MAC地址
- 绑定后，仅允许该MAC地址的设备使用代理
- 用于防止多设备共享激活码/账号
- MAC地址通过TCP连接的客户端信息获取

注意：
- MAC地址获取依赖网络层实现
- 跨网段连接时可能无法获取真实MAC地址
- 此实现通过客户端首次连接时记录的MAC进行绑定
"""

from datetime import datetime

from config import Config
from logger import get_logger


class MACBindManager:
    """
    MAC地址绑定管理器

    负责MAC地址的绑定、验证、查询、解绑等操作。
    """

    def __init__(self, csv_manager):
        """
        初始化MAC绑定管理器

        参数：
            csv_manager: CSVManager 实例
        """
        self.csv_manager = csv_manager
        self.logger = get_logger("mac_bind")

    def bind_mac(self, identifier, account_type, mac_address):
        """
        绑定MAC地址到指定账户

        参数：
            identifier: 用户标识（用户名或激活码）
            account_type: 账户类型（activation/account）
            mac_address: 要绑定的MAC地址

        返回：
            tuple: (bool 是否成功, str 消息)
        """
        # 标准化MAC地址格式
        mac_address = self._normalize_mac(mac_address)

        # 检查是否已有绑定
        existing = self._get_binding(identifier, account_type)
        if existing:
            existing_mac = existing.get("mac_address", "")
            if existing_mac == mac_address:
                return True, "该MAC地址已绑定"
            else:
                return False, f"已绑定其他设备: {existing_mac}"

        # 创建新的绑定记录
        record = {
            "identifier": identifier,
            "account_type": account_type,
            "mac_address": mac_address,
            "bound_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self.csv_manager.append(Config.MAC_BINDINGS_FILE, record)

        # 同时更新激活码/账号记录中的MAC地址
        if account_type == "activation":
            self.csv_manager.update(
                Config.ACTIVATION_CODES_FILE,
                "code", identifier,
                {"mac_address": mac_address}
            )
        elif account_type == "account":
            self.csv_manager.update(
                Config.ACCOUNTS_FILE,
                "username", identifier,
                {"mac_address": mac_address}
            )

        self.logger.info(
            f"MAC绑定成功: {identifier} ({account_type}) -> {mac_address}"
        )
        return True, "绑定成功"

    def verify_mac(self, identifier, account_type, mac_address):
        """
        验证MAC地址是否与绑定的一致

        参数：
            identifier: 用户标识
            account_type: 账户类型
            mac_address: 当前设备的MAC地址

        返回：
            tuple: (bool 是否验证通过, str 消息)
        """
        mac_address = self._normalize_mac(mac_address)
        binding = self._get_binding(identifier, account_type)

        if not binding:
            # 没有绑定记录，允许通过（首次连接将自动绑定）
            return True, "无绑定记录"

        bound_mac = binding.get("mac_address", "")

        if bound_mac == mac_address:
            # 更新最后见到时间
            self._update_last_seen(identifier, account_type)
            return True, "MAC地址匹配"

        return False, f"MAC地址不匹配，已绑定: {bound_mac}"

    def unbind_mac(self, identifier, account_type):
        """
        解除MAC地址绑定

        参数：
            identifier: 用户标识
            account_type: 账户类型

        返回：
            bool: 是否解除成功
        """
        result = self.csv_manager.delete(
            Config.MAC_BINDINGS_FILE,
            "identifier", identifier
        )

        # 同时清除激活码/账号记录中的MAC地址
        if account_type == "activation":
            self.csv_manager.update(
                Config.ACTIVATION_CODES_FILE,
                "code", identifier,
                {"mac_address": ""}
            )
        elif account_type == "account":
            self.csv_manager.update(
                Config.ACCOUNTS_FILE,
                "username", identifier,
                {"mac_address": ""}
            )

        if result:
            self.logger.info(f"已解除MAC绑定: {identifier} ({account_type})")

        return result

    def get_binding(self, identifier, account_type):
        """
        获取绑定信息

        参数：
            identifier: 用户标识
            account_type: 账户类型

        返回：
            dict 或 None: 绑定信息
        """
        return self._get_binding(identifier, account_type)

    def get_all_bindings(self):
        """
        获取所有绑定记录

        返回：
            list[dict]: 所有绑定记录
        """
        return self.csv_manager.read(Config.MAC_BINDINGS_FILE)

    def get_bindings_by_mac(self, mac_address):
        """
        查询使用指定MAC地址的所有绑定

        参数：
            mac_address: MAC地址

        返回：
            list[dict]: 绑定记录列表
        """
        mac_address = self._normalize_mac(mac_address)
        return self.csv_manager.query(
            Config.MAC_BINDINGS_FILE, "mac_address", mac_address
        )

    def _get_binding(self, identifier, account_type):
        """
        内部方法：获取绑定记录

        参数：
            identifier: 用户标识
            account_type: 账户类型

        返回：
            dict 或 None
        """
        records = self.csv_manager.query(
            Config.MAC_BINDINGS_FILE, "identifier", identifier
        )
        for record in records:
            if record.get("account_type") == account_type:
                return record
        return None

    def _update_last_seen(self, identifier, account_type):
        """
        更新最后见到时间

        参数：
            identifier: 用户标识
            account_type: 账户类型
        """
        self.csv_manager.update(
            Config.MAC_BINDINGS_FILE,
            "identifier", identifier,
            {"last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        )

    def _normalize_mac(self, mac_address):
        """
        标准化MAC地址格式

        将各种MAC地址格式统一为大写冒号分隔格式：
        AA:BB:CC:DD:EE:FF

        参数：
            mac_address: 原始MAC地址

        返回：
            str: 标准化后的MAC地址
        """
        # 移除所有分隔符
        clean = mac_address.replace(":", "").replace("-", "").replace(".", "").upper()

        # 插入冒号分隔
        if len(clean) == 12:
            return ":".join([clean[i:i+2] for i in range(0, 12, 2)])

        return mac_address.upper()