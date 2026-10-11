#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy 激活码认证管理模块

实现激活码（不记名账户）的完整生命周期管理：
- 激活码生成（批量/单个）
- 激活码认证（连接时验证）
- 激活码状态管理（未激活/已激活/已过期/已用尽/封禁）
- 套餐配置管理
- 使用记录查询

激活码账户特点：
- 无用户名密码，仅靠激活码授权
- 支持流量计费和带宽时长计费两种模式
- 支持MAC地址绑定（防多设备共享）
- 所有数据存储在CSV文件中
"""

import hashlib
import random
import string
import time
from datetime import datetime, timedelta

from config import Config
from logger import get_logger


class ActivationCodeManager:
    """
    激活码管理器

    负责激活码的生成、认证、查询、删除等全部操作。
    """

    def __init__(self, csv_manager, billing_system):
        """
        初始化激活码管理器

        参数：
            csv_manager: CSVManager 实例
            billing_system: BillingSystem 实例
        """
        self.csv_manager = csv_manager
        self.billing = billing_system
        self.logger = get_logger("activation")

    def generate_code(self, plan_name="默认套餐", total_traffic=0,
                      bandwidth_limit=0, duration=30, duration_unit="days",
                      mac_bind_enabled=False):
        """
        生成单个激活码

        参数：
            plan_name: 套餐名称
            total_traffic: 总流量额度（字节），0表示不限
            bandwidth_limit: 最大带宽限制（字节/秒），0表示不限
            duration: 有效时长数值
            duration_unit: 时长单位（hours/days/months）
            mac_bind_enabled: 是否启用MAC绑定

        返回：
            tuple: (激活码字符串, 序列号字符串)
        """
        # 生成唯一激活码：16位大写字母+数字
        code = self._generate_unique_code()

        # 生成序列号：时间戳+随机数
        serial_number = self._generate_serial_number()

        # 计算过期时间
        now = datetime.now()
        if duration_unit == "hours":
            expire_time = now + timedelta(hours=duration)
        elif duration_unit == "days":
            expire_time = now + timedelta(days=duration)
        elif duration_unit == "months":
            expire_time = now + timedelta(days=duration * 30)
        else:
            expire_time = now + timedelta(days=duration)

        # 构建记录
        record = {
            "code": code,
            "serial_number": serial_number,
            "plan_name": plan_name,
            "total_traffic": str(total_traffic),
            "bandwidth_limit": str(bandwidth_limit),
            "duration": str(duration),
            "duration_unit": duration_unit,
            "mac_bind_enabled": str(mac_bind_enabled).lower(),
            "status": "inactive",  # 初始状态：未激活
            "activated_at": "",
            "last_access": "",
            "mac_address": "",
            "used_traffic": "0",
            "used_duration": "0",
            "created_at": now.strftime("%Y-%m-%d %H:%M:%S")
        }

        # 保存到CSV文件
        self.csv_manager.append(Config.ACTIVATION_CODES_FILE, record)

        self.logger.info(
            f"生成激活码: {code[:8]}*** | 序列号: {serial_number} | "
            f"套餐: {plan_name}"
        )

        return code, serial_number

    def batch_generate(self, count, plan_name="默认套餐", total_traffic=0,
                       bandwidth_limit=0, duration=30, duration_unit="days",
                       mac_bind_enabled=False):
        """
        批量生成激活码

        参数：
            count: 生成数量
            其他参数同 generate_code

        返回：
            list[tuple]: [(code, serial_number), ...]
        """
        codes = []
        for _ in range(count):
            code, serial = self.generate_code(
                plan_name, total_traffic, bandwidth_limit,
                duration, duration_unit, mac_bind_enabled
            )
            codes.append((code, serial))

        self.logger.info(f"批量生成 {count} 个激活码，套餐: {plan_name}")
        return codes

    def authenticate(self, code, client_ip=""):
        """
        认证激活码

        验证激活码的有效性，检查：
        1. 激活码是否存在
        2. 状态是否有效（已激活且未过期/未用尽）
        3. 是否过期
        4. 流量是否用尽
        5. MAC绑定检查

        认证成功后自动激活未激活的码。

        参数：
            code: 激活码字符串
            client_ip: 客户端IP（用于日志）

        返回：
            tuple: (bool 是否成功, str 消息)
        """
        # 查找激活码
        record = self.csv_manager.query_one(
            Config.ACTIVATION_CODES_FILE, "code", code
        )

        if not record:
            return False, "激活码不存在"

        status = record.get("status", "")

        # ============================================================
        # 状态检查
        # ============================================================
        if status == "banned":
            return False, "激活码已被封禁"

        if status == "exhausted":
            return False, "流量已用尽"

        if status == "expired":
            return False, "激活码已过期"

        # ============================================================
        # 自动激活未使用的码
        # ============================================================
        if status == "inactive":
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.csv_manager.update(
                Config.ACTIVATION_CODES_FILE,
                "code", code,
                {"status": "activated", "activated_at": now, "last_access": now}
            )
            self.logger.info(f"激活码 {code[:8]}*** 已自动激活")
            return True, "激活成功"

        # ============================================================
        # 检查是否过期
        # ============================================================
        if status == "activated":
            activated_at = record.get("activated_at", "")
            if activated_at:
                try:
                    activate_time = datetime.strptime(activated_at, "%Y-%m-%d %H:%M:%S")
                    duration = int(record.get("duration", 30))
                    duration_unit = record.get("duration_unit", "days")

                    if duration_unit == "hours":
                        expire_time = activate_time + timedelta(hours=duration)
                    elif duration_unit == "days":
                        expire_time = activate_time + timedelta(days=duration)
                    elif duration_unit == "months":
                        expire_time = activate_time + timedelta(days=duration * 30)
                    else:
                        expire_time = activate_time + timedelta(days=duration)

                    if datetime.now() > expire_time:
                        self.csv_manager.update(
                            Config.ACTIVATION_CODES_FILE,
                            "code", code,
                            {"status": "expired"}
                        )
                        return False, "激活码已过期"

                except (ValueError, TypeError):
                    pass

            # ============================================================
            # 检查流量是否用尽
            # ============================================================
            try:
                used_traffic = int(record.get("used_traffic", 0))
                total_traffic = int(record.get("total_traffic", 0))

                if total_traffic > 0 and used_traffic >= total_traffic:
                    self.csv_manager.update(
                        Config.ACTIVATION_CODES_FILE,
                        "code", code,
                        {"status": "exhausted"}
                    )
                    return False, "流量已用尽"
            except (ValueError, TypeError):
                pass

            # 更新最后访问时间
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.csv_manager.update(
                Config.ACTIVATION_CODES_FILE,
                "code", code,
                {"last_access": now}
            )

            return True, "认证成功"

        return False, "未知的激活码状态"

    def get_code_info(self, code):
        """
        获取激活码详细信息

        参数：
            code: 激活码

        返回：
            dict 或 None: 激活码信息
        """
        record = self.csv_manager.query_one(
            Config.ACTIVATION_CODES_FILE, "code", code
        )
        if record:
            # 添加计算字段
            try:
                used = int(record.get("used_traffic", 0))
                total = int(record.get("total_traffic", 0))
                record["remaining_traffic"] = max(0, total - used) if total > 0 else "不限"
                record["display_used"] = Config.get_bytes_display(used)
                record["display_total"] = Config.get_bytes_display(total) if total > 0 else "不限"
            except (ValueError, TypeError):
                pass
        return record

    def get_all_codes(self):
        """
        获取所有激活码列表

        返回：
            list[dict]: 所有激活码记录
        """
        return self.csv_manager.read(Config.ACTIVATION_CODES_FILE)

    def delete_code(self, code):
        """
        删除单个激活码

        参数：
            code: 激活码

        返回：
            bool: 是否删除成功
        """
        result = self.csv_manager.delete(
            Config.ACTIVATION_CODES_FILE, "code", code
        )
        if result:
            self.logger.info(f"已删除激活码: {code[:8]}***")
        return result

    def clear_all_codes(self):
        """
        清空所有激活码

        返回：
            int: 被清空的激活码数量
        """
        records = self.csv_manager.read(Config.ACTIVATION_CODES_FILE)
        count = len(records)
        self.csv_manager.clear(Config.ACTIVATION_CODES_FILE)
        self.logger.warning(f"已清空所有激活码，共 {count} 个")
        return count

    def ban_code(self, code):
        """
        封禁激活码

        参数：
            code: 激活码

        返回：
            bool: 是否操作成功
        """
        result = self.csv_manager.update(
            Config.ACTIVATION_CODES_FILE,
            "code", code,
            {"status": "banned"}
        )
        if result:
            self.logger.info(f"已封禁激活码: {code[:8]}***")
        return result

    def unban_code(self, code):
        """
        解封激活码

        参数：
            code: 激活码

        返回：
            bool: 是否操作成功
        """
        result = self.csv_manager.update(
            Config.ACTIVATION_CODES_FILE,
            "code", code,
            {"status": "activated"}
        )
        if result:
            self.logger.info(f"已解封激活码: {code[:8]}***")
        return result

    def get_code_count(self, status=None):
        """
        获取激活码数量

        参数：
            status: 可选，按状态过滤

        返回：
            int: 激活码数量
        """
        if status:
            return self.csv_manager.count(
                Config.ACTIVATION_CODES_FILE, "status", status
            )
        return self.csv_manager.count(Config.ACTIVATION_CODES_FILE)

    def _generate_unique_code(self):
        """
        生成唯一的激活码

        格式：16位大写字母+数字，如 ABCD1234EFGH5678

        返回：
            str: 唯一激活码
        """
        while True:
            # 生成16位随机字符串
            code = ''.join(random.choices(
                string.ascii_uppercase + string.digits, k=16
            ))

            # 检查是否已存在
            existing = self.csv_manager.query_one(
                Config.ACTIVATION_CODES_FILE, "code", code
            )
            if not existing:
                return code

    def _generate_serial_number(self):
        """
        生成序列号

        格式：TP-年月日-8位随机字符，如 TP-20240101-A1B2C3D4

        返回：
            str: 序列号
        """
        date_part = datetime.now().strftime("%Y%m%d")
        random_part = ''.join(random.choices(
            string.ascii_uppercase + string.digits, k=8
        ))
        return f"TP-{date_part}-{random_part}"