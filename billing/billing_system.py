#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy 计费统计系统

实现完整的流量和时长计费功能，支持：
- 流量计费模式：按实际上行+下行总流量扣费
- 带宽时长计费模式：按有效时长计费，限制最大带宽
- 实时流量统计和余额扣减
- 计费记录持久化存储

设计特点：
- 线程安全（使用线程锁保护共享数据）
- 支持两种账户类型（激活码账户 / 记名账户）
- 流量统计精确到字节
- 时长统计精确到秒
"""

import threading
import time
from datetime import datetime

from config import Config
from logger import get_logger


class BillingSystem:
    """
    计费统计系统

    负责所有与计费相关的操作：
    1. 流量统计记录
    2. 余额扣减
    3. 额度检查
    4. 计费记录持久化
    """

    def __init__(self, csv_manager):
        """
        初始化计费系统

        参数：
            csv_manager: CSVManager 实例
        """
        self.csv_manager = csv_manager
        self.logger = get_logger("billing")

        # 线程锁
        self._lock = threading.Lock()

        # 内存中的活跃连接统计
        # 结构：{(identifier, account_type): {"upload": int, "download": int, "start_time": float}}
        self._active_sessions = {}

        self.logger.info("计费统计系统已初始化")

    def record_traffic(self, identifier, account_type, upload_bytes, download_bytes):
        """
        记录流量消耗

        参数：
            identifier: 用户标识（用户名或激活码）
            account_type: 账户类型（"activation" 或 "account"）
            upload_bytes: 上行流量（字节）
            download_bytes: 下行流量（字节）

        返回：
            bool: 是否记录成功
        """
        with self._lock:
            try:
                total_bytes = upload_bytes + download_bytes
                session_key = (identifier, account_type)

                # 更新内存中的活跃会话统计
                if session_key not in self._active_sessions:
                    self._active_sessions[session_key] = {
                        "upload": 0,
                        "download": 0,
                        "start_time": time.time()
                    }
                self._active_sessions[session_key]["upload"] += upload_bytes
                self._active_sessions[session_key]["download"] += download_bytes

                return True

            except Exception as e:
                self.logger.error(f"记录流量失败 [{identifier}]: {e}")
                return False

    def deduct_traffic(self, identifier, account_type, bytes_used):
        """
        扣减流量额度

        用于流量计费模式，从用户的流量额度中扣除已用流量。

        参数：
            identifier: 用户标识
            account_type: 账户类型
            bytes_used: 使用的字节数

        返回：
            tuple: (bool 是否扣减成功, str 状态消息)
        """
        with self._lock:
            try:
                if account_type == "activation":
                    return self._deduct_activation_traffic(identifier, bytes_used)
                elif account_type == "account":
                    return self._deduct_account_traffic(identifier, bytes_used)
                else:
                    return False, "未知的账户类型"

            except Exception as e:
                self.logger.error(f"扣减流量失败 [{identifier}]: {e}")
                return False, str(e)

    def _deduct_activation_traffic(self, code, bytes_used):
        """
        扣减激活码账户的流量

        参数：
            code: 激活码
            bytes_used: 使用的字节数

        返回：
            tuple: (bool, str)
        """
        record = self.csv_manager.query_one(
            Config.ACTIVATION_CODES_FILE, "code", code
        )
        if not record:
            return False, "激活码不存在"

        try:
            used_traffic = int(record.get("used_traffic", 0))
            total_traffic = int(record.get("total_traffic", 0))
        except (ValueError, TypeError):
            return False, "流量数据格式错误"

        new_used = used_traffic + bytes_used

        # 检查是否超额
        if total_traffic > 0 and new_used > total_traffic:
            # 标记为已用尽
            self.csv_manager.update(
                Config.ACTIVATION_CODES_FILE,
                "code", code,
                {"used_traffic": str(total_traffic), "status": "exhausted"}
            )
            return False, "流量已用尽"

        # 更新已用流量
        self.csv_manager.update(
            Config.ACTIVATION_CODES_FILE,
            "code", code,
            {"used_traffic": str(new_used)}
        )

        return True, "扣减成功"

    def _deduct_account_traffic(self, username, bytes_used):
        """
        扣减记名账户的流量

        参数：
            username: 用户名
            bytes_used: 使用的字节数

        返回：
            tuple: (bool, str)
        """
        record = self.csv_manager.query_one(
            Config.ACCOUNTS_FILE, "username", username
        )
        if not record:
            return False, "账户不存在"

        try:
            total_traffic = int(record.get("total_traffic", 0))
            traffic_limit = int(record.get("traffic_limit", 0))
        except (ValueError, TypeError):
            return False, "流量数据格式错误"

        new_total = total_traffic + bytes_used

        # 检查是否超额（traffic_limit > 0 表示有限制）
        if traffic_limit > 0 and new_total > traffic_limit:
            self.csv_manager.update(
                Config.ACCOUNTS_FILE,
                "username", username,
                {"total_traffic": str(traffic_limit), "status": "over_traffic"}
            )
            return False, "流量已超额"

        # 更新已用流量
        self.csv_manager.update(
            Config.ACCOUNTS_FILE,
            "username", username,
            {"total_traffic": str(new_total)}
        )

        return True, "扣减成功"

    def check_balance(self, identifier, account_type):
        """
        检查账户余额/额度是否充足

        参数：
            identifier: 用户标识
            account_type: 账户类型

        返回：
            tuple: (bool 是否充足, str 消息)
        """
        with self._lock:
            try:
                if account_type == "activation":
                    record = self.csv_manager.query_one(
                        Config.ACTIVATION_CODES_FILE, "code", identifier
                    )
                    if not record:
                        return False, "激活码不存在"

                    status = record.get("status", "")
                    if status == "exhausted":
                        return False, "流量已用尽"
                    if status == "expired":
                        return False, "已过期"
                    if status == "banned":
                        return False, "已被封禁"

                    return True, "余额充足"

                elif account_type == "account":
                    record = self.csv_manager.query_one(
                        Config.ACCOUNTS_FILE, "username", identifier
                    )
                    if not record:
                        return False, "账户不存在"

                    status = record.get("status", "")
                    if status == "frozen":
                        return False, "账户已冻结"
                    if status == "banned":
                        return False, "账户已被封禁"

                    balance = float(record.get("balance", 0))
                    if balance <= 0:
                        return False, "余额不足"

                    return True, "余额充足"

                return False, "未知账户类型"

            except Exception as e:
                self.logger.error(f"检查余额失败 [{identifier}]: {e}")
                return False, str(e)

    def deduct_balance(self, username, amount):
        """
        扣减记名账户余额

        参数：
            username: 用户名
            amount: 扣减金额

        返回：
            tuple: (bool 是否成功, str 消息, float 剩余余额)
        """
        with self._lock:
            try:
                record = self.csv_manager.query_one(
                    Config.ACCOUNTS_FILE, "username", username
                )
                if not record:
                    return False, "账户不存在", 0

                balance = float(record.get("balance", 0))
                if balance < amount:
                    return False, "余额不足", balance

                new_balance = balance - amount
                self.csv_manager.update(
                    Config.ACCOUNTS_FILE,
                    "username", username,
                    {"balance": f"{new_balance:.2f}"}
                )

                return True, "扣费成功", new_balance

            except Exception as e:
                self.logger.error(f"扣减余额失败 [{username}]: {e}")
                return False, str(e), 0

    def add_balance(self, username, amount):
        """
        为记名账户充值

        参数：
            username: 用户名
            amount: 充值金额

        返回：
            tuple: (bool 是否成功, str 消息, float 充值后余额)
        """
        with self._lock:
            try:
                record = self.csv_manager.query_one(
                    Config.ACCOUNTS_FILE, "username", username
                )
                if not record:
                    return False, "账户不存在", 0

                balance = float(record.get("balance", 0))
                new_balance = balance + amount
                self.csv_manager.update(
                    Config.ACCOUNTS_FILE,
                    "username", username,
                    {"balance": f"{new_balance:.2f}"}
                )

                self.logger.info(f"用户 {username} 充值 {amount:.2f}，余额：{new_balance:.2f}")
                return True, "充值成功", new_balance

            except Exception as e:
                self.logger.error(f"充值失败 [{username}]: {e}")
                return False, str(e), 0

    def record_session_traffic(self, identifier, account_type, upload, download):
        """
        记录一次会话的流量消耗并持久化

        在连接断开时调用，将本次会话的流量统计写入CSV日志。

        参数：
            identifier: 用户标识
            account_type: 账户类型
            upload: 上行流量（字节）
            download: 下行流量（字节）
        """
        with self._lock:
            try:
                total = upload + download
                duration = 0

                # 计算会话时长
                session_key = (identifier, account_type)
                if session_key in self._active_sessions:
                    session = self._active_sessions[session_key]
                    duration = int(time.time() - session.get("start_time", time.time()))

                # 写入流量日志CSV
                self.csv_manager.append(Config.TRAFFIC_LOGS_FILE, {
                    "identifier": identifier,
                    "account_type": account_type,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "upload_bytes": str(upload),
                    "download_bytes": str(download),
                    "total_bytes": str(total),
                    "duration_seconds": str(duration),
                    "avg_bandwidth": str(
                        int(total / duration) if duration > 0 else 0
                    )
                })

                # 清除活跃会话记录
                self._active_sessions.pop(session_key, None)

            except Exception as e:
                self.logger.error(f"记录会话流量失败 [{identifier}]: {e}")

    def get_global_stats(self):
        """
        获取全局流量统计

        返回：
            dict: 包含总流量、总连接数等全局统计信息
        """
        with self._lock:
            try:
                records = self.csv_manager.read(Config.TRAFFIC_LOGS_FILE)
                total_upload = sum(int(r.get("upload_bytes", 0)) for r in records)
                total_download = sum(int(r.get("download_bytes", 0)) for r in records)
                total_duration = sum(int(r.get("duration_seconds", 0)) for r in records)
                total_sessions = len(records)

                return {
                    "total_upload": total_upload,
                    "total_download": total_download,
                    "total_traffic": total_upload + total_download,
                    "total_duration": total_duration,
                    "total_sessions": total_sessions,
                    "active_sessions": len(self._active_sessions),
                    "display_upload": Config.get_bytes_display(total_upload),
                    "display_download": Config.get_bytes_display(total_download),
                    "display_total": Config.get_bytes_display(total_upload + total_download),
                    "display_duration": Config.get_duration_display(total_duration)
                }
            except Exception as e:
                self.logger.error(f"获取全局统计失败: {e}")
                return {}

    def get_user_stats(self, identifier, account_type="all"):
        """
        获取指定用户的流量统计

        参数：
            identifier: 用户标识
            account_type: 账户类型过滤（"all"表示不过滤）

        返回：
            dict: 用户的流量统计信息
        """
        with self._lock:
            try:
                records = self.csv_manager.read(Config.TRAFFIC_LOGS_FILE)

                # 过滤记录
                user_records = []
                for r in records:
                    if r.get("identifier") == identifier:
                        if account_type == "all" or r.get("account_type") == account_type:
                            user_records.append(r)

                total_upload = sum(int(r.get("upload_bytes", 0)) for r in user_records)
                total_download = sum(int(r.get("download_bytes", 0)) for r in user_records)
                total_duration = sum(int(r.get("duration_seconds", 0)) for r in user_records)

                return {
                    "identifier": identifier,
                    "total_upload": total_upload,
                    "total_download": total_download,
                    "total_traffic": total_upload + total_download,
                    "total_duration": total_duration,
                    "session_count": len(user_records),
                    "display_upload": Config.get_bytes_display(total_upload),
                    "display_download": Config.get_bytes_display(total_download),
                    "display_total": Config.get_bytes_display(total_upload + total_download),
                    "display_duration": Config.get_duration_display(total_duration)
                }
            except Exception as e:
                self.logger.error(f"获取用户统计失败 [{identifier}]: {e}")
                return {}

    def get_active_sessions(self):
        """
        获取当前活跃会话列表

        返回：
            list[dict]: 活跃会话信息
        """
        with self._lock:
            sessions = []
            for (identifier, account_type), data in self._active_sessions.items():
                duration = int(time.time() - data.get("start_time", time.time()))
                total = data["upload"] + data["download"]
                sessions.append({
                    "identifier": identifier,
                    "account_type": account_type,
                    "upload": data["upload"],
                    "download": data["download"],
                    "total": total,
                    "duration": duration,
                    "display_upload": Config.get_bytes_display(data["upload"]),
                    "display_download": Config.get_bytes_display(data["download"]),
                    "display_total": Config.get_bytes_display(total),
                    "display_duration": Config.get_duration_display(duration)
                })
            return sessions