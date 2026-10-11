#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy 防火墙模块

提供IP黑白名单管理和连接频率控制功能，用于：
- IP白名单：仅允许白名单中的IP连接
- IP黑名单：拒绝黑名单中的IP连接
- 连接频率控制：防止单IP异常高频连接
- 滥用检测与自动封锁

数据存储：
- IP白名单存储在 CSV 文件中
- IP黑名单存储在 CSV 文件中
- 连接频率记录保存在内存中（程序重启后自动清除）
"""

import threading
import time
from collections import defaultdict
from datetime import datetime

from config import Config
from logger import get_logger


class Firewall:
    """
    TideProxy 防火墙

    负责所有入站连接的安全检查，包括：
    1. IP白名单检查
    2. IP黑名单检查
    3. 连接频率限制
    4. 滥用行为检测与封锁
    """

    def __init__(self, csv_manager):
        """
        初始化防火墙

        参数：
            csv_manager: CSVManager 实例，用于读取IP黑白名单数据
        """
        self.csv_manager = csv_manager
        self.logger = get_logger("firewall")

        # ============================================================
        # IP白名单集合（从CSV加载）
        # ============================================================
        self._whitelist = set()
        self._load_whitelist()

        # ============================================================
        # IP黑名单集合（从CSV加载）
        # ============================================================
        self._blacklist = set()
        self._load_blacklist()

        # ============================================================
        # 连接频率记录（内存存储）
        # 结构：{ip_address: [timestamp1, timestamp2, ...]}
        # 记录每个IP的最近连接时间戳
        # ============================================================
        self._connection_records = defaultdict(list)

        # ============================================================
        # 临时封锁记录
        # 结构：{ip_address: blocked_until_timestamp}
        # ============================================================
        self._blocked_ips = {}

        # ============================================================
        # 线程锁：保护并发访问
        # ============================================================
        self._lock = threading.Lock()

        self.logger.info(
            f"防火墙已初始化 - "
            f"白名单: {len(self._whitelist)}条, "
            f"黑名单: {len(self._blacklist)}条"
        )

    def _load_whitelist(self):
        """从CSV文件加载IP白名单"""
        try:
            records = self.csv_manager.read(Config.IP_WHITELIST_FILE)
            self._whitelist = {r["ip_address"] for r in records if "ip_address" in r}
            self.logger.info(f"已加载 {len(self._whitelist)} 个白名单IP")
        except Exception as e:
            self.logger.warning(f"加载白名单失败: {e}")
            self._whitelist = set()

    def _load_blacklist(self):
        """从CSV文件加载IP黑名单"""
        try:
            records = self.csv_manager.read(Config.IP_BLACKLIST_FILE)
            self._blacklist = {r["ip_address"] for r in records if "ip_address" in r}
            self.logger.info(f"已加载 {len(self._blacklist)} 个黑名单IP")
        except Exception as e:
            self.logger.warning(f"加载黑名单失败: {e}")
            self._blacklist = set()

    def reload_whitelist(self):
        """
        重新加载IP白名单

        管理员可随时修改白名单CSV文件，然后调用此方法刷新。
        """
        with self._lock:
            self._load_whitelist()
        self.logger.info("IP白名单已重新加载")

    def reload_blacklist(self):
        """
        重新加载IP黑名单

        管理员可随时修改黑名单CSV文件，然后调用此方法刷新。
        """
        with self._lock:
            self._load_blacklist()
        self.logger.info("IP黑名单已重新加载")

    def check_ip(self, ip_address):
        """
        检查IP地址是否允许连接

        检查顺序：
        1. 检查是否被临时封锁（异常高频连接）
        2. 检查白名单（如果启用白名单，不在白名单中则拒绝）
        3. 检查黑名单（在黑名单中则拒绝）

        参数：
            ip_address: 客户端IP地址

        返回：
            bool: True 允许连接，False 拒绝连接
        """
        with self._lock:
            # ============================================================
            # 检查临时封锁
            # ============================================================
            if ip_address in self._blocked_ips:
                if time.time() < self._blocked_ips[ip_address]:
                    self.logger.warning(
                        f"[防火墙] IP {ip_address} 处于临时封锁状态，拒绝连接"
                    )
                    return False
                else:
                    # 封锁已过期，移除
                    del self._blocked_ips[ip_address]

            # ============================================================
            # 检查白名单（如果启用）
            # ============================================================
            if Config.IP_WHITELIST_ENABLED and self._whitelist:
                if ip_address not in self._whitelist:
                    self.logger.warning(
                        f"[防火墙] IP {ip_address} 不在白名单中，拒绝连接"
                    )
                    return False

            # ============================================================
            # 检查黑名单
            # ============================================================
            if Config.IP_BLACKLIST_ENABLED and ip_address in self._blacklist:
                self.logger.warning(
                    f"[防火墙] IP {ip_address} 在黑名单中，拒绝连接"
                )
                return False

            return True

    def check_rate_limit(self, ip_address):
        """
        检查连接频率是否超限

        统计指定IP在最近一分钟内的连接次数，
        如果超过阈值则触发封锁。

        参数：
            ip_address: 客户端IP地址

        返回：
            bool: True 允许连接，False 频率超限
        """
        with self._lock:
            now = time.time()
            cutoff = now - 60  # 一分钟前的时间点

            # 清理一分钟前的旧记录
            self._connection_records[ip_address] = [
                t for t in self._connection_records[ip_address]
                if t > cutoff
            ]

            # 记录本次连接时间
            self._connection_records[ip_address].append(now)

            # 检查频率是否超过阈值
            connection_count = len(self._connection_records[ip_address])

            if connection_count > Config.ABUSE_THRESHOLD:
                # 触发封锁
                self._blocked_ips[ip_address] = now + Config.ABUSE_BLOCK_DURATION
                self.logger.warning(
                    f"[风控] IP {ip_address} 连接频率异常 "
                    f"({connection_count}次/分钟)，"
                    f"已封锁 {Config.ABUSE_BLOCK_DURATION}秒"
                )
                # 记录到安全日志
                self._log_security_event(
                    ip_address,
                    "频率超限封锁",
                    f"一分钟内 {connection_count} 次连接"
                )
                return False

            return True

    def _log_security_event(self, ip_address, event_type, detail):
        """
        记录安全事件到专用日志

        参数：
            ip_address: 事件相关的IP地址
            event_type: 事件类型
            detail: 事件详情
        """
        self.logger.warning(
            f"[安全事件] {event_type} | IP: {ip_address} | {detail}"
        )

    def add_to_blacklist(self, ip_address, reason="管理员手动添加"):
        """
        将IP添加到黑名单

        参数：
            ip_address: 要封锁的IP地址
            reason: 封锁原因

        返回：
            bool: 是否添加成功
        """
        with self._lock:
            if ip_address in self._blacklist:
                return False  # 已在黑名单中

            # 添加到内存中的黑名单
            self._blacklist.add(ip_address)

            # 持久化到CSV文件
            self.csv_manager.append(Config.IP_BLACKLIST_FILE, {
                "ip_address": ip_address,
                "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "reason": reason
            })

            self.logger.info(f"已将IP {ip_address} 添加到黑名单，原因：{reason}")
            return True

    def remove_from_blacklist(self, ip_address):
        """
        将IP从黑名单中移除

        参数：
            ip_address: 要解封的IP地址

        返回：
            bool: 是否移除成功
        """
        with self._lock:
            if ip_address not in self._blacklist:
                return False

            self._blacklist.discard(ip_address)
            self.csv_manager.delete(Config.IP_BLACKLIST_FILE, "ip_address", ip_address)

            self.logger.info(f"已将IP {ip_address} 从黑名单中移除")
            return True

    def add_to_whitelist(self, ip_address, note="管理员手动添加"):
        """
        将IP添加到白名单

        参数：
            ip_address: 要添加的IP地址
            note: 备注信息

        返回：
            bool: 是否添加成功
        """
        with self._lock:
            if ip_address in self._whitelist:
                return False

            self._whitelist.add(ip_address)

            self.csv_manager.append(Config.IP_WHITELIST_FILE, {
                "ip_address": ip_address,
                "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "note": note
            })

            self.logger.info(f"已将IP {ip_address} 添加到白名单")
            return True

    def remove_from_whitelist(self, ip_address):
        """
        将IP从白名单中移除

        参数：
            ip_address: 要移除的IP地址

        返回：
            bool: 是否移除成功
        """
        with self._lock:
            if ip_address not in self._whitelist:
                return False

            self._whitelist.discard(ip_address)
            self.csv_manager.delete(Config.IP_WHITELIST_FILE, "ip_address", ip_address)

            self.logger.info(f"已将IP {ip_address} 从白名单中移除")
            return True

    def get_stats(self):
        """
        获取防火墙统计信息

        返回：
            dict: 包含白名单、黑名单、封锁IP等统计信息
        """
        with self._lock:
            return {
                "whitelist_count": len(self._whitelist),
                "blacklist_count": len(self._blacklist),
                "blocked_ips": len(self._blocked_ips),
                "tracked_ips": len(self._connection_records)
            }