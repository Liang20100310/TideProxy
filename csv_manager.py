#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy CSV数据管理模块

提供线程安全的CSV文件读写操作，是所有数据持久化的基础层。

核心功能：
- 线程安全的读写操作（使用线程锁）
- 自动创建CSV文件和表头
- 支持查询、更新、删除、追加操作
- 统计和条件查询支持
- UTF-8编码，支持中文字段

设计原则：
- 所有数据通过CSV文件持久化，不引入外部数据库
- 每次操作都直接读写文件，确保数据一致性
- 使用 threading.Lock 保证并发安全
"""

import csv
import os
import threading
from datetime import datetime

from config import Config
from logger import get_logger


class CSVManager:
    """
    CSV数据管理器

    线程安全的CSV文件操作封装，提供：
    - read(): 读取全部记录
    - write(): 写入全部记录（覆盖）
    - append(): 追加单条记录
    - update(): 更新指定记录
    - delete(): 删除指定记录
    - query(): 条件查询
    - count(): 统计记录数
    """

    def __init__(self):
        """初始化CSV管理器，创建线程锁"""
        # 线程锁：保证同一时间只有一个线程在操作CSV文件
        self._lock = threading.Lock()
        self.logger = get_logger("csv_manager")

    def read(self, file_path):
        """
        读取CSV文件的全部记录

        参数：
            file_path: CSV文件路径

        返回：
            list[dict]: 记录列表，每条记录为一个字典
                        如果文件不存在或为空，返回空列表

        示例：
            records = csv_manager.read("data/accounts.csv")
            for record in records:
                print(record["username"])
        """
        with self._lock:
            # 如果文件不存在，返回空列表
            if not os.path.exists(file_path):
                return []

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    return list(reader)
            except Exception as e:
                self.logger.error(f"读取CSV文件失败 [{file_path}]: {e}")
                return []

    def write(self, file_path, records):
        """
        将记录列表写入CSV文件（覆盖原有内容）

        参数：
            file_path: CSV文件路径
            records: 记录列表，每条记录为一个字典

        注意：
            此操作会覆盖文件的全部内容！
            如果记录列表为空，将只写入表头。
        """
        with self._lock:
            if not records:
                # 空记录时只写入表头（如果文件已存在则保留表头）
                if os.path.exists(file_path):
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            reader = csv.reader(f)
                            headers = next(reader, [])
                        with open(file_path, "w", newline="", encoding="utf-8") as f:
                            writer = csv.writer(f)
                            writer.writerow(headers)
                    except Exception as e:
                        self.logger.error(f"写入CSV文件失败 [{file_path}]: {e}")
                return

            try:
                # 确保目录存在
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                headers = list(records[0].keys())
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=headers)
                    writer.writeheader()
                    writer.writerows(records)
            except Exception as e:
                self.logger.error(f"写入CSV文件失败 [{file_path}]: {e}")

    def append(self, file_path, record):
        """
        向CSV文件追加单条记录

        参数：
            file_path: CSV文件路径
            record: 要追加的记录（字典）

        如果文件不存在，会自动创建文件并写入表头。
        """
        with self._lock:
            try:
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                file_exists = os.path.exists(file_path) and os.path.getsize(file_path) > 0

                with open(file_path, "a", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=list(record.keys()))
                    if not file_exists:
                        writer.writeheader()
                    writer.writerow(record)
            except Exception as e:
                self.logger.error(f"追加CSV记录失败 [{file_path}]: {e}")

    def update(self, file_path, key_field, key_value, new_record):
        """
        更新CSV文件中指定字段匹配的记录

        参数：
            file_path: CSV文件路径
            key_field: 用于匹配的字段名（如 "username"）
            key_value: 要匹配的字段值
            new_record: 更新后的记录数据（字典）

        返回：
            bool: 是否找到并更新了记录

        注意：
            如果有多条记录匹配，只更新第一条。
        """
        with self._lock:
            try:
                records = []
                updated = False

                # 读取现有记录
                if os.path.exists(file_path):
                    with open(file_path, "r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            if not updated and row.get(key_field) == str(key_value):
                                # 找到匹配记录，进行更新
                                row.update(new_record)
                                updated = True
                            records.append(row)

                if not updated:
                    return False

                # 写回所有记录
                if records:
                    headers = list(records[0].keys())
                    with open(file_path, "w", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(f, fieldnames=headers)
                        writer.writeheader()
                        writer.writerows(records)

                return True

            except Exception as e:
                self.logger.error(f"更新CSV记录失败 [{file_path}]: {e}")
                return False

    def delete(self, file_path, key_field, key_value):
        """
        删除CSV文件中指定字段匹配的记录

        参数：
            file_path: CSV文件路径
            key_field: 用于匹配的字段名
            key_value: 要匹配的字段值

        返回：
            bool: 是否找到并删除了记录
        """
        with self._lock:
            try:
                if not os.path.exists(file_path):
                    return False

                # 读取所有记录，排除匹配的
                records = []
                deleted = False
                with open(file_path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if not deleted and row.get(key_field) == str(key_value):
                            deleted = True
                            continue  # 跳过要删除的记录
                        records.append(row)

                if not deleted:
                    return False

                # 写回剩余记录
                if records:
                    headers = list(records[0].keys())
                    with open(file_path, "w", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(f, fieldnames=headers)
                        writer.writeheader()
                        writer.writerows(records)
                else:
                    # 没有记录了，只保留表头
                    with open(file_path, "r", encoding="utf-8") as f:
                        reader = csv.reader(f)
                        headers = next(reader, [])
                    with open(file_path, "w", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(headers)

                return True

            except Exception as e:
                self.logger.error(f"删除CSV记录失败 [{file_path}]: {e}")
                return False

    def query(self, file_path, key_field, key_value):
        """
        查询CSV文件中指定字段匹配的记录

        参数：
            file_path: CSV文件路径
            key_field: 用于匹配的字段名
            key_value: 要匹配的字段值

        返回：
            list[dict]: 所有匹配的记录列表
        """
        with self._lock:
            try:
                if not os.path.exists(file_path):
                    return []

                results = []
                with open(file_path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get(key_field) == str(key_value):
                            results.append(row)

                return results

            except Exception as e:
                self.logger.error(f"查询CSV记录失败 [{file_path}]: {e}")
                return []

    def query_one(self, file_path, key_field, key_value):
        """
        查询CSV文件中指定字段匹配的第一条记录

        参数：
            file_path: CSV文件路径
            key_field: 用于匹配的字段名
            key_value: 要匹配的字段值

        返回：
            dict 或 None: 匹配的记录，未找到返回 None
        """
        results = self.query(file_path, key_field, key_value)
        return results[0] if results else None

    def count(self, file_path, key_field=None, key_value=None):
        """
        统计CSV文件中的记录数

        参数：
            file_path: CSV文件路径
            key_field: 可选，用于条件过滤的字段名
            key_value: 可选，用于条件过滤的字段值

        返回：
            int: 记录数量

        如果指定 key_field 和 key_value，则只统计匹配的记录。
        """
        with self._lock:
            try:
                if not os.path.exists(file_path):
                    return 0

                count = 0
                with open(file_path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if key_field is None or row.get(key_field) == str(key_value):
                            count += 1

                return count

            except Exception as e:
                self.logger.error(f"统计CSV记录失败 [{file_path}]: {e}")
                return 0

    def get_all(self, file_path):
        """
        获取CSV文件全部记录（read的别名，语义更清晰）

        参数：
            file_path: CSV文件路径

        返回：
            list[dict]: 全部记录列表
        """
        return self.read(file_path)

    def clear(self, file_path):
        """
        清空CSV文件内容（保留表头）

        参数：
            file_path: CSV文件路径
        """
        with self._lock:
            try:
                if not os.path.exists(file_path):
                    return

                with open(file_path, "r", encoding="utf-8") as f:
                    reader = csv.reader(f)
                    headers = next(reader, [])

                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)

            except Exception as e:
                self.logger.error(f"清空CSV文件失败 [{file_path}]: {e}")

    def file_exists(self, file_path):
        """
        检查CSV文件是否存在

        参数：
            file_path: CSV文件路径

        返回：
            bool: 文件是否存在
        """
        return os.path.exists(file_path)