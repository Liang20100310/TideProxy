#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy 日志模块

提供统一的日志管理功能：
- 控制台日志输出（带颜色高亮）
- 文件日志记录（支持自动轮转）
- 按模块名称分类日志
- 统一的日志格式和级别控制

使用方式：
    from logger import get_logger
    logger = get_logger("模块名")
    logger.info("这是一条信息日志")
"""

import logging
import logging.handlers
import os
import sys

from config import Config


# ============================================================
# 全局变量：记录初始化状态
# ============================================================
_initialized = False


def setup_logger():
    """
    初始化全局日志系统

    配置日志的输出格式、级别、处理器（Handler）。
    此函数应在程序启动时调用一次。

    功能：
    - 创建日志目录
    - 配置根日志记录器
    - 添加控制台处理器（彩色输出）
    - 添加文件处理器（自动轮转）
    """
    global _initialized

    # 防止重复初始化
    if _initialized:
        return

    # ============================================================
    # 确保日志目录存在
    # ============================================================
    os.makedirs(Config.LOG_DIR, exist_ok=True)

    # ============================================================
    # 获取根日志记录器
    # ============================================================
    root_logger = logging.getLogger("TideProxy")
    root_logger.setLevel(getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO))

    # 清除可能存在的旧处理器
    root_logger.handlers.clear()

    # ============================================================
    # 定义日志格式
    # ============================================================
    formatter = logging.Formatter(
        fmt=Config.LOG_FORMAT,
        datefmt=Config.LOG_DATE_FORMAT
    )

    # ============================================================
    # 添加控制台处理器
    # ============================================================
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO))
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # ============================================================
    # 添加文件处理器（带自动轮转）
    # 当日志文件达到 LOG_MAX_BYTES 时自动创建新文件
    # 保留 LOG_BACKUP_COUNT 个历史日志文件
    # ============================================================
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            filename=Config.LOG_FILE,
            maxBytes=Config.LOG_MAX_BYTES,
            backupCount=Config.LOG_BACKUP_COUNT,
            encoding="utf-8"
        )
        file_handler.setLevel(getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO))
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except Exception as e:
        root_logger.warning(f"无法创建日志文件处理器：{e}")

    _initialized = True


def get_logger(module_name):
    """
    获取指定模块的日志记录器

    参数：
        module_name: 模块名称，用于日志中的来源标识
                     例如："server", "socks5", "auth", "billing"

    返回：
        logging.Logger 实例

    使用示例：
        logger = get_logger("server")
        logger.info("服务器启动")
        logger.error("连接失败", exc_info=True)
    """
    return logging.getLogger(f"TideProxy.{module_name}")