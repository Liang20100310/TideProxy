#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TideProxy 管理员命令行接口模块

提供本地命令行管理功能，支持：
- 代理服务控制（启动/停止/状态）
- 激活码管理（生成/查询/删除/批量）
- 套餐管理（新增/修改/删除）
- 记名账号管理（新增/充值/冻结/解封等）
- MAC绑定管理（绑定/解绑/查询）
- 数据统计查询
- 系统维护操作

所有管理操作均通过此CLI和HTTP API双入口提供。
"""

import asyncio
import sys
from datetime import datetime

from config import Config
from logger import get_logger


class AdminCLI:
    """
    管理员命令行接口

    提供交互式命令行管理界面，管理员可输入命令执行操作。
    使用 asyncio 的 run_in_executor 处理阻塞式输入。
    """

    def __init__(self, account_mgr, activation_mgr, mac_bind,
                 billing, firewall, csv_manager, proxy_server, api_server=None):
        """
        初始化管理员CLI

        参数：
            account_mgr: 记名账号管理器
            activation_mgr: 激活码管理器
            mac_bind: MAC绑定管理器
            billing: 计费系统
            firewall: 防火墙
            csv_manager: CSV数据管理器
            proxy_server: 代理服务器实例
            api_server: HTTP API服务器实例（可选）
        """
        self.account_mgr = account_mgr
        self.activation_mgr = activation_mgr
        self.mac_bind = mac_bind
        self.billing = billing
        self.firewall = firewall
        self.csv_manager = csv_manager
        self.proxy_server = proxy_server
        self.api_server = api_server

        self.logger = get_logger("admin_cli")

        # ============================================================
        # 命令分发表：命令名 -> 处理方法
        # ============================================================
        self._commands = {
            # 系统控制
            "help": self._cmd_help,
            "start": self._cmd_start,
            "stop": self._cmd_stop,
            "restart": self._cmd_restart,
            "status": self._cmd_status,
            "quit": self._cmd_quit,
            "exit": self._cmd_quit,

            # 激活码管理
            "gen_code": self._cmd_gen_code,
            "list_codes": self._cmd_list_codes,
            "del_code": self._cmd_del_code,
            "clear_codes": self._cmd_clear_codes,
            "code_info": self._cmd_code_info,
            "export_codes": self._cmd_export_codes,

            # 套餐管理
            "add_plan": self._cmd_add_plan,
            "list_plans": self._cmd_list_plans,
            "del_plan": self._cmd_del_plan,
            "mod_plan": self._cmd_mod_plan,

            # 记名账号管理
            "add_user": self._cmd_add_user,
            "del_user": self._cmd_del_user,
            "user_info": self._cmd_user_info,
            "list_users": self._cmd_list_users,
            "topup": self._cmd_topup,
            "freeze": self._cmd_freeze,
            "unfreeze": self._cmd_unfreeze,
            "ban": self._cmd_ban,
            "unban": self._cmd_unban,
            "reset_pwd": self._cmd_reset_pwd,
            "set_bw": self._cmd_set_bw,
            "set_traffic": self._cmd_set_traffic,

            # MAC绑定
            "bind_mac": self._cmd_bind_mac,
            "unbind_mac": self._cmd_unbind_mac,
            "list_mac": self._cmd_list_mac,

            # 统计与维护
            "stats": self._cmd_stats,
            "user_stats": self._cmd_user_stats,
            "clear_expired": self._cmd_clear_expired,

            # 计费系统
            "billing_on": self._cmd_billing_on,
            "billing_off": self._cmd_billing_off,

            # 防火墙
            "reload_wl": self._cmd_reload_wl,
            "reload_bl": self._cmd_reload_bl,

            # 多协议管理（新增）
            "proto_status": self._cmd_proto_status,
            "proto_enable": self._cmd_proto_enable,
            "proto_disable": self._cmd_proto_disable,
            "ss_config": self._cmd_ss_config,
            "vmess_config": self._cmd_vmess_config,
            "trojan_config": self._cmd_trojan_config,
            "ws_config": self._cmd_ws_config,
            "add_proto_user": self._cmd_add_proto_user,
            "del_proto_user": self._cmd_del_proto_user,
            "list_proto_users": self._cmd_list_proto_users,
            "sub_url": self._cmd_sub_url,
            "sub_generate": self._cmd_sub_generate,
            "sub_status": self._cmd_sub_status,
        }

        # 命令历史记录
        self._history = []

    async def run(self):
        """
        运行CLI主循环

        异步读取用户输入并执行对应命令。
        使用 run_in_executor 避免阻塞事件循环。
        """
        self.logger.info("管理员命令行已启动，输入 help 查看帮助")
        print("\n[TideProxy] 管理员命令行已就绪，输入 help 查看所有命令\n")

        loop = asyncio.get_event_loop()

        while True:
            try:
                # 在线程池中执行阻塞式输入
                line = await loop.run_in_executor(
                    None, lambda: input("TideProxy> ").strip()
                )

                if not line:
                    continue

                # 记录命令历史
                self._history.append(line)

                # 解析命令和参数
                parts = line.split()
                cmd = parts[0].lower()
                args = parts[1:]

                # 执行命令
                if cmd in self._commands:
                    result = self._commands[cmd](args)
                    print(result)
                else:
                    print(f"[错误] 未知命令: {cmd}，输入 help 查看帮助")

                print()  # 空行分隔

            except EOFError:
                break
            except KeyboardInterrupt:
                print("\n[系统] 使用 quit 或 exit 退出")
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"命令执行异常: {e}", exc_info=True)
                print(f"[错误] 命令执行异常: {e}")

    def execute_command(self, cmd_string):
        """
        执行命令字符串（供API调用）

        参数：
            cmd_string: 完整的命令字符串（如 "gen_code 5 traffic 1GB"）

        返回：
            str: 命令执行结果
        """
        parts = cmd_string.strip().split()
        if not parts:
            return "[错误] 空命令"

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in self._commands:
            return self._commands[cmd](args)
        else:
            return f"[错误] 未知命令: {cmd}"

    # ================================================================
    # 系统控制命令
    # ================================================================

    def _cmd_help(self, args):
        """显示帮助信息"""
        return """
╔══════════════════════════════════════════════════════════════╗
║                TideProxy 管理员命令帮助                      ║
╠══════════════════════════════════════════════════════════════╣
║ 【系统控制】                                                 ║
║   help              - 显示此帮助信息                         ║
║   start             - 启动代理服务                           ║
║   stop              - 停止代理服务                           ║
║   restart           - 重启代理服务                           ║
║   status            - 查看服务状态                           ║
║   quit / exit       - 退出程序                               ║
║                                                              ║
║ 【激活码管理】                                               ║
║   gen_code [数量] [套餐名] [流量] [带宽] [时长] [单位]        ║
║                     - 生成激活码                             ║
║   list_codes        - 列出所有激活码                         ║
║   del_code <码>     - 删除指定激活码                         ║
║   clear_codes       - 清空所有激活码                         ║
║   code_info <码>    - 查看激活码详情                         ║
║   export_codes      - 导出激活码到CSV                        ║
║                                                              ║
║ 【套餐管理】                                                 ║
║   add_plan <名> <流量> <带宽> <时长> [单位]                   ║
║                     - 新增套餐                               ║
║   list_plans        - 列出所有套餐                           ║
║   del_plan <名>     - 删除套餐                               ║
║   mod_plan <名> <字段> <值>                                   ║
║                     - 修改套餐                               ║
║                                                              ║
║ 【记名账号管理】                                             ║
║   add_user <用户名> <密码> [余额] [计费模式]                  ║
║                     - 新增账号                               ║
║   del_user <用户名> - 删除账号                               ║
║   user_info <用户名> - 查看账号详情                          ║
║   list_users        - 列出所有账号                           ║
║   topup <用户名> <金额> - 充值余额                           ║
║   freeze <用户名>   - 冻结账号                               ║
║   unfreeze <用户名> - 解冻账号                               ║
║   ban <用户名>      - 封禁账号                               ║
║   unban <用户名>    - 解封账号                               ║
║   reset_pwd <用户名> <新密码> - 重置密码                     ║
║   set_bw <用户名> <带宽> - 设置带宽限制                      ║
║   set_traffic <用户名> <流量> - 设置流量限制                 ║
║                                                              ║
║ 【MAC绑定】                                                  ║
║   bind_mac <标识> <类型> <MAC>  - 绑定MAC                    ║
║   unbind_mac <标识> <类型>      - 解绑MAC                    ║
║   list_mac                      - 列出所有绑定               ║
║                                                              ║
║ 【统计与维护】                                               ║
║   stats             - 查看全局统计                           ║
║   user_stats <标识> [类型] - 查看用户统计                    ║
║   clear_expired     - 清理过期数据                           ║
║                                                              ║
║ 【计费系统】                                                 ║
║   billing_on        - 开启计费系统                           ║
║   billing_off       - 关闭计费系统                           ║
║                                                              ║
║ 【防火墙】                                                   ║
║   reload_wl         - 重载IP白名单                           ║
║   reload_bl         - 重载IP黑名单                           ║
║                                                              ║
║ 【多协议管理】（新增）                                        ║
║   proto_status      - 查看所有协议状态                       ║
║   proto_enable <协议>  - 启用协议(ss/vmess/ws/sub)           ║
║   proto_disable <协议> - 禁用协议                             ║
║   ss_config [key] [val] - 查看/修改SS配置                    ║
║   vmess_config [k] [v]  - 查看/修改VMess配置                 ║
║   ws_config [k] [v]     - 查看/修改WebSocket配置             ║
║   trojan_config     - 查看Trojan配置                         ║
║   add_proto_user <协议> <用户> <密码/UUID>                    ║
║                     - 添加协议用户                            ║
║   del_proto_user <协议> <用户>  - 删除协议用户                ║
║   list_proto_users  - 列出所有协议用户                       ║
║   sub_url           - 查看订阅链接                            ║
║   sub_generate <格式>  - 生成订阅配置                        ║
║   sub_status        - 查看订阅服务状态                       ║
╚══════════════════════════════════════════════════════════════╝
"""

    def _cmd_start(self, args):
        """启动代理服务"""
        if self.proxy_server._running:
            return "[信息] 代理服务已在运行中"
        # 服务器在主程序中启动，这里仅做状态提示
        return "[信息] 代理服务将在主程序中启动"

    def _cmd_stop(self, args):
        """停止代理服务"""
        if not self.proxy_server._running:
            return "[信息] 代理服务未在运行"
        return "[信息] 请使用 Ctrl+C 或 quit 命令停止服务"

    def _cmd_restart(self, args):
        """重启代理服务"""
        return "[信息] 请使用 stop 然后 start 重启服务"

    def _cmd_status(self, args):
        """查看服务状态"""
        status = self.proxy_server.get_status()
        fw_stats = self.firewall.get_stats()

        return f"""
╔══════════════════════════════════════════╗
║          TideProxy 服务状态              ║
╠══════════════════════════════════════════╣
║  运行状态  : {'运行中' if status['running'] else '已停止'}
║  监听地址  : {status['listen_addr']}
║  活跃连接  : {status['active_connections']} / {status['max_connections']}
║  总连接数  : {status['total_connections']}
║  拒绝连接  : {status['rejected_connections']}
║  商业计费  : {'开启' if status['billing_enabled'] else '关闭'}
║  白名单IP  : {fw_stats['whitelist_count']}
║  黑名单IP  : {fw_stats['blacklist_count']}
║  临时封锁  : {fw_stats['blocked_ips']}
╚══════════════════════════════════════════╝"""

    def _cmd_quit(self, args):
        """退出程序"""
        print("[系统] 正在退出...")
        # 触发程序退出
        import os
        os._exit(0)

    # ================================================================
    # 激活码管理命令
    # ================================================================

    def _cmd_gen_code(self, args):
        """
        生成激活码

        用法: gen_code [数量] [套餐名] [流量GB] [带宽Mbps] [时长] [单位]
        示例: gen_code 5 流量套餐 10 0 30 days
        """
        count = int(args[0]) if len(args) > 0 else 1
        plan_name = args[1] if len(args) > 1 else "默认套餐"
        total_traffic = int(float(args[2]) * Config.BYTES_PER_GB) if len(args) > 2 else 0
        bandwidth = int(float(args[3]) * 1024 * 1024) if len(args) > 3 else 0
        duration = int(args[4]) if len(args) > 4 else 30
        unit = args[5] if len(args) > 5 else "days"

        codes = self.activation_mgr.batch_generate(
            count, plan_name, total_traffic, bandwidth, duration, unit
        )

        result = f"[成功] 已生成 {len(codes)} 个激活码：\n"
        for code, serial in codes:
            result += f"  激活码: {code}  序列号: {serial}\n"
        return result

    def _cmd_list_codes(self, args):
        """列出所有激活码"""
        codes = self.activation_mgr.get_all_codes()
        if not codes:
            return "[信息] 暂无激活码"

        result = f"[信息] 共 {len(codes)} 个激活码：\n"
        result += f"{'激活码':<20} {'状态':<10} {'套餐':<15} {'已用/总量':<20} {'序列号':<25}\n"
        result += "-" * 95 + "\n"

        for c in codes:
            status_map = {
                "inactive": "未激活",
                "activated": "已激活",
                "expired": "已过期",
                "exhausted": "已用尽",
                "banned": "已封禁"
            }
            status = status_map.get(c.get("status", ""), c.get("status", ""))
            used = Config.get_bytes_display(int(c.get("used_traffic", 0)))
            total_val = int(c.get("total_traffic", 0))
            total = Config.get_bytes_display(total_val) if total_val > 0 else "不限"

            result += (
                f"{c.get('code', ''):<20} {status:<10} "
                f"{c.get('plan_name', ''):<15} {used}/{total:<15} "
                f"{c.get('serial_number', ''):<25}\n"
            )

        return result

    def _cmd_del_code(self, args):
        """删除激活码"""
        if not args:
            return "[错误] 用法: del_code <激活码>"
        code = args[0]
        if self.activation_mgr.delete_code(code):
            return f"[成功] 已删除激活码: {code}"
        return f"[错误] 删除失败，激活码不存在: {code}"

    def _cmd_clear_codes(self, args):
        """清空所有激活码"""
        count = self.activation_mgr.clear_all_codes()
        return f"[成功] 已清空 {count} 个激活码"

    def _cmd_code_info(self, args):
        """查看激活码详情"""
        if not args:
            return "[错误] 用法: code_info <激活码>"
        code = args[0]
        info = self.activation_mgr.get_code_info(code)
        if not info:
            return f"[错误] 激活码不存在: {code}"

        status_map = {
            "inactive": "未激活",
            "activated": "已激活",
            "expired": "已过期",
            "exhausted": "已用尽",
            "banned": "已封禁"
        }

        return f"""
╔══════════════════════════════════════════╗
║          激活码详情                      ║
╠══════════════════════════════════════════╣
║  激活码    : {info.get('code', '')}
║  序列号    : {info.get('serial_number', '')}
║  套餐名称  : {info.get('plan_name', '')}
║  状态      : {status_map.get(info.get('status', ''), info.get('status', ''))}
║  已用流量  : {info.get('display_used', '')}
║  流量额度  : {info.get('display_total', '')}
║  带宽限制  : {info.get('bandwidth_limit', '0')} B/s
║  时长限制  : {info.get('duration', '')} {info.get('duration_unit', '')}
║  MAC绑定   : {'是' if info.get('mac_bind_enabled') == 'true' else '否'}
║  绑定MAC   : {info.get('mac_address', '无')}
║  创建时间  : {info.get('created_at', '')}
║  激活时间  : {info.get('activated_at', '未激活')}
║  最后访问  : {info.get('last_access', '无')}
╚══════════════════════════════════════════╝"""

    def _cmd_export_codes(self, args):
        """导出激活码"""
        codes = self.activation_mgr.get_all_codes()
        if not codes:
            return "[信息] 暂无激活码可导出"

        export_file = f"data/export_codes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.csv_manager.write(export_file, codes)
        return f"[成功] 已导出 {len(codes)} 个激活码到 {export_file}"

    # ================================================================
    # 套餐管理命令
    # ================================================================

    def _cmd_add_plan(self, args):
        """新增套餐"""
        if len(args) < 4:
            return "[错误] 用法: add_plan <名称> <流量GB> <带宽Mbps> <时长> [单位]"

        plan = {
            "plan_name": args[0],
            "total_traffic": str(int(float(args[1]) * Config.BYTES_PER_GB)),
            "bandwidth_limit": str(int(float(args[2]) * 1024 * 1024)),
            "duration": args[3],
            "duration_unit": args[4] if len(args) > 4 else "days",
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self.csv_manager.append(Config.PLANS_FILE, plan)
        return f"[成功] 已新增套餐: {args[0]}"

    def _cmd_list_plans(self, args):
        """列出所有套餐"""
        plans = self.csv_manager.read(Config.PLANS_FILE)
        if not plans:
            return "[信息] 暂无套餐"

        result = f"[信息] 共 {len(plans)} 个套餐：\n"
        for p in plans:
            result += (
                f"  {p.get('plan_name', '')}: "
                f"流量={Config.get_bytes_display(int(p.get('total_traffic', 0)))}, "
                f"带宽={int(p.get('bandwidth_limit', 0)) / 1024 / 1024:.1f}Mbps, "
                f"时长={p.get('duration', '')} {p.get('duration_unit', '')}\n"
            )
        return result

    def _cmd_del_plan(self, args):
        """删除套餐"""
        if not args:
            return "[错误] 用法: del_plan <套餐名>"
        if self.csv_manager.delete(Config.PLANS_FILE, "plan_name", args[0]):
            return f"[成功] 已删除套餐: {args[0]}"
        return f"[错误] 套餐不存在: {args[0]}"

    def _cmd_mod_plan(self, args):
        """修改套餐"""
        if len(args) < 3:
            return "[错误] 用法: mod_plan <套餐名> <字段> <值>"
        plan_name, field, value = args[0], args[1], args[2]
        if self.csv_manager.update(Config.PLANS_FILE, "plan_name", plan_name, {field: value}):
            return f"[成功] 已修改套餐 {plan_name} 的 {field} 为 {value}"
        return f"[错误] 套餐不存在: {plan_name}"

    # ================================================================
    # 记名账号管理命令
    # ================================================================

    def _cmd_add_user(self, args):
        """新增记名账号"""
        if len(args) < 2:
            return "[错误] 用法: add_user <用户名> <密码> [余额] [计费模式]"

        username = args[0]
        password = args[1]
        balance = float(args[2]) if len(args) > 2 else 0
        billing_mode = args[3] if len(args) > 3 else "traffic"

        success, msg = self.account_mgr.create_account(
            username, password, balance, billing_mode
        )
        if success:
            return f"[成功] 已创建账号: {username}，余额: {balance:.2f}"
        return f"[错误] {msg}"

    def _cmd_del_user(self, args):
        """删除账号"""
        if not args:
            return "[错误] 用法: del_user <用户名>"
        if self.account_mgr.delete_account(args[0]):
            return f"[成功] 已删除账号: {args[0]}"
        return f"[错误] 账号不存在: {args[0]}"

    def _cmd_user_info(self, args):
        """查看账号详情"""
        if not args:
            return "[错误] 用法: user_info <用户名>"
        info = self.account_mgr.get_account(args[0])
        if not info:
            return f"[错误] 账号不存在: {args[0]}"

        status_map = {
            "active": "正常",
            "frozen": "已冻结",
            "banned": "已封禁",
            "expired": "已过期",
            "over_traffic": "流量超额"
        }

        return f"""
╔══════════════════════════════════════════╗
║          账号详情                        ║
╠══════════════════════════════════════════╣
║  用户名    : {info.get('username', '')}
║  状态      : {status_map.get(info.get('status', ''), info.get('status', ''))}
║  余额      : {info.get('balance', '0')}
║  计费模式  : {info.get('billing_mode', '')}
║  带宽限制  : {info.get('bandwidth_limit', '0')} B/s
║  流量限制  : {info.get('traffic_limit', '0')} B
║  已用流量  : {info.get('total_traffic', '0')} B
║  MAC绑定   : {'是' if info.get('mac_bind_enabled') == 'true' else '否'}
║  绑定MAC   : {info.get('mac_address', '无')}
║  创建时间  : {info.get('created_at', '')}
║  最后登录  : {info.get('last_login', '从未登录')}
╚══════════════════════════════════════════╝"""

    def _cmd_list_users(self, args):
        """列出所有账号"""
        users = self.account_mgr.get_all_accounts()
        if not users:
            return "[信息] 暂无记名账号"

        result = f"[信息] 共 {len(users)} 个账号：\n"
        result += f"{'用户名':<15} {'状态':<8} {'余额':<12} {'计费模式':<10} {'已用流量':<15}\n"
        result += "-" * 65 + "\n"

        status_map = {
            "active": "正常",
            "frozen": "冻结",
            "banned": "封禁",
            "expired": "过期"
        }

        for u in users:
            status = status_map.get(u.get("status", ""), u.get("status", ""))
            traffic = Config.get_bytes_display(int(u.get("total_traffic", 0)))
            result += (
                f"{u.get('username', ''):<15} {status:<8} "
                f"{u.get('balance', '0'):<12} {u.get('billing_mode', ''):<10} "
                f"{traffic:<15}\n"
            )

        return result

    def _cmd_topup(self, args):
        """充值余额"""
        if len(args) < 2:
            return "[错误] 用法: topup <用户名> <金额>"
        username = args[0]
        amount = float(args[1])

        success, msg, new_balance = self.billing.add_balance(username, amount)
        if success:
            return f"[成功] {msg}，当前余额: {new_balance:.2f}"
        return f"[错误] {msg}"

    def _cmd_freeze(self, args):
        """冻结账号"""
        if not args:
            return "[错误] 用法: freeze <用户名>"
        if self.account_mgr.freeze_account(args[0]):
            return f"[成功] 已冻结账号: {args[0]}"
        return f"[错误] 操作失败"

    def _cmd_unfreeze(self, args):
        """解冻账号"""
        if not args:
            return "[错误] 用法: unfreeze <用户名>"
        if self.account_mgr.unfreeze_account(args[0]):
            return f"[成功] 已解冻账号: {args[0]}"
        return f"[错误] 操作失败"

    def _cmd_ban(self, args):
        """封禁账号"""
        if not args:
            return "[错误] 用法: ban <用户名>"
        if self.account_mgr.ban_account(args[0]):
            return f"[成功] 已封禁账号: {args[0]}"
        return f"[错误] 操作失败"

    def _cmd_unban(self, args):
        """解封账号"""
        if not args:
            return "[错误] 用法: unban <用户名>"
        if self.account_mgr.unban_account(args[0]):
            return f"[成功] 已解封账号: {args[0]}"
        return f"[错误] 操作失败"

    def _cmd_reset_pwd(self, args):
        """重置密码"""
        if len(args) < 2:
            return "[错误] 用法: reset_pwd <用户名> <新密码>"
        if self.account_mgr.admin_reset_password(args[0], args[1]):
            return f"[成功] 已重置 {args[0]} 的密码"
        return f"[错误] 操作失败"

    def _cmd_set_bw(self, args):
        """设置带宽限制"""
        if len(args) < 2:
            return "[错误] 用法: set_bw <用户名> <带宽Mbps>"
        limit = int(float(args[1]) * 1024 * 1024)
        if self.account_mgr.set_bandwidth_limit(args[0], limit):
            return f"[成功] 已设置 {args[0]} 带宽限制: {args[1]} Mbps"
        return f"[错误] 操作失败"

    def _cmd_set_traffic(self, args):
        """设置流量限制"""
        if len(args) < 2:
            return "[错误] 用法: set_traffic <用户名> <流量GB>"
        limit = int(float(args[1]) * Config.BYTES_PER_GB)
        if self.account_mgr.set_traffic_limit(args[0], limit):
            return f"[成功] 已设置 {args[0]} 流量限制: {args[1]} GB"
        return f"[错误] 操作失败"

    # ================================================================
    # MAC绑定管理命令
    # ================================================================

    def _cmd_bind_mac(self, args):
        """绑定MAC地址"""
        if len(args) < 3:
            return "[错误] 用法: bind_mac <标识> <类型(activation/account)> <MAC地址>"
        success, msg = self.mac_bind.bind_mac(args[0], args[1], args[2])
        if success:
            return f"[成功] {msg}"
        return f"[错误] {msg}"

    def _cmd_unbind_mac(self, args):
        """解绑MAC地址"""
        if len(args) < 2:
            return "[错误] 用法: unbind_mac <标识> <类型>"
        if self.mac_bind.unbind_mac(args[0], args[1]):
            return f"[成功] 已解除MAC绑定"
        return f"[错误] 操作失败"

    def _cmd_list_mac(self, args):
        """列出所有MAC绑定"""
        bindings = self.mac_bind.get_all_bindings()
        if not bindings:
            return "[信息] 暂无MAC绑定记录"

        result = f"[信息] 共 {len(bindings)} 条绑定记录：\n"
        for b in bindings:
            result += (
                f"  {b.get('identifier', '')} ({b.get('account_type', '')}): "
                f"{b.get('mac_address', '')} - 绑定于 {b.get('bound_at', '')}\n"
            )
        return result

    # ================================================================
    # 统计与维护命令
    # ================================================================

    def _cmd_stats(self, args):
        """查看全局统计"""
        stats = self.billing.get_global_stats()
        sessions = self.billing.get_active_sessions()
        ac_count = self.activation_mgr.get_code_count()
        ac_active = self.activation_mgr.get_code_count("activated")
        user_count = self.account_mgr.get_account_count()
        user_active = self.account_mgr.get_account_count("active")

        return f"""
╔══════════════════════════════════════════╗
║          TideProxy 全局统计              ║
╠══════════════════════════════════════════╣
║  总上行流量  : {stats.get('display_upload', '0 B')}
║  总下行流量  : {stats.get('display_download', '0 B')}
║  总流量      : {stats.get('display_total', '0 B')}
║  总在线时长  : {stats.get('display_duration', '0秒')}
║  总会话数    : {stats.get('total_sessions', 0)}
║  活跃会话    : {stats.get('active_sessions', 0)}
║  激活码总数  : {ac_count} (活跃: {ac_active})
║  账号总数    : {user_count} (活跃: {user_active})
╚══════════════════════════════════════════╝"""

    def _cmd_user_stats(self, args):
        """查看用户统计"""
        if not args:
            return "[错误] 用法: user_stats <标识> [类型]"

        identifier = args[0]
        account_type = args[1] if len(args) > 1 else "all"

        stats = self.billing.get_user_stats(identifier, account_type)
        if not stats:
            return f"[信息] 未找到 {identifier} 的统计数据"

        return f"""
╔══════════════════════════════════════════╗
║          用户统计: {identifier}
╠══════════════════════════════════════════╣
║  总上行流量  : {stats.get('display_upload', '0 B')}
║  总下行流量  : {stats.get('display_download', '0 B')}
║  总流量      : {stats.get('display_total', '0 B')}
║  总在线时长  : {stats.get('display_duration', '0秒')}
║  会话数      : {stats.get('session_count', 0)}
╚══════════════════════════════════════════╝"""

    def _cmd_clear_expired(self, args):
        """清理过期数据"""
        # 清理过期激活码
        codes = self.activation_mgr.get_all_codes()
        expired_count = 0
        for code in codes:
            status = code.get("status", "")
            if status in ("expired", "exhausted"):
                expired_count += 1

        return f"[成功] 已扫描数据，发现 {expired_count} 个过期/已用尽的激活码"

    # ================================================================
    # 计费系统控制命令
    # ================================================================

    def _cmd_billing_on(self, args):
        """开启计费系统"""
        Config.BILLING_ENABLED = True
        return "[成功] 商业计费系统已开启"

    def _cmd_billing_off(self, args):
        """关闭计费系统"""
        Config.BILLING_ENABLED = False
        return "[成功] 商业计费系统已关闭（所有用户无需认证即可使用）"

    # ================================================================
    # 防火墙命令
    # ================================================================

    def _cmd_reload_wl(self, args):
        """重载IP白名单"""
        self.firewall.reload_whitelist()
        return "[成功] IP白名单已重载"

    def _cmd_reload_bl(self, args):
        """重载IP黑名单"""
        self.firewall.reload_blacklist()
        return "[成功] IP黑名单已重载"

    # ================================================================
    # 多协议管理命令（新增）
    # ================================================================

    def _cmd_proto_status(self, args):
        """查看所有协议状态"""
        status = self.proxy_server.get_status()

        result = """
╔══════════════════════════════════════════════════════════════╗
║              TideProxy 多协议服务状态                        ║
╠══════════════════════════════════════════════════════════════╣
║  【基础代理协议】                                             ║
║  SOCKS5/HTTP  ：{addr}                                      ║
║                                                              ║
║  【Shadowsocks】                                             ║
║  状态        ：{ss_status}                                    ║
║  监听地址    ：{ss_addr}                                      ║
║  加密方式    ：{ss_method}                                    ║
║  用户数      ：{ss_users}                                     ║
║                                                              ║
║  【VMess】                                                   ║
║  状态        ：{vmess_status}                                 ║
║  监听地址    ：{vmess_addr}                                   ║
║  用户数      ：{vmess_users}                                  ║
║                                                              ║
║  【WebSocket传输】                                           ║
║  状态        ：{ws_status}                                    ║
║  监听地址    ：{ws_addr}                                      ║
║  WS路径      ：{ws_path}                                     ║
║                                                              ║
║  【订阅服务】                                                 ║
║  状态        ：{sub_status}                                   ║
║  订阅地址    ：{sub_addr}                                     ║
╚══════════════════════════════════════════════════════════════╝
""".format(
            addr=status["listen_addr"],
            ss_status="运行中" if status["shadowsocks"]["enabled"] else "未启用",
            ss_addr=status["shadowsocks"]["addr"],
            ss_method=status["shadowsocks"]["method"],
            ss_users=status["shadowsocks"]["users"],
            vmess_status="运行中" if status["vmess"]["enabled"] else "未启用",
            vmess_addr=status["vmess"]["addr"],
            vmess_users=status["vmess"]["users"],
            ws_status="运行中" if status["websocket"]["enabled"] else "未启用",
            ws_addr=status["websocket"]["addr"],
            ws_path=status["websocket"]["path"],
            sub_status="运行中" if status["subscription"]["enabled"] else "未启用",
            sub_addr=status["subscription"]["addr"],
        )
        return result

    def _cmd_proto_enable(self, args):
        """启用协议"""
        if not args:
            return "[错误] 用法: proto_enable <ss|vmess|ws|sub>"

        proto = args[0].lower()
        if proto == "ss":
            Config.SS_ENABLED = True
            return "[成功] Shadowsocks协议已启用（需重启服务生效）"
        elif proto == "vmess":
            Config.VMESS_ENABLED = True
            return "[成功] VMess协议已启用（需重启服务生效）"
        elif proto == "ws":
            Config.WS_ENABLED = True
            return "[成功] WebSocket传输已启用（需重启服务生效）"
        elif proto == "sub":
            Config.SUB_ENABLED = True
            return "[成功] 订阅服务已启用（需重启服务生效）"
        else:
            return "[错误] 未知协议: {proto}，支持: ss, vmess, ws, sub"

    def _cmd_proto_disable(self, args):
        """禁用协议"""
        if not args:
            return "[错误] 用法: proto_disable <ss|vmess|ws|sub>"

        proto = args[0].lower()
        if proto == "ss":
            Config.SS_ENABLED = False
            return "[成功] Shadowsocks协议已禁用"
        elif proto == "vmess":
            Config.VMESS_ENABLED = False
            return "[成功] VMess协议已禁用"
        elif proto == "ws":
            Config.WS_ENABLED = False
            return "[成功] WebSocket传输已禁用"
        elif proto == "sub":
            Config.SUB_ENABLED = False
            return "[成功] 订阅服务已禁用"
        else:
            return "[错误] 未知协议: {proto}"

    def _cmd_ss_config(self, args):
        """查看/修改Shadowsocks配置"""
        if not args:
            return f"""Shadowsocks配置：
  启用状态：{'开启' if Config.SS_ENABLED else '关闭'}
  监听地址：{Config.SS_HOST}:{Config.SS_PORT}
  加密方式：{Config.SS_METHOD}
  密码    ：{'*' * len(Config.SS_PASSWORD)}
  支持加密：{', '.join(Config.SS_SUPPORTED_METHODS)}"""

        # 修改配置
        if len(args) >= 2:
            key, value = args[0], args[1]
            if key == "port":
                Config.SS_PORT = int(value)
                return f"[成功] SS端口已设置为 {value}（需重启）"
            elif key == "method":
                if value in Config.SS_SUPPORTED_METHODS:
                    Config.SS_METHOD = value
                    return f"[成功] SS加密方式已设置为 {value}"
                else:
                    return f"[错误] 不支持的加密方式: {value}"
            elif key == "password":
                Config.SS_PASSWORD = value
                return "[成功] SS密码已更新"
        return "[错误] 用法: ss_config [port|method|password] [值]"

    def _cmd_vmess_config(self, args):
        """查看/修改VMess配置"""
        if not args:
            return f"""VMess配置：
  启用状态：{'开启' if Config.VMESS_ENABLED else '关闭'}
  监听地址：{Config.VMESS_HOST}:{Config.VMESS_PORT}
  UUID    ：{Config.VMESS_UUID or '(自动生成)'}
  AlterID ：{Config.VMESS_ALTER_ID}
  加密方式：{Config.VMESS_SECURITY}"""

        if len(args) >= 2:
            key, value = args[0], args[1]
            if key == "port":
                Config.VMESS_PORT = int(value)
                return f"[成功] VMess端口已设置为 {value}"
            elif key == "uuid":
                Config.VMESS_UUID = value
                return f"[成功] VMess UUID已设置"
            elif key == "alterid":
                Config.VMESS_ALTER_ID = int(value)
                return f"[成功] VMess AlterID已设置为 {value}"
        return "[错误] 用法: vmess_config [port|uuid|alterid] [值]"

    def _cmd_trojan_config(self, args):
        """查看Trojan配置"""
        return f"""Trojan配置：
  启用状态：{'开启' if Config.TROJAN_ENABLED else '关闭'}
  监听地址：{Config.TROJAN_HOST}:{Config.TROJAN_PORT}
  证书路径：{Config.TROJAN_CERT_PATH or '(未配置)'}
  注意：Trojan强制要求TLS证书"""

    def _cmd_ws_config(self, args):
        """查看/修改WebSocket配置"""
        if not args:
            return f"""WebSocket传输配置：
  启用状态：{'开启' if Config.WS_ENABLED else '关闭'}
  监听地址：{Config.WS_HOST}:{Config.WS_PORT}
  WS路径  ：{Config.WS_PATH}
  TLS状态 ：{'开启' if Config.WS_TLS_ENABLED else '关闭'}"""

        if len(args) >= 2:
            key, value = args[0], args[1]
            if key == "port":
                Config.WS_PORT = int(value)
                return f"[成功] WS端口已设置为 {value}"
            elif key == "path":
                Config.WS_PATH = value
                return f"[成功] WS路径已设置为 {value}"
        return "[错误] 用法: ws_config [port|path] [值]"

    def _cmd_add_proto_user(self, args):
        """添加协议用户"""
        if len(args) < 3:
            return "[错误] 用法: add_proto_user <协议> <用户名> <密码/UUID>\n  支持协议: ss, vmess"

        proto, username, credential = args[0], args[1], args[2]

        if proto == "ss":
            if not self.proxy_server.ss_handler:
                return "[错误] Shadowsocks协议未启用"
            method = args[3] if len(args) > 3 else Config.SS_METHOD
            self.proxy_server.ss_handler.add_user(username, credential, method)
            return f"[成功] 已添加SS用户: {username} (加密: {method})"

        elif proto == "vmess":
            if not self.proxy_server.vmess_handler:
                return "[错误] VMess协议未启用"
            uuid = self.proxy_server.vmess_handler.add_user(username, credential)
            return f"[成功] 已添加VMess用户: {username} (UUID: {uuid})"

        else:
            return "[错误] 未知协议: {proto}，支持: ss, vmess"

    def _cmd_del_proto_user(self, args):
        """删除协议用户"""
        if len(args) < 2:
            return "[错误] 用法: del_proto_user <协议> <用户名>"

        proto, username = args[0], args[1]

        if proto == "ss":
            if self.proxy_server.ss_handler and self.proxy_server.ss_handler.remove_user(username):
                return f"[成功] 已删除SS用户: {username}"
            return f"[错误] 用户不存在或SS未启用"

        elif proto == "vmess":
            if self.proxy_server.vmess_handler and self.proxy_server.vmess_handler.remove_user(username):
                return f"[成功] 已删除VMess用户: {username}"
            return f"[错误] 用户不存在或VMess未启用"

        return "[错误] 未知协议"

    def _cmd_list_proto_users(self, args):
        """列出协议用户"""
        result = ""

        if self.proxy_server.ss_handler:
            ss_users = self.proxy_server.ss_handler.get_all_users()
            result += f"\n【Shadowsocks用户】共 {len(ss_users)} 个：\n"
            for name, info in ss_users.items():
                result += f"  {name}: 加密={info['method']}, 密码={'*' * len(info['password'])}\n"

        if self.proxy_server.vmess_handler:
            vmess_users = self.proxy_server.vmess_handler.get_all_users()
            result += f"\n【VMess用户】共 {len(vmess_users)} 个：\n"
            for name, info in vmess_users.items():
                result += f"  {name}: UUID={info['uuid']}, AlterID={info['alter_id']}\n"

        if not result:
            return "[信息] 暂无协议用户配置"

        return result

    def _cmd_sub_url(self, args):
        """查看订阅链接"""
        if not Config.SUB_ENABLED:
            return "[错误] 订阅服务未启用"

        base = f"http://{Config.SUB_SERVER_ADDR or 'your-server.com'}:{Config.SUB_PORT}"
        token = Config.SUB_SECRET

        return f"""订阅链接：
  Clash    : {base}{Config.SUB_PATH}/{token}/clash
  Surge    : {base}{Config.SUB_PATH}/{token}/surge
  SIP008   : {base}{Config.SUB_PATH}/{token}/sip008
  V2RayN   : {base}{Config.SUB_PATH}/{token}/v2ray
  Hiddify  : {base}{Config.SUB_PATH}/{token}/hiddify
  URI列表  : {base}{Config.SUB_PATH}/{token}/uri
  首页     : {base}{Config.SUB_PATH}/{token}/"""

    def _cmd_sub_generate(self, args):
        """手动生成订阅配置"""
        if not Config.SUB_ENABLED:
            return "[错误] 订阅服务未启用"

        if not args:
            return "[错误] 用法: sub_generate <clash|surge|sip008|v2ray|hiddify>"

        fmt = args[0].lower()
        if fmt == "clash":
            return self.proxy_server.sub_server.generate_clash_config()
        elif fmt == "surge":
            return self.proxy_server.sub_server.generate_surge_config()
        elif fmt == "sip008":
            return self.proxy_server.sub_server.generate_sip008_config()
        elif fmt == "v2ray":
            return self.proxy_server.sub_server.generate_v2ray_config()
        elif fmt == "hiddify":
            return self.proxy_server.sub_server.generate_hiddify_config()
        else:
            return f"[错误] 未知格式: {fmt}"

    def _cmd_sub_status(self, args):
        """查看订阅服务状态"""
        return f"""订阅服务状态：
  启用状态：{'开启' if Config.SUB_ENABLED else '关闭'}
  监听地址：{Config.SUB_HOST}:{Config.SUB_PORT}
  订阅路径：{Config.SUB_PATH}
  服务器IP：{Config.SUB_SERVER_ADDR or '(未配置)'}
  服务名称：{Config.SUB_SERVER_NAME}
  支持格式：Clash, Surge, SIP008, V2RayN, Hiddify"""