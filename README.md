# TideProxy（潮汐代理）

**项目名称：** TideProxy（潮汐代理）  
**项目作者：** Yicheng Liang  
**开源协议：** GNU General Public License v3.0 (GPL3.0)  
**版本号：** v1.0.0

> 本项目为开源项目，允许二次修改、分发、商用，但衍生作品必须同样遵循GPL3.0协议公开源码。

---

## 📖 项目介绍

TideProxy 是一款基于 Python asyncio 异步框架开发的高性能代理服务软件，对标 CCProxy 等商用代理服务，提供完整的商业化运营能力。

### 核心特性

- **双协议支持**：完整实现 HTTP/HTTPS CONNECT 代理和 SOCKS5 全协议代理
- **双账户体系**：不记名激活码账户 + 记名正式用户账号，独立管理
- **双计费模式**：流量计费 + 带宽时长计费，自由切换
- **双管理入口**：本地管理员CLI + HTTP API远程管理，操作完全对齐
- **全异步架构**：基于 asyncio 实现高并发TCP连接，单进程支持数百连接
- **CSV纯文件存储**：所有数据持久化为CSV文件，无需外部数据库
- **完整商业化**：激活码系统、套餐管理、余额充值、MAC绑定防共享、风控机制

### 技术栈

- **语言**：Python 3.8+
- **异步框架**：asyncio（标准库）
- **数据存储**：CSV文件（标准库csv模块）
- **日志系统**：logging + RotatingFileHandler
- **API服务**：http.server（标准库）
- **外部依赖**：零依赖，仅使用Python标准库

---

## 📁 项目目录结构

```
TideProxy/
├── tideproxy.py            # 主入口脚本（唯一启动文件）
├── config.py               # 全局配置模块
├── logger.py               # 日志系统模块
├── csv_manager.py          # CSV数据管理模块
├── firewall.py             # 防火墙（IP黑白名单、频率控制）
├── server.py               # 核心代理服务器（协议检测、连接管理）
├── requirements.txt        # Python依赖清单
├── README.md               # 项目自述文件（本文件）
├── DOC.md                  # 官方使用文档
│
├── protocol/               # 协议解析层
│   ├── __init__.py
│   ├── socks5.py           # SOCKS5协议处理器
│   └── http_proxy.py       # HTTP/HTTPS CONNECT协议处理器
│
├── auth/                   # 用户认证层
│   ├── __init__.py
│   ├── activation.py       # 激活码认证管理
│   ├── account.py          # 记名账号认证管理
│   └── mac_bind.py         # MAC地址绑定管理
│
├── billing/                # 计费统计层
│   ├── __init__.py
│   └── billing_system.py   # 计费统计系统
│
├── admin/                  # 管理员接口层
│   ├── __init__.py
│   ├── cli.py              # 本地管理员命令行接口
│   └── api.py              # HTTP API管理接口
│
├── data/                   # 数据存储目录（CSV文件）
│   ├── accounts.csv        # 记名账号数据
│   ├── activation_codes.csv # 激活码数据
│   ├── mac_bindings.csv    # MAC绑定记录
│   ├── traffic_logs.csv    # 流量统计日志
│   ├── plans.csv           # 套餐配置
│   ├── ip_whitelist.csv    # IP白名单
│   └── ip_blacklist.csv    # IP黑名单
│
└── logs/                   # 日志文件目录
    └── tideproxy.log       # 运行日志（自动轮转）
```

---

## 🔧 Python环境依赖

### 必须环境

- **Python 3.8 或更高版本**
- **操作系统**：Linux / macOS / Windows

### 检查Python版本

```bash
python3 --version
```

### 安装依赖

```bash
# 本项目零外部依赖，仅使用Python标准库
# 如需可选增强功能，可安装：
pip install -r requirements.txt
```

---

## 🚀 环境部署教程

### 1. 获取源码

```bash
git clone <仓库地址> TideProxy
cd TideProxy
```

### 2. 检查环境

```bash
python3 --version  # 确认Python >= 3.8
```

### 3. 创建数据目录（首次运行自动创建）

```bash
mkdir -p data logs
```

### 4. 启动服务

```bash
# 默认配置启动（代理端口1080，仅本地CLI管理）
python3 tideproxy.py

# 指定代理端口
python3 tideproxy.py -p 8888

# 启用HTTP API管理服务
python3 tideproxy.py --api --api-port 8080 --api-key your_secret_key

# 无CLI模式（仅API管理，适合后台运行）
python3 tideproxy.py --api --no-cli

# 完整参数启动
python3 tideproxy.py -H 0.0.0.0 -p 1080 --api --api-host 127.0.0.1 --api-port 8080 --api-key mykey123
```

---

## 📋 启动命令参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-H, --host` | 代理监听地址 | 0.0.0.0 |
| `-p, --port` | 代理监听端口 | 1080 |
| `--max-conn` | 最大并发连接数 | 500 |
| `--api` | 启用HTTP API服务 | 关闭 |
| `--api-host` | API监听地址 | 127.0.0.1 |
| `--api-port` | API监听端口 | 8080 |
| `--api-key` | API访问密钥 | tideproxy_admin_2024 |
| `--no-cli` | 禁用本地命令行 | 关闭 |
| `--log-level` | 日志级别 | INFO |

---

## 🎯 管理员全部操作命令

### 系统控制

| 命令 | 说明 |
|------|------|
| `help` | 显示帮助信息 |
| `start` | 启动代理服务 |
| `stop` | 停止代理服务 |
| `restart` | 重启代理服务 |
| `status` | 查看服务状态 |
| `quit` / `exit` | 退出程序 |

### 激活码管理

| 命令 | 说明 | 示例 |
|------|------|------|
| `gen_code` | 生成激活码 | `gen_code 5 流量套餐 10 0 30 days` |
| `list_codes` | 列出所有激活码 | `list_codes` |
| `del_code` | 删除激活码 | `del_code ABCD1234EFGH5678` |
| `clear_codes` | 清空所有激活码 | `clear_codes` |
| `code_info` | 查看激活码详情 | `code_info ABCD1234EFGH5678` |
| `export_codes` | 导出激活码CSV | `export_codes` |

### 套餐管理

| 命令 | 说明 | 示例 |
|------|------|------|
| `add_plan` | 新增套餐 | `add_plan 月卡 100 10 30 days` |
| `list_plans` | 列出所有套餐 | `list_plans` |
| `del_plan` | 删除套餐 | `del_plan 月卡` |
| `mod_plan` | 修改套餐 | `mod_plan 月卡 total_traffic 214748364800` |

### 记名账号管理

| 命令 | 说明 | 示例 |
|------|------|------|
| `add_user` | 新增账号 | `add_user admin password123 100 traffic` |
| `del_user` | 删除账号 | `del_user admin` |
| `user_info` | 查看账号详情 | `user_info admin` |
| `list_users` | 列出所有账号 | `list_users` |
| `topup` | 充值余额 | `topup admin 50.00` |
| `freeze` | 冻结账号 | `freeze admin` |
| `unfreeze` | 解冻账号 | `unfreeze admin` |
| `ban` | 封禁账号 | `ban admin` |
| `unban` | 解封账号 | `unban admin` |
| `reset_pwd` | 重置密码 | `reset_pwd admin newpass` |
| `set_bw` | 设置带宽限制 | `set_bw admin 10` (10Mbps) |
| `set_traffic` | 设置流量限制 | `set_traffic admin 50` (50GB) |

### MAC绑定管理

| 命令 | 说明 | 示例 |
|------|------|------|
| `bind_mac` | 绑定MAC | `bind_mac user1 account AA:BB:CC:DD:EE:FF` |
| `unbind_mac` | 解绑MAC | `unbind_mac user1 account` |
| `list_mac` | 列出所有绑定 | `list_mac` |

### 统计与维护

| 命令 | 说明 | 示例 |
|------|------|------|
| `stats` | 全局统计 | `stats` |
| `user_stats` | 用户统计 | `user_stats admin account` |
| `clear_expired` | 清理过期数据 | `clear_expired` |

### 系统控制

| 命令 | 说明 |
|------|------|
| `billing_on` | 开启计费系统 |
| `billing_off` | 关闭计费系统 |
| `reload_wl` | 重载IP白名单 |
| `reload_bl` | 重载IP黑名单 |

---

## 🌐 HTTP API接口简介

### 接口信息

- **地址**：`http://<api_host>:<api_port>`
- **方法**：POST
- **认证**：Header `X-Admin-Key: <你的API密钥>`
- **请求体**：JSON `{"command": "<管理命令>"}`
- **返回**：JSON `{"code": 200, "message": "...", "data": {...}}`

### 调用示例

```bash
# 查看服务状态
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "status"}'

# 生成激活码
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "gen_code 3 流量套餐 10 0 30 days"}'

# 充值余额
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "topup admin 100.00"}'
```

---

## 📊 双账户使用教程

### 激活码账户（不记名）

1. **生成激活码**：管理员执行 `gen_code` 命令
2. **分发给用户**：将激活码告知用户
3. **用户连接**：在代理客户端中，用户名填入激活码，密码留空或任意填写
4. **自动激活**：首次使用时自动激活并开始计费
5. **到期/用尽**：流量或时长耗尽后自动失效

### 记名账户（正式用户）

1. **创建账号**：管理员执行 `add_user` 命令
2. **充值余额**：管理员执行 `topup` 命令充值
3. **用户连接**：在代理客户端中输入用户名和密码
4. **持续使用**：余额充足即可持续使用
5. **管理维护**：管理员可随时冻结、解封、限速等

---

## 🔑 激活码生成教程

### 生成单个激活码

```bash
# 生成1个默认套餐激活码
gen_code 1
```

### 批量生成带配置的激活码

```bash
# 生成10个激活码：流量套餐、10GB流量、不限带宽、30天有效
gen_code 10 流量套餐 10 0 30 days

# 生成5个激活码：带宽套餐、不限流量、10Mbps带宽、1个月有效
gen_code 5 带宽套餐 0 10 1 months
```

### 激活码参数说明

- **数量**：要生成的激活码个数
- **套餐名**：自定义名称（如"月卡"、"年卡"）
- **流量GB**：总流量额度，0表示不限
- **带宽Mbps**：最大带宽限制，0表示不限
- **时长**：有效时长数值
- **单位**：hours（小时）/ days（天）/ months（月）

---

## 💰 计费规则说明

### 流量计费模式

- 按用户实际上行+下行总流量消耗扣费
- 流量统计精确到字节
- 流量耗尽后自动断连并禁止登录
- 适用于激活码账户和记名账户

### 带宽时长计费模式

- 按有效使用时长计费
- 同时限制最大带宽速率
- 时长到期后自动失效
- 适用于激活码账户和记名账户

### 计费精度

- 流量统计：精确到字节
- 时长统计：精确到秒
- 余额扣减：精确到0.01

---

## 📁 CSV数据文件说明

详见 [DOC.md](DOC.md) 中的"CSV数据文件说明"章节。

---

## ❓ 常见问题

### Q: 如何修改API访问密钥？

A: 通过启动参数 `--api-key your_new_key` 指定，或修改 `config.py` 中的 `API_ADMIN_KEY`。

### Q: 如何在后台长期运行？

A: 使用 `nohup python3 tideproxy.py --api --no-cli &` 或配合 systemd/screen/tmux。

### Q: 支持哪些代理协议？

A: 支持 SOCKS5（含认证）和 HTTP/HTTPS CONNECT 代理。

### Q: 数据存储在哪里？

A: 所有数据存储在 `data/` 目录下的CSV文件中。

### Q: 如何备份数据？

A: 直接复制 `data/` 目录即可。

### Q: 最大支持多少并发连接？

A: 默认500，可通过 `--max-conn` 参数调整。

### Q: 如何限制用户带宽？

A: 使用 `set_bw <用户名> <Mbps>` 命令设置。

### Q: MAC绑定是什么？

A: 将用户的代理账号绑定到特定设备的MAC地址，防止多设备共享。

---

## 📄 开源协议

本项目采用 [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html) 开源协议。

```
Copyright (C) 2024 Yicheng Liang

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```