# TideProxy（潮汐代理）官方使用文档

**版本：** v1.1.0  
**作者：** Yicheng Liang  
**协议：** GNU GPL v3.0

---

## 目录

1. [功能架构说明](#1-功能架构说明)
2. [命令行参数手册](#2-命令行参数手册)
3. [HTTP API完整接口文档](#3-http-api完整接口文档)
4. [计费逻辑详细说明](#4-计费逻辑详细说明)
5. [不记名激活码运营教程](#5-不记名激活码运营教程)
6. [记名账号管理教程](#6-记名账号管理教程)
7. [MAC绑定防共享教程](#7-mac绑定防共享教程)
8. [CSV数据文件说明](#8-csv数据文件说明)
9. [日志持久化说明](#9-日志持久化说明)
10. [API安全部署注意事项](#10-api安全部署注意事项)
11. [后台长期运行部署方案](#11-后台长期运行部署方案)

---

## 1. 功能架构说明

### 1.1 系统架构

TideProxy 采用模块化分层架构设计，各层职责明确：

```
┌─────────────────────────────────────────────────────────┐
│                    管理层 (Admin)                        │
│  ┌──────────────┐  ┌──────────────┐                     │
│  │  CLI命令行   │  │  HTTP API    │                     │
│  └──────┬───────┘  └──────┬───────┘                     │
│         └────────┬────────┘                              │
├──────────────────┼──────────────────────────────────────┤
│                  │     业务层 (Business)                 │
│  ┌───────────────┴──────────────┐                       │
│  │     计费统计系统 (Billing)    │                       │
│  └───────────────┬──────────────┘                       │
│  ┌───────────────┴──────────────┐                       │
│  │     认证层 (Auth)             │                       │
│  │  ┌─────────┐  ┌─────────┐   │                       │
│  │  │激活码   │  │记名账号 │   │                       │
│  │  └────┬────┘  └────┬────┘   │                       │
│  │       └──────┬─────┘        │                       │
│  │        ┌─────┴─────┐        │                       │
│  │        │ MAC绑定   │        │                       │
│  │        └───────────┘        │                       │
│  └─────────────────────────────┘                       │
├─────────────────────────────────────────────────────────┤
│                    协议层 (Protocol)                     │
│  ┌───────────────┐  ┌───────────────┐                   │
│  │  SOCKS5协议   │  │  HTTP代理协议 │                   │
│  └───────┬───────┘  └───────┬───────┘                   │
│          └────────┬─────────┘                           │
├───────────────────┼─────────────────────────────────────┤
│                   │     网络层 (Network)                 │
│  ┌────────────────┴────────────────┐                    │
│  │    TCP代理服务器 (Server)        │                    │
│  │    - 协议自动检测               │                    │
│  │    - 连接管理                   │                    │
│  │    - 防火墙检查                 │                    │
│  └────────────────┬────────────────┘                    │
│  ┌────────────────┴────────────────┐                    │
│  │    防火墙 (Firewall)            │                    │
│  │    - IP黑白名单                 │                    │
│  │    - 频率限制                   │                    │
│  └─────────────────────────────────┘                    │
├─────────────────────────────────────────────────────────┤
│                    数据层 (Data)                         │
│  ┌───────────────┐  ┌───────────────┐                   │
│  │ CSV数据管理   │  │ 日志系统      │                   │
│  └───────────────┘  └───────────────┘                   │
└─────────────────────────────────────────────────────────┘
```

### 1.2 模块说明

| 模块 | 文件 | 职责 |
|------|------|------|
| 主入口 | `tideproxy.py` | 程序启动、参数解析、子系统协调 |
| 配置 | `config.py` | 集中管理所有可配置参数 |
| 日志 | `logger.py` | 统一日志输出（控制台+文件） |
| 数据管理 | `csv_manager.py` | 线程安全的CSV文件读写 |
| 防火墙 | `firewall.py` | IP黑白名单、频率控制 |
| 代理服务器 | `server.py` | TCP连接监听、协议检测 |
| SOCKS5 | `protocol/socks5.py` | SOCKS5协议解析和转发 |
| HTTP代理 | `protocol/http_proxy.py` | HTTP/HTTPS CONNECT代理 |
| 激活码 | `auth/activation.py` | 激活码生成、认证、管理 |
| 记名账号 | `auth/account.py` | 账号创建、认证、管理 |
| MAC绑定 | `auth/mac_bind.py` | 设备MAC地址绑定管理 |
| 计费系统 | `billing/billing_system.py` | 流量统计、余额扣减 |
| CLI管理 | `admin/cli.py` | 本地命令行管理接口 |
| API管理 | `admin/api.py` | HTTP API远程管理接口 |

### 1.3 数据流向

```
客户端连接 → 防火墙检查 → 协议检测 → 认证验证 → 数据转发 → 流量统计
    │              │            │          │          │          │
    │         IP/频率检查   SOCKS5/HTTP  激活码/账号  双向转发   记录CSV
    │                          │
                    ┌──────────┴──────────┐
                    │                     │
               SOCKS5协议            HTTP CONNECT
                    │                     │
                    └──────────┬──────────┘
                               │
                         目标服务器
```

---

## 2. 命令行参数手册

### 2.1 启动参数

```bash
python3 tideproxy.py [选项]
```

#### 代理服务参数

| 参数 | 缩写 | 说明 | 类型 | 默认值 |
|------|------|------|------|--------|
| `--host` | `-H` | 代理监听地址 | 字符串 | 0.0.0.0 |
| `--port` | `-p` | 代理监听端口 | 整数 | 1080 |
| `--max-conn` | - | 最大并发连接数 | 整数 | 500 |

#### API服务参数

| 参数 | 说明 | 类型 | 默认值 |
|------|------|------|--------|
| `--api` | 启用HTTP API服务 | 开关 | 关闭 |
| `--api-host` | API监听地址 | 字符串 | 127.0.0.1 |
| `--api-port` | API监听端口 | 整数 | 8080 |
| `--api-key` | API访问密钥 | 字符串 | tideproxy_admin_2024 |

#### 其他参数

| 参数 | 说明 | 类型 | 默认值 |
|------|------|------|--------|
| `--no-cli` | 禁用本地命令行 | 开关 | 关闭 |
| `--log-level` | 日志级别 | DEBUG/INFO/WARNING/ERROR | INFO |

### 2.2 启动示例

```bash
# 最简启动（默认配置）
python3 tideproxy.py

# 指定端口启动
python3 tideproxy.py -p 8888

# 启用API服务
python3 tideproxy.py --api --api-port 8080

# 生产环境推荐配置
python3 tideproxy.py \
  -H 0.0.0.0 \
  -p 1080 \
  --max-conn 1000 \
  --api \
  --api-host 127.0.0.1 \
  --api-port 8080 \
  --api-key your_secure_key_here \
  --log-level INFO

# 后台运行模式（无CLI）
python3 tideproxy.py \
  --api \
  --no-cli \
  -p 1080 \
  --api-port 8080
```

### 2.3 管理员CLI命令

启动后进入交互式命令行，可输入以下命令：

#### 系统控制命令

```
help                    显示帮助信息
start                   启动代理服务
stop                    停止代理服务
restart                 重启代理服务
status                  查看服务状态
quit / exit             退出程序
```

#### 激活码管理命令

```
gen_code [数量] [套餐名] [流量GB] [带宽Mbps] [时长] [单位]
                        生成激活码
                        示例: gen_code 5 流量套餐 10 0 30 days

list_codes              列出所有激活码
del_code <激活码>       删除指定激活码
clear_codes             清空所有激活码
code_info <激活码>      查看激活码详情
export_codes            导出激活码到CSV文件
```

#### 套餐管理命令

```
add_plan <名称> <流量GB> <带宽Mbps> <时长> [单位]
                        新增套餐
                        示例: add_plan 月卡 100 10 30 days

list_plans              列出所有套餐
del_plan <套餐名>       删除套餐
mod_plan <套餐名> <字段> <值>
                        修改套餐字段
```

#### 记名账号管理命令

```
add_user <用户名> <密码> [余额] [计费模式]
                        新增记名账号
                        示例: add_user admin pass123 100 traffic

del_user <用户名>       删除账号
user_info <用户名>      查看账号详情
list_users              列出所有账号
topup <用户名> <金额>   充值余额
                        示例: topup admin 50.00

freeze <用户名>         冻结账号
unfreeze <用户名>       解冻账号
ban <用户名>            封禁账号
unban <用户名>          解封账号
reset_pwd <用户名> <新密码>
                        重置账号密码
set_bw <用户名> <带宽Mbps>
                        设置带宽限制
set_traffic <用户名> <流量GB>
                        设置流量限制
```

#### MAC绑定管理命令

```
bind_mac <标识> <类型> <MAC地址>
                        绑定MAC地址
                        示例: bind_mac user1 account AA:BB:CC:DD:EE:FF

unbind_mac <标识> <类型>
                        解除MAC绑定
list_mac                列出所有MAC绑定记录
```

#### 统计与维护命令

```
stats                   查看全局统计数据
user_stats <标识> [类型]
                        查看指定用户统计
clear_expired           清理过期数据
```

#### 计费系统控制命令

```
billing_on              开启商业计费系统
billing_off             关闭商业计费系统
```

#### 防火墙命令

```
reload_wl               重新加载IP白名单
reload_bl               重新加载IP黑名单
```

---

## 3. HTTP API完整接口文档

### 3.1 接口基础信息

| 项目 | 说明 |
|------|------|
| 基础URL | `http://<api_host>:<api_port>` |
| 请求方法 | POST |
| 请求格式 | JSON |
| 响应格式 | JSON |
| 认证方式 | Header `X-Admin-Key` |
| 默认密钥 | `tideproxy_admin_2024` |

### 3.2 统一响应格式

```json
{
    "code": 200,
    "message": "执行成功",
    "timestamp": "2024-01-01 12:00:00",
    "data": {
        "output": "命令执行结果文本"
    }
}
```

#### 状态码说明

| 状态码 | 说明 |
|--------|------|
| 200 | 执行成功 |
| 400 | 请求参数错误 |
| 403 | API密钥无效 |
| 413 | 请求体过大 |
| 429 | 请求频率超限 |
| 500 | 服务器内部错误 |

### 3.3 鉴权方式

所有API请求必须在HTTP Header中携带API密钥：

```
X-Admin-Key: tideproxy_admin_2024
```

密钥不匹配时返回403错误：

```json
{
    "code": 403,
    "message": "API密钥无效",
    "timestamp": "2024-01-01 12:00:00"
}
```

### 3.4 API接口列表

#### 3.4.1 系统控制

**查看服务状态**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "status"}'
```

返回示例：
```json
{
    "code": 200,
    "message": "执行成功",
    "timestamp": "2024-01-01 12:00:00",
    "data": {
        "output": "╔══════════════════════════════════════════╗\n║          TideProxy 服务状态              ║\n..."
    }
}
```

#### 3.4.2 激活码管理

**生成激活码**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "gen_code 5 流量套餐 10 0 30 days"}'
```

**列出所有激活码**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "list_codes"}'
```

**删除激活码**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "del_code ABCD1234EFGH5678"}'
```

**查看激活码详情**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "code_info ABCD1234EFGH5678"}'
```

#### 3.4.3 套餐管理

**新增套餐**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "add_plan 月卡 100 10 30 days"}'
```

**列出所有套餐**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "list_plans"}'
```

#### 3.4.4 记名账号管理

**新增账号**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "add_user admin password123 100 traffic"}'
```

**充值余额**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "topup admin 50.00"}'
```

**冻结账号**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "freeze admin"}'
```

**设置带宽限制**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "set_bw admin 10"}'
```

#### 3.4.5 统计查询

**全局统计**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "stats"}'
```

**用户统计**

```bash
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: tideproxy_admin_2024" \
  -H "Content-Type: application/json" \
  -d '{"command": "user_stats admin account"}'
```

#### 3.4.6 健康检查

```bash
curl http://127.0.0.1:8080/health \
  -H "X-Admin-Key: tideproxy_admin_2024"
```

返回：
```json
{
    "code": 200,
    "message": "TideProxy API 运行正常",
    "timestamp": "2024-01-01 12:00:00",
    "data": {
        "version": "1.0.0",
        "status": "running"
    }
}
```

---

## 4. 计费逻辑详细说明

### 4.1 流量计费模式

#### 计费原理

- 统计用户的实际上行+下行总流量
- 实时扣减流量额度
- 流量耗尽后自动断连并禁止登录

#### 计费精度

- 流量统计精确到**字节**
- 每次数据转发都会实时记录
- 连接断开时写入CSV日志

#### 激活码流量计费流程

```
用户连接 → 认证激活码 → 检查流量额度 → 允许/拒绝
                                    ↓
                            转发数据时实时统计
                                    ↓
                            流量用尽 → 自动断连
                                    ↓
                            更新状态为 exhausted
```

#### 记名账号流量计费流程

```
用户连接 → 验证用户名密码 → 检查状态和余额 → 允许/拒绝
                                    ↓
                            转发数据时实时统计
                                    ↓
                            扣减账户余额
                                    ↓
                            余额不足 → 自动断连
```

### 4.2 带宽时长计费模式

#### 计费原理

- 按有效使用时长计费
- 同时限制最大带宽速率
- 时长到期后自动失效

#### 带宽限制实现

- 在数据转发时检查带宽限制
- 超过限制时延迟发送数据
- 确保不超过设定的带宽上限

#### 时长计算

- 从激活/登录开始计时
- 持续计算在线时长
- 断开连接时记录到日志

### 4.3 双模式切换

管理员可以为每个用户/激活码配置不同的计费模式：

- **流量模式**：`billing_mode = traffic`
- **带宽时长模式**：`billing_mode = bandwidth`

两种模式可以同时配置，取先触发限制的模式。

---

## 5. 不记名激活码运营教程

### 5.1 激活码生命周期

```
生成（inactive）→ 首次使用（activated）→ 正常使用 → 到期/用尽（expired/exhausted）
                                                      ↘ 管理员封禁（banned）
```

### 5.2 运营流程

#### 第一步：设计套餐

根据目标用户群体设计不同的套餐：

```bash
# 体验套餐：1GB流量，3天有效
add_plan 体验套餐 1 0 3 days

# 月卡套餐：100GB流量，30天有效
add_plan 月卡 100 0 30 days

# 带宽套餐：10Mbps带宽，不限流量，30天有效
add_plan 带宽套餐 0 10 30 days

# 年卡套餐：1TB流量，365天有效
add_plan 年卡 1024 0 365 days
```

#### 第二步：批量生成激活码

```bash
# 生成100个月卡激活码
gen_code 100 月卡 100 0 30 days

# 生成50个带宽套餐激活码
gen_code 50 带宽套餐 0 10 30 days
```

#### 第三步：分发激活码

将生成的激活码分发给用户，用户在代理客户端中：
- **用户名**：填入激活码
- **密码**：留空或任意填写

#### 第四步：监控使用情况

```bash
# 查看所有激活码状态
list_codes

# 查看特定激活码详情
code_info ABCD1234EFGH5678

# 查看全局统计
stats
```

### 5.3 激活码状态说明

| 状态 | 说明 | 触发条件 |
|------|------|----------|
| `inactive` | 未激活 | 新生成的激活码 |
| `activated` | 已激活 | 用户首次使用 |
| `expired` | 已过期 | 超过有效时长 |
| `exhausted` | 已用尽 | 流量额度用完 |
| `banned` | 已封禁 | 管理员手动封禁 |

### 5.4 导出与备份

```bash
# 导出所有激活码到CSV
export_codes

# 导出文件保存在 data/ 目录下
```

---

## 6. 记名账号充值、改密、风控管理教程

### 6.1 账号创建

```bash
# 创建账号：用户名admin，密码pass123，初始余额100元，流量计费模式
add_user admin pass123 100 traffic

# 创建账号：带宽时长计费模式
add_user user2 pass456 50 bandwidth
```

### 6.2 余额管理

```bash
# 为admin充值50元
topup admin 50.00

# 查看账号信息（包含余额）
user_info admin
```

### 6.3 密码管理

```bash
# 管理员重置密码
reset_pwd admin new_password_123
```

### 6.4 账号状态管理

```bash
# 冻结账号（暂停使用）
freeze admin

# 解冻账号（恢复使用）
unfreeze admin

# 封禁账号（严重违规）
ban admin

# 解封账号
unban admin
```

### 6.5 限制配置

```bash
# 设置带宽限制为10Mbps
set_bw admin 10

# 设置流量限制为50GB
set_traffic admin 50

# 取消限制（设为0）
set_bw admin 0
set_traffic admin 0
```

### 6.6 账号状态说明

| 状态 | 说明 | 可否使用 |
|------|------|----------|
| `active` | 正常 | ✅ |
| `frozen` | 已冻结 | ❌ |
| `banned` | 已封禁 | ❌ |
| `expired` | 已过期 | ❌ |
| `over_traffic` | 流量超额 | ❌ |

---

## 7. MAC绑定防共享原理与使用教程

### 7.1 什么是MAC绑定

MAC（Media Access Control）地址是网络设备的唯一硬件标识。TideProxy的MAC绑定功能将用户的代理账号绑定到特定设备的MAC地址，确保：

- 每个激活码/账号只能在一台设备上使用
- 防止多人共享同一账号
- 提高账号安全性

### 7.2 工作原理

```
设备A（MAC: AA:BB:CC:DD:EE:FF）首次连接
        ↓
认证成功，系统记录MAC地址
        ↓
绑定关系写入 mac_bindings.csv
        ↓
设备B（MAC: 11:22:33:44:55:66）尝试连接
        ↓
检测到MAC地址不匹配
        ↓
拒绝连接
```

### 7.3 启用MAC绑定

#### 生成激活码时启用

```bash
# 生成带MAC绑定的激活码
# 参数说明：最后一个参数 true 表示启用MAC绑定
gen_code 1 月卡 100 0 30 days true
```

#### 创建账号时启用

```bash
# 创建带MAC绑定的账号
# mac_bind_enabled 在CSV中设置为 true
add_user secure_user pass123 100 traffic
# 然后手动修改 accounts.csv 中的 mac_bind_enabled 为 true
```

#### 手动绑定MAC

```bash
# 绑定MAC地址到激活码
bind_mac ABCD1234EFGH5678 activation AA:BB:CC:DD:EE:FF

# 绑定MAC地址到记名账号
bind_mac admin account AA:BB:CC:DD:EE:FF
```

### 7.4 管理MAC绑定

```bash
# 查看所有绑定记录
list_mac

# 解除绑定
unbind_mac ABCD1234EFGH5678 activation
unbind_mac admin account
```

### 7.5 注意事项

- MAC地址获取依赖网络层实现
- 跨网段连接时可能无法获取真实MAC地址
- 虚拟机、VPN等环境可能显示虚拟MAC地址
- 建议在局域网环境中使用MAC绑定功能

---

## 8. CSV数据文件说明

### 8.1 accounts.csv（记名账号数据）

| 字段名 | 说明 | 类型 | 示例 |
|--------|------|------|------|
| `username` | 用户名（唯一） | 字符串 | admin |
| `password` | 密码（SHA256哈希） | 字符串 | a1b2c3... |
| `balance` | 账户余额 | 浮点数 | 100.00 |
| `billing_mode` | 计费模式 | 字符串 | traffic/bandwidth |
| `bandwidth_limit` | 带宽限制（B/s） | 整数 | 10485760 |
| `traffic_limit` | 流量限制（字节） | 整数 | 107374182400 |
| `mac_bind_enabled` | 是否启用MAC绑定 | 布尔 | true/false |
| `status` | 账号状态 | 字符串 | active/frozen/banned/expired |
| `created_at` | 创建时间 | 时间戳 | 2024-01-01 12:00:00 |
| `last_login` | 最后登录时间 | 时间戳 | 2024-01-01 12:00:00 |
| `total_traffic` | 已用总流量（字节） | 整数 | 1073741824 |
| `total_duration` | 总在线时长（秒） | 整数 | 3600 |
| `mac_address` | 绑定的MAC地址 | 字符串 | AA:BB:CC:DD:EE:FF |

### 8.2 activation_codes.csv（激活码数据）

| 字段名 | 说明 | 类型 | 示例 |
|--------|------|------|------|
| `code` | 激活码（唯一） | 字符串 | ABCD1234EFGH5678 |
| `serial_number` | 序列号 | 字符串 | TP-20240101-A1B2C3D4 |
| `plan_name` | 套餐名称 | 字符串 | 月卡 |
| `total_traffic` | 流量额度（字节） | 整数 | 107374182400 |
| `bandwidth_limit` | 带宽限制（B/s） | 整数 | 10485760 |
| `duration` | 有效时长数值 | 整数 | 30 |
| `duration_unit` | 时长单位 | 字符串 | hours/days/months |
| `mac_bind_enabled` | 是否启用MAC绑定 | 布尔 | true/false |
| `status` | 激活码状态 | 字符串 | inactive/activated/expired/exhausted/banned |
| `activated_at` | 激活时间 | 时间戳 | 2024-01-01 12:00:00 |
| `last_access` | 最后访问时间 | 时间戳 | 2024-01-01 12:00:00 |
| `mac_address` | 绑定的MAC地址 | 字符串 | AA:BB:CC:DD:EE:FF |
| `used_traffic` | 已用流量（字节） | 整数 | 1073741824 |
| `used_duration` | 已用时长（秒） | 整数 | 3600 |
| `created_at` | 创建时间 | 时间戳 | 2024-01-01 12:00:00 |

### 8.3 mac_bindings.csv（MAC绑定记录）

| 字段名 | 说明 | 类型 | 示例 |
|--------|------|------|------|
| `identifier` | 用户标识 | 字符串 | admin/ABCD1234... |
| `account_type` | 账户类型 | 字符串 | activation/account |
| `mac_address` | MAC地址 | 字符串 | AA:BB:CC:DD:EE:FF |
| `bound_at` | 绑定时间 | 时间戳 | 2024-01-01 12:00:00 |
| `last_seen` | 最后见到时间 | 时间戳 | 2024-01-01 12:00:00 |

### 8.4 traffic_logs.csv（流量统计日志）

| 字段名 | 说明 | 类型 | 示例 |
|--------|------|------|------|
| `identifier` | 用户标识 | 字符串 | admin |
| `account_type` | 账户类型 | 字符串 | activation/account |
| `timestamp` | 记录时间 | 时间戳 | 2024-01-01 12:00:00 |
| `upload_bytes` | 上行流量（字节） | 整数 | 1048576 |
| `download_bytes` | 下行流量（字节） | 整数 | 10485760 |
| `total_bytes` | 总流量（字节） | 整数 | 11534336 |
| `duration_seconds` | 会话时长（秒） | 整数 | 300 |
| `avg_bandwidth` | 平均带宽（B/s） | 整数 | 38447 |

### 8.5 plans.csv（套餐配置）

| 字段名 | 说明 | 类型 | 示例 |
|--------|------|------|------|
| `plan_name` | 套餐名称 | 字符串 | 月卡 |
| `total_traffic` | 流量额度（字节） | 整数 | 107374182400 |
| `bandwidth_limit` | 带宽限制（B/s） | 整数 | 10485760 |
| `duration` | 有效时长 | 整数 | 30 |
| `duration_unit` | 时长单位 | 字符串 | days |
| `created_at` | 创建时间 | 时间戳 | 2024-01-01 12:00:00 |

### 8.6 ip_whitelist.csv（IP白名单）

| 字段名 | 说明 | 类型 | 示例 |
|--------|------|------|------|
| `ip_address` | IP地址 | 字符串 | 192.168.1.100 |
| `added_at` | 添加时间 | 时间戳 | 2024-01-01 12:00:00 |
| `note` | 备注 | 字符串 | 管理员手动添加 |

### 8.7 ip_blacklist.csv（IP黑名单）

| 字段名 | 说明 | 类型 | 示例 |
|--------|------|------|------|
| `ip_address` | IP地址 | 字符串 | 10.0.0.1 |
| `added_at` | 添加时间 | 时间戳 | 2024-01-01 12:00:00 |
| `reason` | 封锁原因 | 字符串 | 异常高频连接 |

---

## 9. 日志持久化说明

### 9.1 日志文件位置

```
logs/
└── tideproxy.log       # 当前日志文件
└── tideproxy.log.1     # 历史日志（轮转）
└── tideproxy.log.2     # 更早的历史日志
└── ...
```

### 9.2 日志配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `LOG_LEVEL` | INFO | 日志级别 |
| `LOG_MAX_BYTES` | 10MB | 单文件最大大小 |
| `LOG_BACKUP_COUNT` | 5 | 保留历史文件数 |

### 9.3 日志格式

```
2024-01-01 12:00:00 [INFO] TideProxy.server: 代理服务器已启动 - 监听 0.0.0.0:1080
```

格式：`时间 [级别] 模块名: 消息内容`

### 9.4 日志级别说明

| 级别 | 说明 | 使用场景 |
|------|------|----------|
| DEBUG | 调试信息 | 开发调试时使用 |
| INFO | 一般信息 | 正常运行状态记录 |
| WARNING | 警告信息 | 异常但不影响运行 |
| ERROR | 错误信息 | 功能异常需要关注 |

### 9.5 日志轮转

当日志文件达到 `LOG_MAX_BYTES`（默认10MB）时：
1. 当前日志文件重命名为 `tideproxy.log.1`
2. 创建新的 `tideproxy.log` 文件
3. 保留最近 `LOG_BACKUP_COUNT`（默认5）个历史文件
4. 更早的历史文件自动删除

---

## 10. API安全部署注意事项

### 10.1 密钥安全

- **务必修改默认API密钥**：启动时使用 `--api-key` 指定强密钥
- 密钥应包含大小写字母、数字和特殊字符
- 定期更换API密钥
- 不要在公开场所暴露API密钥

### 10.2 网络安全

- **默认仅监听本地**：API服务默认监听 `127.0.0.1`
- 如需远程访问，建议通过SSH隧道或VPN
- 不建议将API端口直接暴露到公网
- 配合防火墙限制访问来源IP

### 10.3 频率限制

- 默认限制每IP每分钟60次请求
- 超过限制返回429状态码
- 可在 `config.py` 中调整 `API_RATE_LIMIT`

### 10.4 HTTPS部署

如需HTTPS访问，建议通过Nginx反向代理：

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 11. 后台长期运行部署方案

### 11.1 使用nohup

```bash
nohup python3 tideproxy.py --api --no-cli -p 1080 --api-port 8080 > /dev/null 2>&1 &
```

### 11.2 使用screen

```bash
# 创建screen会话
screen -S tideproxy

# 在screen中启动
python3 tideproxy.py --api --no-cli -p 1080

# 分离会话：Ctrl+A, D

# 重新连接
screen -r tideproxy
```

### 11.3 使用tmux

```bash
# 创建tmux会话
tmux new -s tideproxy

# 在tmux中启动
python3 tideproxy.py --api --no-cli -p 1080

# 分离会话：Ctrl+B, D

# 重新连接
tmux attach -t tideproxy
```

### 11.4 使用systemd（推荐）

创建服务文件 `/etc/systemd/system/tideproxy.service`：

```ini
[Unit]
Description=TideProxy Service
After=network.target

[Service]
Type=simple
User=proxy_user
WorkingDirectory=/path/to/TideProxy
ExecStart=/usr/bin/python3 tideproxy.py --api --no-cli -p 1080 --api-port 8080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable tideproxy
sudo systemctl start tideproxy
sudo systemctl status tideproxy
```

### 11.5 使用supervisor

安装supervisor：

```bash
pip install supervisor
```

配置文件 `/etc/supervisor/conf.d/tideproxy.conf`：

```ini
[program:tideproxy]
command=python3 /path/to/TideProxy/tideproxy.py --api --no-cli -p 1080
directory=/path/to/TideProxy
user=proxy_user
autostart=true
autorestart=true
stderr_logfile=/var/log/tideproxy.err.log
stdout_logfile=/var/log/tideproxy.out.log
```

### 11.6 Docker部署

创建 `Dockerfile`：

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
EXPOSE 1080 8080
CMD ["python3", "tideproxy.py", "--api", "--no-cli", "-p", "1080", "--api-port", "8080"]
```

构建和运行：

```bash
docker build -t tideproxy .
docker run -d -p 1080:1080 -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  --name tideproxy tideproxy
```

---

## 附录：快速参考卡

### 常用命令速查

```
# 启动
python3 tideproxy.py -p 1080 --api --api-key mykey

# 管理
gen_code 10 月卡 100 0 30 days    # 生成激活码
add_user admin pass 100           # 创建账号
topup admin 50                    # 充值
stats                             # 查看统计
status                            # 服务状态
```

### API调用速查

```bash
# 执行任意管理命令
curl -X POST http://127.0.0.1:8080 \
  -H "X-Admin-Key: your_key" \
  -H "Content-Type: application/json" \
  -d '{"command": "<命令>"}'
```

---

*文档版本：v1.0.0 | 最后更新：2024*