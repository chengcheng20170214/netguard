# NetGuard

网络安全扫描与资产管理平台，基于 FastAPI + Vue 3 + Celery 构建。

## 功能特性

### 网络扫描
- **主机发现**：三阶段渐进式探测流水线（Ping → ARP → SYN），自动发现存活主机
- **服务发现**：支持 SYN 全端口/Connect/UDP/服务版本/OS 识别/脚本扫描等多种 Nmap 扫描方法
- **全端口分块扫描**：65535 端口自动分块（默认 5000/块），支持失败重试与断点续扫
- **多种扫描模式**：快速（Top 100）、标准、隐蔽（轻/中/深三档，含诱饵、分片、随机化等反检测策略）
- **定时扫描**：支持周期性扫描任务，Celery 异步执行，自动调度
- **实时进度**：WebSocket 推送扫描进度与增量结果

### 资产管理
- **自动录入**：扫描结果自动入库，指纹去重（基于 MAC/主机名+OS/IP 三级匹配）
- **资产台账**：手动增删改查，支持标签、分组、在线状态
- **变更追踪**：快照对比，自动检测新主机上线、服务变更、版本变化、主机下线等 9 种变更类型
- **变更告警**：按严重等级（info/warning/critical）分类记录

### 漏洞检测
- **NVD 集成**：对接 NIST NVD CVE 数据库，支持全量/增量同步
- **自动匹配**：根据资产品牌/服务/版本自动关联 CVE 漏洞
- **定时同步**：可配置自动漏洞扫描与数据库更新间隔
- **已知服务库**：内置 60+ 常见端口服务风险等级分类（FTP/SSH/SMB/RDP/MySQL 等）

### 可视化与运维
- **仪表盘**：ECharts 可视化资产统计、漏洞分布、扫描趋势
- **用户权限**：管理员/审计员/访客三角色，JWT + Refresh Token 双令牌认证
- **系统配置**：扫描器路径、API Key、漏洞扫描策略等运行时配置管理

## 技术架构

```
┌──────────────────┐     ┌───────────────────┐     ┌───────────┐
│   Vue 3 前端      │────▶│   FastAPI 后端      │────▶│   Redis   │
│   Element Plus    │     │   SQLAlchemy async │     └─────┬─────┘
│   ECharts         │     │   Pydantic Settings│           │
│   Pinia + Router  │     │   Celery Worker    │     ┌─────┴─────┐
└──────────────────┘     └───────────────────┘     │  Celery    │
                          ┌───────────────────┐     │  Worker    │
                          │   SQLite (async)   │     └───────────┘
                          └───────────────────┘
```

| 层级 | 技术栈 |
|------|--------|
| 后端 | FastAPI 0.115 + SQLAlchemy 2.0 (async) + aiosqlite + Celery 5.4 + Redis |
| 前端 | Vue 3.5 + Vite 8 + Element Plus 2.14 + ECharts 6 + Pinia 3 + Vue Router 4 |
| 扫描 | Nmap（SYN/Connect/UDP/Service/OS/Script/Ping/ARP） |
| 认证 | JWT (HS256) + bcrypt + OAuth2 + Refresh Token |

## 扫描方法

### 主机发现（/api/host-scans）

| 方法 | 说明 |
|------|------|
| nmap_ping | ICMP Ping 存活探测 |
| nmap_arp | ARP 存活探测（局域网） |
| nmap_syn | SYN 端口扫描发现 |

三阶段流水线自动执行：Ping → ARP → SYN，每阶段增量合并结果。

### 服务发现（/api/service-scans）

| 方法 | 说明 |
|------|------|
| nmap_syn | SYN 半开连接扫描 |
| nmap_syn_full | SYN 全端口分块扫描（1-65535） |
| nmap_connect | TCP 全连接扫描 |
| nmap_udp | UDP 端口扫描 |
| nmap_service | 服务版本识别 |
| nmap_os | 操作系统指纹识别 |
| nmap_script | Nmap 脚本扫描 |

### 扫描模式

| 模式 | 说明 |
|------|------|
| quick | Top 100 端口快速扫描 |
| standard | 全端口标准扫描 |
| stealth_light | T2 时序 + 400ms 延迟 + 50包/秒 |
| stealth_medium | T1 时序 + 3s 延迟 + 分片 + 诱饵 + 随机化 |
| stealth_deep | T0 时序 + 10s 延迟 + 分片 + 双诱饵 + 源端口53 + 数据填充 |

## 快速启动

### Docker Compose（推荐）

```bash
# 设置必要环境变量
export JWT_SECRET_KEY="your-secret-key-at-least-32-chars"
export ADMIN_DEFAULT_PASSWORD="your-strong-admin-password-15+"

docker compose up -d
```

访问 `http://localhost` 即可使用。

### 手动启动

**后端：**

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET_KEY="your-secret-key"
export ADMIN_DEFAULT_PASSWORD="your-strong-admin-password-15+"
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Celery Worker：**

```bash
cd backend
source .venv/bin/activate
export JWT_SECRET_KEY="your-secret-key"
export REDIS_URL="redis://localhost:6379/0"
export CELERY_BROKER_URL="redis://localhost:6379/0"
celery -A app.tasks.celery_app worker --loglevel=info
```

**前端：**

```bash
cd frontend
npm install
npm run dev     # 开发模式，访问 http://localhost:5173
npm run build   # 生产构建
```

## 环境变量

| 变量 | 必需 | 默认值 | 说明 |
|------|------|--------|------|
| `JWT_SECRET_KEY` | 是 | - | JWT 签名密钥，未设置则拒绝启动 |
| `ADMIN_DEFAULT_PASSWORD` | 是 | - | 初始管理员密码，至少 15 位，弱密码拒绝创建 |
| `DATABASE_URL` | 否 | sqlite+aiosqlite:///./netguard.db | 数据库连接 |
| `REDIS_URL` | 否 | redis://localhost:6379/0 | Redis 地址 |
| `CELERY_BROKER_URL` | 否 | redis://localhost:6379/0 | Celery Broker |
| `CELERY_RESULT_BACKEND` | 否 | redis://localhost:6379/0 | Celery 结果后端 |
| `NMAP_PATH` | 否 | /usr/bin/nmap | nmap 可执行文件路径 |
| `NVD_API_KEY` | 否 | - | NVD API Key，提升漏洞同步速率 |
| `SCAN_CHUNK_SIZE` | 否 | 5000 | 全端口扫描每块端口数 |
| `SCAN_MAX_RETRIES` | 否 | 6 | nmap 最大重传次数 |
| `SCAN_MIN_RATE` | 否 | 300 | nmap 最低发包速率/秒 |
| `SCAN_HOST_TIMEOUT_MIN` | 否 | 60 | 单主机超时（分钟） |
| `SCAN_CHUNK_MAX_RETRIES` | 否 | 3 | 失败分块最大重试次数 |
| `CORS_ORIGINS` | 否 | ["http://localhost:5173", ...] | CORS 允许源 |
| `DEBUG` | 否 | false | 调试模式 |

## API 路由

| 路由前缀 | 说明 | 权限 |
|----------|------|------|
| `/api/auth` | 登录/注册/刷新令牌/当前用户 | 公开(登录) / 管理员(注册) |
| `/api/users` | 用户 CRUD | 管理员 |
| `/api/host-scans` | 主机发现任务 + WebSocket 实时进度 | 管理员/审计员 |
| `/api/service-scans` | 服务发现任务 + WebSocket 实时进度 | 管理员/审计员 |
| `/api/assets` | 资产 CRUD + 变更历史 | 登录用户 |
| `/api/vulns` | 漏洞查询 + NVD 数据库管理 | 登录用户 |
| `/api/sysconfig` | 系统配置管理 | 管理员 |
| `/api/health` | 健康检查 | 公开 |

## 安全特性

- JWT 强制密钥配置，空密钥拒绝启动
- 管理员密码至少 15 位，弱密码拒绝创建
- Access Token (30min) + Refresh Token (7d) 双令牌机制
- Refresh Token 通过请求体传参（防 URL 泄露）
- CORS 限制方法和头部
- 扫描目标注入校验（IP/CIDR/主机名白名单）
- WebSocket 连接认证
- Docker 容器非 root 运行 + setcap 最小权限
- 角色权限控制（admin/auditor/guest）

## 数据模型

| 模型 | 说明 |
|------|------|
| User | 用户（admin/auditor/guest 三角色） |
| ScanTask | 扫描任务（主机发现/服务发现，一次性/周期性） |
| ScanResult | 扫描结果（IP/MAC/主机名/OS/端口） |
| ScanChunk | 扫描分块（全端口分块状态追踪） |
| Asset | 资产（指纹去重 + 标签 + 分组） |
| AssetSnapshot | 资产快照（用于变更对比） |
| AssetChange | 资产变更（9 种变更类型 + 严重等级） |
| Vulnerability | 漏洞（CVE + CVSS + 修复建议） |
| VulnDB | NVD 漏洞库缓存 |
| KnownService | 已知服务端口风险分类 |
| SystemConfig | 系统运行时配置 |

## 项目结构

```
netguard/
├── docker-compose.yml
├── deploy.sh                  # 一键部署脚本
├── .env                       # 环境变量配置
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── start.sh
│   └── app/
│       ├── main.py            # FastAPI 入口 + 生命周期
│       ├── config.py          # Pydantic Settings 配置
│       ├── database.py        # 异步数据库引擎
│       ├── api/               # REST API 路由
│       │   ├── auth.py        # 登录/注册/刷新
│       │   ├── users.py       # 用户管理
│       │   ├── host_discovery.py  # 主机发现 + WebSocket
│       │   ├── service_discovery.py  # 服务发现 + WebSocket
│       │   ├── assets.py      # 资产 CRUD + 变更历史
│       │   ├── vulns.py       # 漏洞查询 + NVD 管理
│       │   └── sysconfig.py   # 系统配置
│       ├── models/
│       │   └── models.py      # 全部 SQLAlchemy 模型
│       ├── schemas/           # Pydantic 请求/响应模型
│       │   ├── auth.py
│       │   ├── asset.py
│       │   ├── discovery.py
│       │   ├── vuln.py
│       │   └── settings.py
│       ├── services/          # 业务逻辑
│       │   ├── auth.py        # 密码哈希 + JWT 令牌
│       │   ├── scan_executor.py   # 扫描执行器（分块/流水线/增量持久化）
│       │   ├── scheduler.py   # 周期扫描调度器
│       │   ├── change_tracker.py  # 资产快照对比 + 变更检测
│       │   ├── vuln_service.py    # 漏洞扫描 + 自动调度
│       │   ├── nvd.py         # NVD API 客户端
│       │   ├── config_service.py  # 配置管理
│       │   ├── known_services.py  # 已知服务端口库（60+）
│       │   └── scanner/       # 扫描引擎
│       │       ├── base.py    # 抽象基类
│       │       └── nmap_scanner.py  # Nmap 扫描器（9 种方法 + 隐蔽模式）
│       ├── middleware/
│       │   └── auth.py       # JWT 认证中间件 + 角色守卫
│       └── tasks/             # Celery 异步任务
│           ├── celery_app.py
│           └── scan_tasks.py
└── frontend/
    ├── Dockerfile
    ├── vite.config.js
    ├── package.json
    └── src/
        ├── App.vue
        ├── main.js
        ├── api/              # 后端 API 封装
        │   ├── auth.js
        │   ├── assets.js
        │   ├── discovery.js
        │   ├── vulns.js
        │   ├── users.js
        │   └── settings.js
        ├── views/             # 页面组件
        │   ├── Login.vue
        │   ├── Dashboard.vue
        │   ├── HostDiscovery.vue
        │   ├── ServiceDiscovery.vue
        │   ├── Assets.vue
        │   ├── AssetDetail.vue
        │   ├── Vulns.vue
        │   ├── Users.vue
        │   └── Settings.vue
        ├── stores/            # Pinia 状态管理
        │   ├── auth.js
        │   └── scan.js
        ├── router/            # Vue Router 路由守卫
        │   └── index.js
        ├── components/
        ├── assets/
        └── styles/
```

## License

MIT
