# NetGuard v1.1.0

网络安全扫描与资产管理平台，基于 FastAPI + Vue 3 + Celery 构建。

## 功能特性

### 网络扫描
- **主机发现**：三阶段探测流水线（Ping → ARP → TCP端口扫描），自动发现存活主机与开放端口
- **无Root运行**：所有扫描操作使用 TCP Connect（-sT），无需 root/sudo 权限
- **端口块并行**：全端口 1-65535 自动拆分为 5000/块（14块），Semaphore 控制并发，4倍加速
- **超时优化**：`--max-retries 2` + `--max-rtt-timeout 1s` + `--initial-rtt-timeout 500ms`，大幅减少无响应主机等待
- **失败重试**：端口块失败自动重试 2 次，仍失败则跳过不阻塞；阶段失败不影响后续阶段
- **服务发现**：支持 TCP Connect/服务版本识别/脚本扫描等多种 Nmap 扫描方法
- **定时扫描**：支持周期性扫描任务，Celery 异步执行
- **实时进度**：WebSocket 推送扫描进度与增量结果，30秒心跳防黑屏

### 资产管理
- **自动录入**：扫描结果自动入库，指纹去重（基于 MAC/主机名+OS/IP 三级匹配）
- **资产台账**：手动增删改查，支持标签、分组、在线状态
- **变更追踪**：快照对比，自动检测新主机上线、服务变更、版本变化、主机下线等 9 种变更类型
- **变更告警**：按严重等级（info/warning/critical）分类记录

### 漏洞检测
- **NVD 集成**：对接 NIST NVD CVE 数据库，支持全量/增量同步
- **自动匹配**：根据资产品牌/服务/版本自动关联 CVE 漏洞
- **定时同步**：可配置自动漏洞扫描与数据库更新间隔
- **已知服务库**：内置 60+ 常见端口服务风险等级分类

### 可视化与运维
- **仪表盘**：ECharts 可视化资产统计、漏洞分布、扫描趋势
- **用户权限**：管理员/审计员/访客三角色，JWT + Refresh Token 双令牌认证
- **系统配置**：扫描器路径、API Key、漏洞扫描策略等运行时配置管理

## v1.1.0 更新内容

- 🔒 **无Root运行**：所有 nmap 操作统一使用 `-sT`（TCP Connect），不依赖 root/sudo
- ⚡ **端口块并行**：全端口扫描拆分为 14 块（5000/块）并发执行，速度提升约 4 倍
- ⏱️ **超时优化**：新增 `--max-rtt-timeout`、`--initial-rtt-timeout`、`--max-scan-delay`，无响应主机等待从分钟级降至秒级
- 🔄 **失败重试**：端口块失败自动重试 2 次；Ping/ARP 失败不影响后续阶段
- 🎯 **格式校验**：扫描目标前端+后端双重校验（IP段0-255、CIDR掩码8-32、域名需含点）
- 🧹 **简化配置**：移除扫描模式选择（固定标准模式）和端口范围输入（固定全端口）

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
| 扫描 | Nmap（TCP Connect/服务版本/脚本扫描，无需root） |
| 认证 | JWT (HS256) + bcrypt + OAuth2 + Refresh Token |

## 主机发现扫描流程

```
阶段1: Ping探测 (nmap -sn -T4)              ~5-15秒
  │ 完成后
  ▼
阶段2: ARP探测 (nmap -sn -PR -T4)           ~5秒
  │ 完成后
  ▼
阶段3: TCP端口扫描 (nmap -sT -T4)            ← 最耗时，内部并行
  │ 1-65535 拆为5000/块(14块)，Semaphore(并发数)并行
  │ 每块独立执行、独立解析、失败重试2次
  ▼
三阶段结果合并去重 → 持久化
```

### TCP端口扫描参数（v1.1.0 优化）

```bash
nmap -sT -T4 -p {port_start}-{port_end} \n  -Pn -n \                              # 跳过主机发现和DNS
  --max-retries 2 \                      # 无响应端口重传2次(原6次)
  --min-rate 300 \                       # 最低300包/秒
  --host-timeout 30m \                   # 单主机超时30分钟
  --max-rtt-timeout 1s \                 # RTT超时1秒(原默认~10秒)
  --initial-rtt-timeout 500ms \          # 初始RTT 500ms
  --max-scan-delay 200ms \               # 扫描延迟上限200ms
  -v --reason -oX <xml>                  # 进度输出+XML
```

## 快速启动

### 一键部署（无sudo）

```bash
git clone https://github.com/chengcheng20170214/netguard.git
cd netguard
chmod +x deploy.sh
./deploy.sh install     # 首次安装
./deploy.sh start       # 启动服务
./deploy.sh status      # 查看状态
```

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
| `ADMIN_DEFAULT_PASSWORD` | 是 | - | 初始管理员密码，至少 15 位 |
| `DATABASE_URL` | 否 | sqlite+aiosqlite:///./netguard.db | 数据库连接 |
| `REDIS_URL` | 否 | redis://localhost:6379/0 | Redis 地址 |
| `CELERY_BROKER_URL` | 否 | redis://localhost:6379/0 | Celery Broker |
| `NMAP_PATH` | 否 | /usr/bin/nmap | nmap 可执行文件路径 |
| `SCAN_CHUNK_SIZE` | 否 | 5000 | 全端口扫描每块端口数 |
| `SCAN_MAX_RETRIES` | 否 | 2 | nmap 无响应端口重传次数 |
| `SCAN_MIN_RATE` | 否 | 300 | nmap 最低发包速率/秒 |
| `SCAN_HOST_TIMEOUT_MIN` | 否 | 30 | 单主机超时（分钟） |
| `SCAN_MAX_RTT_TIMEOUT_MS` | 否 | 1000 | 最大RTT超时（毫秒） |
| `SCAN_INITIAL_RTT_TIMEOUT_MS` | 否 | 500 | 初始RTT超时（毫秒） |
| `SCAN_MAX_SCAN_DELAY_MS` | 否 | 200 | 最大扫描延迟（毫秒） |
| `SCAN_CHUNK_MAX_RETRIES` | 否 | 2 | 失败端口块最大重试次数 |
| `SCAN_MAX_CONCURRENT` | 否 | 4 | 最大并发 nmap 进程数 |
| `SCAN_HOST_DISCOVERY_TIMEOUT` | 否 | 30 | 主机发现单阶段超时（分钟） |

## API 路由

| 路由前缀 | 说明 | 权限 |
|----------|------|------|
| `/api/auth` | 登录/注册/刷新令牌 | 公开(登录) / 管理员(注册) |
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
- 所有 nmap 操作使用 `-sT`（TCP Connect），无需 root/sudo
- 扫描目标注入校验（IP/CIDR/主机名白名单，前后端双重校验）
- WebSocket 连接认证
- 角色权限控制（admin/auditor/guest）

## 项目结构

```
netguard/
├── deploy.sh                  # 一键部署脚本（无sudo）
├── .env                       # 环境变量配置
├── backend/
│   ├── requirements.txt
│   └── app/
│       ├── main.py            # FastAPI 入口
│       ├── config.py          # Pydantic Settings 配置
│       ├── database.py        # 异步数据库引擎
│       ├── api/               # REST API 路由
│       ├── models/            # SQLAlchemy 模型
│       ├── schemas/           # Pydantic 请求/响应
│       ├── services/          # 业务逻辑
│       │   ├── scan_executor.py   # 扫描执行器
│       │   └── scanner/nmap_scanner.py  # Nmap 扫描器
│       ├── middleware/         # JWT 认证中间件
│       └── tasks/             # Celery 异步任务
└── frontend/
    ├── vite.config.js
    ├── package.json
    └── src/
        ├── views/             # 页面组件
        ├── api/               # 后端 API 封装
        ├── stores/            # Pinia 状态管理
        └── router/            # Vue Router
```

## License

MIT
