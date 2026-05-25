# NetGuard

网络安全扫描与资产管理平台，基于 FastAPI + Vue 3 + Celery 构建。

## 功能

- 🔍 **网络发现**：支持 Nmap/Masscan/fping/Socket/Scapy/ARP 多种扫描引擎，一键发现存活主机与开放端口
- 📋 **资产管理**：自动录入扫描结果，手动增删改查，资产变更追踪
- 🛡️ **漏洞检测**：集成 NVD CVE 数据库，自动匹配资产漏洞，定时同步
- 📊 **仪表盘**：ECharts 可视化：资产统计、漏洞分布、扫描趋势
- 👥 **用户权限**：管理员/审计员/访客三角色，JWT 认证
- ⏱️ **定时任务**：周期扫描调度器，Celery 异步执行
- ⚙️ **系统配置**：扫描器路径、API Key 等运行时配置管理

## 架构

```
┌─────────────┐     ┌──────────────┐     ┌───────┐
│  Vue 3 前端  │────▶│  FastAPI 后端  │────▶│ Redis │
│  Element Plus│     │  SQLAlchemy   │     └───┬───┘
│  ECharts     │     │  Celery       │         │
└─────────────┘     └──────────────┘     ┌─────┴─────┐
                    ┌──────────────┐      │  Celery    │
                    │   SQLite DB   │      │  Worker    │
                    └──────────────┘      └───────────┘
```

**后端**：FastAPI + SQLAlchemy (async) + aiosqlite + Celery + Redis

**前端**：Vue 3 + Vite + Element Plus + ECharts + Pinia + Vue Router

## 扫描引擎

| 引擎 | 扫描方式 | 说明 |
|---|---|---|
| Nmap | SYN/Connect/UDP/Service/OS/Script | 全功能端口扫描与服务识别 |
| Masscan | 高速端口扫描 | 大规模网段快速发现 |
| fping | ICMP 存活检测 | 批量主机存活判断 |
| Socket | TCP Connect | 零依赖端口探测 |
| Scapy | ARP/自定义 | 局域网主机发现 |

支持快速/标准/隐蔽(轻/中/深)多种扫描模式。

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
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Celery Worker：**

```bash
cd backend
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

| 变量 | 必需 | 说明 |
|---|---|---|
| `JWT_SECRET_KEY` | ✅ | JWT 签名密钥，未设置则拒绝启动 |
| `ADMIN_DEFAULT_PASSWORD` | ✅ | 初始管理员密码，至少 15 位 |
| `REDIS_URL` | ❌ | Redis 地址，默认 `redis://localhost:6379/0` |
| `NVD_API_KEY` | ❌ | NVD API Key，提升漏洞同步速率 |
| `NMAP_PATH` | ❌ | nmap 路径，默认 `/usr/bin/nmap` |
| `MASSCAN_PATH` | ❌ | masscan 路径，默认 `/usr/bin/masscan` |

## 安全特性

- JWT 强制密钥配置，空密钥拒绝启动
- 管理员密码至少 15 位，弱密码拒绝创建
- CORS 限制方法和头部
- 扫描目标注入校验
- WebSocket 连接认证
- Docker 容器非 root 运行 + setcap 最小权限
- refresh_token 通过 body 传参（防 URL 泄露）

## 项目结构

```
netguard/
├── docker-compose.yml
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── start.sh
│   └── app/
│       ├── main.py              # FastAPI 入口
│       ├── config.py            # 配置（Pydantic Settings）
│       ├── database.py          # 异步数据库
│       ├── api/                 # REST API 路由
│       │   ├── auth.py          # 登录/注册/刷新
│       │   ├── users.py         # 用户管理
│       │   ├── assets.py        # 资产 CRUD
│       │   ├── discovery.py     # 扫描任务
│       │   ├── vulns.py         # 漏洞查询
│       │   └── sysconfig.py     # 系统配置
│       ├── models/              # SQLAlchemy 模型
│       ├── schemas/             # Pydantic 请求/响应
│       ├── services/            # 业务逻辑
│       │   ├── auth.py
│       │   ├── scan_executor.py # 扫描执行器
│       │   ├── scheduler.py     # 扫描调度器
│       │   ├── vuln_service.py  # 漏洞服务+调度
│       │   ├── nvd.py           # NVD API 客户端
│       │   ├── change_tracker.py# 资产变更追踪
│       │   ├── config_service.py# 配置管理
│       │   └── scanner/         # 扫描引擎
│       │       ├── base.py      # 抽象基类
│       │       ├── nmap_scanner.py
│       │       ├── masscan_scanner.py
│       │       ├── fping_scan.py
│       │       ├── socket_scanner.py
│       │       └── scapy_scan.py
│       ├── middleware/           # 中间件
│       └── tasks/               # Celery 异步任务
└── frontend/
    ├── vite.config.js
    ├── package.json
    └── src/
        ├── api/                 # 后端 API 封装
        ├── views/               # 页面组件
        │   ├── Dashboard.vue
        │   ├── Assets.vue
        │   ├── AssetDetail.vue
        │   ├── Discovery.vue
        │   ├── Vulns.vue
        │   ├── Users.vue
        │   ├── Settings.vue
        │   └── Login.vue
        ├── stores/              # Pinia 状态
        ├── router/              # Vue Router
        └── components/
```

## License

MIT
