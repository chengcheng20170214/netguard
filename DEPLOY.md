# NetGuard 部署指南

## 目录

- [环境要求](#环境要求)
- [Docker Compose 部署（推荐）](#docker-compose-部署推荐)
- [手动部署](#手动部署)
- [生产环境加固](#生产环境加固)
- [常见问题](#常见问题)

## 环境要求

### 最低配置

| 项目 | 要求 |
|---|---|
| CPU | 2 核 |
| 内存 | 2 GB |
| 磁盘 | 10 GB |
| 系统 | Ubuntu 22.04+ / Debian 12+ / CentOS 8+ |

### 软件依赖

| 软件 | 版本 | 必需 |
|---|---|---|
| Docker | ≥ 20.10 | Docker 部署 |
| Docker Compose | ≥ v2.0 | Docker 部署 |
| Python | ≥ 3.11 | 手动部署 |
| Node.js | ≥ 18 | 手动部署前端 |
| Redis | ≥ 6.0 | 手动部署 |
| nmap | 最新 | 手动部署扫描功能 |

---

## Docker Compose 部署（推荐）

### 1. 克隆项目

```bash
git clone https://github.com/chengcheng20170214/netguard.git
cd netguard
```

### 2. 创建前端 Dockerfile

项目缺少前端 Dockerfile，需创建 `frontend/Dockerfile`：

```dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY <<'EOF' /etc/nginx/conf.d/default.conf
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ws/ {
        proxy_pass http://backend:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
```

### 3. 配置环境变量

```bash
cat > .env << 'EOF'
# [必须] JWT 签名密钥 - 随机生成，至少32字符
JWT_SECRET_KEY=$(openssl rand -hex 32)

# [必须] 初始管理员密码 - 至少15位
ADMIN_DEFAULT_PASSWORD=YourStrongPassword123!

# [可选] NVD API Key - 提升漏洞同步速率
# NVD_API_KEY=your-nvd-api-key
EOF
```

### 4. 启动服务

```bash
docker compose up -d
```

### 5. 验证

```bash
# 检查服务状态
docker compose ps

# 健康检查
curl http://localhost/api/health

# 预期返回: {"status":"ok","version":"1.0.0"}
```

访问 `http://localhost`，使用管理员账号登录。

### 6. 常用命令

```bash
# 查看日志
docker compose logs -f backend
docker compose logs -f celery-worker

# 重启服务
docker compose restart

# 停止并删除
docker compose down

# 停止并清除数据
docker compose down -v
```

---

## 手动部署

### 1. 安装系统依赖

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y nmap masscan fping python3 python3-venv python3-pip redis-server

# CentOS/RHEL
sudo yum install -y nmap fping python3 python3-pip redis
```

### 2. 启动 Redis

```bash
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

### 3. 部署后端

```bash
cd netguard/backend

# 创建虚拟环境
python3 -m venv .venv
source .venv/bin/activate

# 安装依赖
pip install -r requirements.txt

# 设置环境变量
export JWT_SECRET_KEY="$(openssl rand -hex 32)"
export ADMIN_DEFAULT_PASSWORD="YourStrongPassword123!"
export REDIS_URL="redis://localhost:6379/0"
export CELERY_BROKER_URL="redis://localhost:6379/0"
export CELERY_RESULT_BACKEND="redis://localhost:6379/0"

# 初始化数据库（首次启动自动完成）
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 4. 启动 Celery Worker

```bash
# 新终端
cd netguard/backend
source .venv/bin/activate

export JWT_SECRET_KEY="同上"
export REDIS_URL="redis://localhost:6379/0"
export CELERY_BROKER_URL="redis://localhost:6379/0"
export CELERY_RESULT_BACKEND="redis://localhost:6379/0"

celery -A app.tasks.celery_app worker --loglevel=info
```

### 5. 构建前端

```bash
cd netguard/frontend

# 安装依赖
npm install

# 开发模式（API 代理到 localhost:8000）
npm run dev

# 或生产构建
npm run build
# 产物在 dist/ 目录，用 Nginx 托管
```

### 6. Nginx 配置（生产环境）

```nginx
server {
    listen 80;
    server_name netguard.example.com;

    # 前端静态文件
    root /path/to/netguard/frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # API 反向代理
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket
    location /api/ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## 生产环境加固

### 必做项

| 项 | 说明 |
|---|---|
| HTTPS | Nginx 配置 SSL 证书（Let's Encrypt） |
| 防火墙 | 仅开放 80/443，关闭 8000/6379 外部访问 |
| JWT_SECRET_KEY | 随机生成，不使用弱密钥 |
| ADMIN_DEFAULT_PASSWORD | 首次登录后立即修改 |
| CORS_ORIGINS | `.env` 中限定前端域名 |

### 环境变量完整参考

```bash
# === 必须 ===
JWT_SECRET_KEY=随机32字符以上的密钥
ADMIN_DEFAULT_PASSWORD=15位以上的强密码

# === 数据库 ===
DATABASE_URL=sqlite+aiosqlite:///./netguard.db

# === Redis ===
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# === 扫描器路径 ===
NMAP_PATH=/usr/bin/nmap
MASSCAN_PATH=/usr/bin/masscan
FPING_PATH=/usr/bin/fping

# === NVD 漏洞库 ===
NVD_API_KEY=                        # 申请: https://nvd.nist.gov/developers/request-an-api-key

# === CORS ===
# 多个源用逗号分隔
CORS_ORIGINS=["https://netguard.example.com"]

# === 调试 ===
DEBUG=false
```

### Systemd 服务（手动部署推荐）

后端 `netguard-backend.service`：

```ini
[Unit]
Description=NetGuard Backend
After=network.target redis-server.service

[Service]
Type=simple
User=netguard
WorkingDirectory=/opt/netguard/backend
EnvironmentFile=/opt/netguard/backend/.env
ExecStart=/opt/netguard/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Celery `netguard-celery.service`：

```ini
[Unit]
Description=NetGuard Celery Worker
After=network.target redis-server.service

[Service]
Type=simple
User=netguard
WorkingDirectory=/opt/netguard/backend
EnvironmentFile=/opt/netguard/backend/.env
ExecStart=/opt/netguard/backend/.venv/bin/celery -A app.tasks.celery_app worker --loglevel=info
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp netguard-backend.service /etc/systemd/system/
sudo cp netguard-celery.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netguard-backend
sudo systemctl enable --now netguard-celery
```

---

## 常见问题

### 扫描任务一直 pending

- 检查 Celery Worker 是否运行：`docker compose logs celery-worker`
- 检查 Redis 连接：`docker compose exec redis redis-cli ping`
- 确认 `CELERY_BROKER_URL` 配置正确

### 登录后提示未认证

- 确认 `JWT_SECRET_KEY` 后端与 Celery 使用同一个值
- 检查浏览器控制台 CORS 报错
- 确认 `CORS_ORIGINS` 包含前端访问地址

### Nmap 扫描失败

- 确认 nmap 已安装：`which nmap`
- Docker 部署：镜像内已包含
- 手动部署：`sudo setcap cap_net_raw+ep $(which nmap)` 或 root 运行

### NVD 漏洞同步慢

- 未配置 `NVD_API_KEY` 时速率限制为 5 请求/30秒
- 申请免费 API Key：https://nvd.nist.gov/developers/request-an-api-key
- 配置后速率提升至 50 请求/30秒

### 数据库位置

- Docker：容器内 `/app/netguard.db`，挂载 `./data` 目录持久化
- 手动：`backend/netguard.db`，配置 `DATABASE_URL` 可切换 PostgreSQL
