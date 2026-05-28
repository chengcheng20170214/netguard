#!/bin/bash
# ============================================================
#  NetGuard v1.1.0 本地部署脚本（无 sudo，用户态运行）
# ============================================================
set -e

# ---------- 颜色 ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ---------- 配置 ----------
INSTALL_DIR="${INSTALL_DIR:-$HOME/code/netguard}"
REDIS_DIR="$INSTALL_DIR/local/redis"
BACKEND_DIR="$INSTALL_DIR/backend"
FRONTEND_DIR="$INSTALL_DIR/frontend"
LOG_DIR="/tmp"

# ============================================================
#  帮助
# ============================================================
usage() {
  cat <<EOF
用法: $0 <命令>

命令:
  install    首次安装（克隆代码 + 安装依赖 + 初始化配置）
  start      启动所有服务
  stop       停止所有服务
  restart    重启所有服务
  status     查看服务状态
  update     更新代码并重启服务
  logs       查看最近日志
EOF
  exit 0
}

# ============================================================
#  工具函数
# ============================================================
check_port() {
  python3 -c "
import socket
s = socket.socket()
s.settimeout(1)
try:
    s.connect(('127.0.0.1', $1))
    print('used')
except:
    print('free')
finally:
    s.close()
"
}

wait_for() {
  local url="$1" expect="$2" tries="${3:-15}"
  for i in $(seq 1 $tries); do
    resp=$(curl -s "$url" 2>/dev/null) && echo "$resp" | grep -q "$expect" && return 0
    sleep 1
  done
  return 1
}

# ============================================================
#  install
# ============================================================
do_install() {
  echo "=========================================="
  echo "   NetGuard v1.1.0 首次安装"
  echo "=========================================="

  # ---- 1. 克隆代码 ----
  if [ -d "$INSTALL_DIR/.git" ]; then
    warn "目录已存在: $INSTALL_DIR，跳过克隆"
  else
    info "克隆代码..."
    git clone https://github.com/chengcheng20170214/netguard.git "$INSTALL_DIR"
  fi

  # ---- 2. 后端 Python 依赖 ----
  info "安装后端 Python 依赖..."
  cd "$BACKEND_DIR"
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt -q

  # ---- 3. 前端 Node 依赖 ----
  info "安装前端 Node 依赖..."
  cd "$FRONTEND_DIR"
  npm install

  # ---- 4. Redis（用户态安装）----
  if [ -x "$REDIS_DIR/usr/bin/redis-server" ]; then
    info "Redis 已存在于 $REDIS_DIR"
  else
    info "安装 Redis（apt download，无需 sudo）..."
    mkdir -p "$REDIS_DIR"
    local tmpdir=$(mktemp -d)
    cd "$tmpdir"
    apt download redis-server redis-tools liblzf1 2>/dev/null || 
      apt-get download redis-server redis-tools liblzf1 2>/dev/null || 
      warn "apt download 失败，请手动安装 Redis"
    for deb in *.deb; do
      [ -f "$deb" ] && dpkg-deb -x "$deb" "$REDIS_DIR"
    done
    rm -rf "$tmpdir"
  fi

  # ---- 5. 环境变量 ----
  if [ -f "$BACKEND_DIR/.env" ]; then
    warn ".env 已存在，跳过"
  else
    info "生成 .env 配置..."
    JWT_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    ADMIN_PWD="NetGuard@$(python3 -c 'import secrets; print(secrets.token_hex(6))')!"
    cat > "$BACKEND_DIR/.env" <<EOF
# JWT 签名密钥（已自动生成）
JWT_SECRET_KEY=${JWT_KEY}

# 初始管理员密码（登录后请立即修改）
ADMIN_DEFAULT_PASSWORD=${ADMIN_PWD}

# Redis
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# 数据库
DATABASE_URL=sqlite+aiosqlite:///./netguard.db
EOF
    echo ""
    info "=========================================="
    info "  管理员初始密码: ${ADMIN_PWD}"
    info "  请登录后立即修改！"
    info "=========================================="
    echo ""
  fi

  # ---- 6. nmap 权限 ----
  if command -v nmap &>/dev/null; then
    info "nmap 已安装: $(which nmap)"
  else
    warn "nmap 未安装，扫描功能需要: sudo apt install nmap"
  fi

  info "安装完成！运行 $0 start 启动服务"
}

# ============================================================
#  start
# ============================================================
do_start() {
  echo "=========================================="
  echo "   NetGuard 启动服务"
  echo "=========================================="

  cd "$BACKEND_DIR"
  source_env

  # ---- Redis ----
  if [ "$(check_port 6379)" = "used" ]; then
    info "Redis 已运行"
  else
    info "启动 Redis..."
    if [ ! -x "$REDIS_DIR/usr/bin/redis-server" ]; then
      error "Redis 未安装，运行 $0 install"
    fi
    LD_LIBRARY_PATH="$REDIS_DIR/usr/lib/x86_64-linux-gnu" "$REDIS_DIR/usr/bin/redis-server" --port 6379 --dir /tmp --daemonize yes
    sleep 1
    if [ "$(check_port 6379)" = "used" ]; then
      info "Redis 启动成功"
    else
      error "Redis 启动失败"
    fi
  fi

  # ---- 后端 ----
  if [ "$(check_port 8000)" = "used" ]; then
    info "后端已运行"
  else
    info "启动后端..."
    nohup .venv/bin/uvicorn app.main:app 
      --host 127.0.0.1 --port 8000 
      > "$LOG_DIR/netguard-uvicorn.log" 2>&1 &
    if wait_for "http://127.0.0.1:8000/api/health" "ok" 15; then
      info "后端启动成功"
    else
      error "后端启动失败，查看日志: tail $LOG_DIR/netguard-uvicorn.log"
    fi
  fi

  # ---- Celery ----
  if pgrep -f "celery -A app.tasks" &>/dev/null; then
    info "Celery 已运行"
  else
    info "启动 Celery Worker..."
    nohup .venv/bin/celery -A app.tasks.celery_app worker --loglevel=info 
      > "$LOG_DIR/netguard-celery.log" 2>&1 &
    sleep 3
    if pgrep -f "celery -A app.tasks" &>/dev/null; then
      info "Celery 启动成功"
      # 验证任务注册
      if grep -q "run_scan_task" "$LOG_DIR/netguard-celery.log" 2>/dev/null; then
        info "Celery 任务已注册: run_scan_task"
      else
        warn "Celery 日志中未发现 run_scan_task，请检查"
      fi
    else
      error "Celery 启动失败，查看日志: tail $LOG_DIR/netguard-celery.log"
    fi
  fi

  # ---- 前端 ----
  if [ "$(check_port 5173)" = "used" ]; then
    info "前端已运行"
  else
    info "启动前端..."
    cd "$FRONTEND_DIR"
    nohup npx vite --host 127.0.0.1 
      > "$LOG_DIR/netguard-frontend.log" 2>&1 &
    if wait_for "http://127.0.0.1:5173/" "" 15; then
      info "前端启动成功"
    else
      error "前端启动失败，查看日志: tail $LOG_DIR/netguard-frontend.log"
    fi
  fi

  echo ""
  info "=========================================="
  info "  NetGuard 服务已启动！"
  info "  前端: http://127.0.0.1:5173"
  info "  后端: http://127.0.0.1:8000"
  info "  日志: $LOG_DIR/netguard-*.log"
  info "=========================================="
}

# ============================================================
#  stop
# ============================================================
do_stop() {
  echo "停止 NetGuard 服务..."

  # 前端
  pkill -f "node.*vite" 2>/dev/null && info "前端已停止" || warn "前端未运行"

  # Celery
  pkill -f "celery -A app.tasks" 2>/dev/null && info "Celery 已停止" || warn "Celery 未运行"

  # 后端
  pkill -f "uvicorn app.main:app" 2>/dev/null && info "后端已停止" || warn "后端未运行"

  # Redis
  if [ "$(check_port 6379)" = "used" ]; then
    redis-cli -p 6379 shutdown nosave 2>/dev/null && info "Redis 已停止" || 
      pkill -f "redis-server.*6379" 2>/dev/null && info "Redis 已停止"
  else
    warn "Redis 未运行"
  fi
}

# ============================================================
#  restart
# ============================================================
do_restart() {
  do_stop
  sleep 2
  do_start
}

# ============================================================
#  status
# ============================================================
do_status() {
  echo "=========================================="
  echo "   NetGuard 服务状态"
  echo "=========================================="

  # Redis
  if [ "$(check_port 6379)" = "used" ]; then
    info "Redis       :6379  运行中"
  else
    error_no_exit=true
    echo -e "${RED}[✗]${NC} Redis       :6379  未运行"
    unset error_no_exit
  fi

  # 后端
  health=$(curl -s http://127.0.0.1:8000/api/health 2>/dev/null)
  if echo "$health" | grep -q "ok"; then
    ver=$(echo "$health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('version','?'))" 2>/dev/null)
    info "后端        :8000  运行中 v${ver:-?}"
  else
    echo -e "${RED}[✗]${NC} 后端        :8000  未运行"
  fi

  # Celery
  if pgrep -f "celery -A app.tasks" &>/dev/null; then
    cnt=$(pgrep -f "celery -A app.tasks" | wc -l)
    info "Celery      worker ${cnt} 进程"
  else
    echo -e "${RED}[✗]${NC} Celery      未运行"
  fi

  # 前端
  if [ "$(check_port 5173)" = "used" ]; then
    info "前端        :5173  运行中"
  else
    echo -e "${RED}[✗]${NC} 前端        :5173  未运行"
  fi
}

# ============================================================
#  update
# ============================================================
do_update() {
  echo "=========================================="
  echo "   NetGuard 更新部署"
  echo "=========================================="

  # 停服务
  do_stop
  sleep 2

  # 拉代码
  info "拉取最新代码..."
  cd "$INSTALL_DIR"
  git pull origin main

  # 后端依赖
  if git diff --name-only HEAD@{1} HEAD | grep -q "requirements.txt"; then
    info "更新后端依赖..."
    cd "$BACKEND_DIR"
    .venv/bin/pip install -r requirements.txt -q
  fi

  # 前端依赖
  if git diff --name-only HEAD@{1} HEAD | grep -q "package.json"; then
    info "更新前端依赖..."
    cd "$FRONTEND_DIR"
    npm install
  fi

  # 启动
  do_start
}

# ============================================================
#  logs
# ============================================================
do_logs() {
  local svc="${1:-all}"
  case "$svc" in
    redis)   tail -30 /tmp/redis.log 2>/dev/null || echo "无 Redis 日志" ;;
    backend) tail -50 "$LOG_DIR/netguard-uvicorn.log" ;;
    celery)  tail -50 "$LOG_DIR/netguard-celery.log" ;;
    frontend) tail -50 "$LOG_DIR/netguard-frontend.log" ;;
    *)       for f in netguard-uvicorn netguard-celery netguard-frontend; do
               echo "=== $f ===" && tail -20 "$LOG_DIR/$f.log" 2>/dev/null && echo ""
             done ;;
  esac
}

# ============================================================
#  加载环境变量
# ============================================================
source_env() {
  if [ -f "$BACKEND_DIR/.env" ]; then
    set -a
    source <(grep -v '^#' "$BACKEND_DIR/.env" | grep -v '^$')
    set +a
  fi
}

# ============================================================
#  入口
# ============================================================
case "${1:-}" in
  install)  do_install ;;
  start)    do_start ;;
  stop)     do_stop ;;
  restart)  do_restart ;;
  status)   do_status ;;
  update)   do_update ;;
  logs)     do_logs "$2" ;;
  *)        usage ;;
esac
