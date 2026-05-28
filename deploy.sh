#!/bin/bash
set -e

echo "=========================================="
echo "   NetGuard 一键部署脚本"
echo "=========================================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 检查是否为 root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}请使用 root 用户运行此脚本${NC}"
  exit 1
fi

# ---- 1. 安装 Docker ----
echo -e "${YELLOW}[1/5] 检查 Docker...${NC}"
if ! command -v docker &> /dev/null; then
  echo "Docker 未安装，正在安装..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
  echo -e "${GREEN}Docker 安装完成${NC}"
else
  echo -e "${GREEN}Docker 已安装: $(docker --version)${NC}"
fi

# ---- 2. 安装 Docker Compose ----
echo -e "${YELLOW}[2/5] 检查 Docker Compose...${NC}"
if ! docker compose version &> /dev/null; then
  echo "Docker Compose 未安装，正在安装..."
  apt-get update && apt-get install -y docker-compose-plugin 2>/dev/null || \
  yum install -y docker-compose-plugin 2>/dev/null || \
  mkdir -p /usr/local/lib/docker/cli-plugins && \
  curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
    -o /usr/local/lib/docker/cli-plugins/docker-compose && \
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  echo -e "${GREEN}Docker Compose 安装完成${NC}"
else
  echo -e "${GREEN}Docker Compose 已安装: $(docker compose version)${NC}"
fi

# ---- 3. 克隆项目 ----
echo -e "${YELLOW}[3/5] 克隆 NetGuard 代码...${NC}"
if [ -d "/opt/netguard" ]; then
  echo "目录已存在，拉取最新代码..."
  cd /opt/netguard && git pull
else
  git clone https://github.com/chengcheng20170214/netguard.git /opt/netguard
fi
cd /opt/netguard
echo -e "${GREEN}代码准备完成${NC}"

# ---- 4. 配置环境变量 ----
echo -e "${YELLOW}[4/5] 配置环境变量...${NC}"
if [ ! -f .env ]; then
  # 生成随机 JWT 密钥
  JWT_KEY=$(openssl rand -hex 32)
  ADMIN_PWD="NetGuard@$(openssl rand -hex 6)!"

  cat > .env << EOF
# JWT 签名密钥（已自动生成）
JWT_SECRET_KEY=${JWT_KEY}

# 初始管理员密码（请登录后立即修改）
ADMIN_DEFAULT_PASSWORD=${ADMIN_PWD}
EOF
  echo -e "${GREEN}环境变量已配置${NC}"
  echo -e "${YELLOW}=========================================="
  echo -e "  管理员初始密码: ${ADMIN_PWD}"
  echo -e "  请登录后立即修改！"
  echo -e "==========================================${NC}"
else
  echo -e "${GREEN}.env 文件已存在，跳过配置${NC}"
fi

# ---- 5. 启动服务 ----
echo -e "${YELLOW}[5/5] 启动 Docker Compose 服务...${NC}"
docker compose up -d --build

echo ""
echo -e "${GREEN}=========================================="
echo -e "   NetGuard 部署完成！"
echo -e "=========================================="
echo -e ""
echo -e "  访问地址: http://$(hostname -I | awk '{print $1}')"
echo -e "  管理员账号: admin"
echo -e "  管理员密码: 见上方输出或 /opt/netguard/.env"
echo -e ""
echo -e "  常用命令:"
echo -e "    查看状态: cd /opt/netguard && docker compose ps"
echo -e "    查看日志: cd /opt/netguard && docker compose logs -f"
echo -e "    停止服务: cd /opt/netguard && docker compose down"
echo -e "==========================================${NC}"
