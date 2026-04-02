#!/bin/bash
#
# API Checker 一键部署脚本
# 支持: Docker + Nginx + SSL
#
# 用法:
#   bash deploy.sh                    # 交互式
#   bash deploy.sh --docker           # 仅 Docker 部署
#   bash deploy.sh --full             # Docker + Nginx + SSL
#

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 默认配置
ADMIN_PASSWORD="admin123"
DOMAIN=""
EMAIL=""
DEPLOY_TYPE="docker"  # docker | full

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --docker)  DEPLOY_TYPE="docker"; shift ;;
        --full)    DEPLOY_TYPE="full"; shift ;;
        --domain)  DOMAIN="$2"; shift 2 ;;
        --password) ADMIN_PASSWORD="$2"; shift 2 ;;
        --email)   EMAIL="$2"; shift 2 ;;
        *)         log_error "未知参数: $1"; exit 1 ;;
    esac
done

# 检查是否为 root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请用 root 权限运行此脚本（sudo bash deploy.sh）"
        exit 1
    fi
}

# 检查 Docker
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_info "Docker 未安装，正在安装..."
        curl -fsSL https://get.docker.com | sh
        systemctl enable docker
        systemctl start docker
        log_ok "Docker 安装完成"
    else
        log_ok "Docker 已安装: $(docker --version)"
    fi
}

# 检查 Docker Compose
check_docker_compose() {
    if command -v docker-compose &> /dev/null; then
        log_ok "Docker Compose 已安装"
        DOCKER_COMPOSE="docker-compose"
    elif docker compose version &> /dev/null; then
        log_ok "Docker Compose (v2) 已安装"
        DOCKER_COMPOSE="docker compose"
    else
        log_info "Docker Compose 未安装，正在安装..."
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        log_ok "Docker Compose 安装完成"
        DOCKER_COMPOSE="docker-compose"
    fi
}

# 交互式配置
interactive_config() {
    echo ""
    echo "========================================"
    echo "   API Checker 部署配置"
    echo "========================================"
    echo ""

    read -p "管理员密码 [$ADMIN_PASSWORD]: " input
    [[ -n "$input" ]] && ADMIN_PASSWORD="$input"

    read -p "域名（留空则只用 IP 访问）: " input
    DOMAIN="$input"

    if [[ -n "$DOMAIN" ]]; then
        read -p "邮箱（用于 SSL 证书）: " input
        EMAIL="${input:-admin@example.com}"
    fi
}

# 拉取代码
pull_code() {
    local target="/opt/api-checker"

    if [[ -d "$target/.git" ]]; then
        log_info "代码已存在，更新中..."
        cd "$target"
        git pull
    else
        log_info "克隆代码到 $target ..."
        git clone https://github.com/Jimmy102836/api-checker "$target"
        cd "$target"
    fi

    log_ok "代码准备完成"
}

# Docker 部署
deploy_docker() {
    local target="/opt/api-checker"
    cd "$target"

    log_info "构建 Docker 镜像..."
    $DOCKER_COMPOSE build api-checker

    log_info "启动容器..."
    ADMIN_PASSWORD="$ADMIN_PASSWORD" $DOCKER_COMPOSE up -d api-checker

    sleep 3

    if $DOCKER_COMPOSE ps | grep -q "api-checker.*running"; then
        log_ok "API Checker 部署成功！"
    else
        log_error "容器启动失败，查看日志："
        $DOCKER_COMPOSE logs api-checker
        exit 1
    fi
}

# Nginx 配置
setup_nginx() {
    if [[ -z "$DOMAIN" ]]; then
        log_warn "未配置域名，跳过 Nginx"
        return
    fi

    log_info "配置 Nginx..."

    cat > /etc/nginx/sites-available/api-checker << EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
}
EOF

    ln -sf /etc/nginx/sites-available/api-checker /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx
    log_ok "Nginx 配置完成"
}

# SSL 证书
setup_ssl() {
    if [[ -z "$DOMAIN" ]]; then
        log_warn "未配置域名，跳过 SSL"
        return
    fi

    if ! command -v certbot &> /dev/null; then
        log_info "安装 Certbot..."
        apt-get update
        apt-get install -y certbot python3-certbot-nginx
    fi

    log_info "申请 SSL 证书..."
    certbot --nginx -d "$DOMAIN" --noninteractive --agree-tos -m "$EMAIL"

    # 自动续期
    systemctl enable certbot.timer
    systemctl start certbot.timer

    log_ok "SSL 证书申请完成"
}

# 显示结果
show_result() {
    echo ""
    echo "========================================"
    echo -e "${GREEN}   部署完成！${NC}"
    echo "========================================"
    echo ""

    if [[ -n "$DOMAIN" ]]; then
        echo -e "访问地址: ${BLUE}https://$DOMAIN${NC}"
    else
        echo -e "访问地址: ${BLUE}http://$(curl -s ifconfig.me):8000${NC}"
    fi

    echo ""
    echo "管理员后台: /admin"
    echo "管理员密码: $ADMIN_PASSWORD"
    echo ""
    echo "常用命令:"
    echo "  查看状态: cd /opt/api-checker && $DOCKER_COMPOSE ps"
    echo "  查看日志: cd /opt/api-checker && $DOCKER_COMPOSE logs -f"
    echo "  重启服务: cd /opt/api-checker && $DOCKER_COMPOSE restart"
    echo ""
}

# 主流程
main() {
    echo ""
    echo "========================================"
    echo "   API Checker 一键部署脚本"
    echo "========================================"

    check_root

    if [[ "$DEPLOY_TYPE" == "full" ]] && [[ -z "$DOMAIN" ]]; then
        interactive_config
    fi

    check_docker
    check_docker_compose
    pull_code
    deploy_docker

    if [[ "$DEPLOY_TYPE" == "full" ]]; then
        setup_nginx
        setup_ssl
    fi

    show_result
}

main "$@"
