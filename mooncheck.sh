#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
umask 077
if ! command -v docker >/dev/null 2>&1; then
  echo '请先安装 Docker Engine 和 Docker Compose。'; exit 1
fi
docker compose version >/dev/null
docker info >/dev/null
configure() {
  if [[ -f .env ]]; then return; fi
  read -r -p '网站域名（例如 checkin.example.com；直接回车为本机测试）: ' domain
  token=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
  if [[ -z "$domain" ]]; then
    sed "s/^SETUP_TOKEN=$/SETUP_TOKEN=$token/" .env.example > .env
    echo '本机地址：http://localhost:8080'
    echo '远程测试：在自己电脑执行 ssh -N -L 8080:127.0.0.1:8080 用户名@服务器IP'
  else
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] || [[ "$domain" != *.* ]]; then
      echo '请只填写域名，不要带 https://、端口或路径。'; exit 1
    fi
    printf 'DOMAIN=%s\nSITE_ADDRESS=%s\nBIND_IP=0.0.0.0\nHTTP_PORT=80\nHTTPS_PORT=443\nSECURE_COOKIE=1\nSETUP_TOKEN=%s\n' "$domain" "$domain" "$token" > .env
    printf '网站地址：https://%s\n请确认域名已解析到服务器，并放行 TCP 80、443 端口。\n' "$domain"
  fi
  printf '首次创建管理员时填写此设置令牌：%s\n' "$token"
  echo '令牌保存在 .env 的 SETUP_TOKEN 中；已有账号无需再次初始化。'
}
case "${1:-help}" in
  start|update)
    configure
    docker compose config --quiet
    docker compose up -d --build
    docker compose ps
    echo '已启动。如无法访问，运行 bash mooncheck.sh logs 查看原因。'
    ;;
  stop) docker compose down ;;
  restart) docker compose restart app gateway ;;
  status) docker compose ps ;;
  logs) docker compose logs --tail=100 -f app gateway ;;
  backup)
    [[ -f data/master.key && -f data/mooncheck.db ]] || { echo '未找到可备份的数据。'; exit 1; }
    mkdir -p backups
    destination="backups/mooncheck-$(date +%Y%m%d-%H%M%S)-$$.tar.gz"
    running=$(docker compose ps --status running -q app)
    if [[ -n "$running" ]]; then
      docker compose stop app
      trap 'docker compose start app' EXIT
    fi
    if [[ -f .env ]]; then tar -czf "$destination" data .env; else tar -czf "$destination" data; fi
    printf '备份已保存：%s\n包含账号密钥，请妥善保管。\n' "$destination"
    ;;
  *) echo '用法：bash mooncheck.sh {start|stop|restart|status|logs|backup|update}' ;;
esac
