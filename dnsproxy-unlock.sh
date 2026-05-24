#!/usr/bin/env bash

# ============================================================
# AdGuard dnsproxy 在线规则 DNS 分流解锁脚本
# GitHub: https://github.com/pjy02/dnsproxy-unlock.
#
# 功能：
# - 安装 / 更新 AdGuard dnsproxy
# - 在线拉取 Clash .list 规则
# - 转换 DOMAIN / DOMAIN-SUFFIX 为 dnsproxy upstream 格式
# - 不内置默认解锁 DNS / DoH
# - 用户自行输入解锁 DNS / DoH / DoT / DoQ / IPv4 DNS
# - 主菜单支持输入 dns / doh / unlock 快捷打开解锁 DNS 配置
# - 支持 systemd 服务
# - 支持 systemd timer 自动更新规则
# - 支持测试解析、状态查看、卸载恢复
# ============================================================

set -Eeuo pipefail

APP_DIR="/opt/dnsproxy"
BIN_PATH="${APP_DIR}/dnsproxy"
RUNNER_PATH="${APP_DIR}/run-dnsproxy.sh"
SCRIPT_COPY="${APP_DIR}/dnsproxy-unlock.sh"

CONFIG_FILE="${APP_DIR}/config.env"
SOURCE_FILE="${APP_DIR}/rule-sources.conf"
UPSTREAM_FILE="${APP_DIR}/upstream.txt"
IGNORED_LOG="${APP_DIR}/ignored-rules.log"
TMP_FILE="${APP_DIR}/upstream.txt.tmp"

SERVICE_FILE="/etc/systemd/system/dnsproxy.service"
UPDATE_SERVICE_FILE="/etc/systemd/system/dnsproxy-rule-update.service"
UPDATE_TIMER_FILE="/etc/systemd/system/dnsproxy-rule-update.timer"

RESOLV_CONF="/etc/resolv.conf"
RESOLV_BACKUP="/etc/resolv.conf.bak.dnsproxy"

DNSPROXY_FALLBACK_VERSION="v0.79.0"

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
NC="\033[0m"

BUILTIN_RULE_NAMES=(
  "YouTube"
)

BUILTIN_RULE_URLS=(
  "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/YouTube/YouTube.list"
)

# ============================================================
# 基础函数
# ============================================================

info() {
  echo -e "${BLUE}[INFO]${NC} $*"
}

ok() {
  echo -e "${GREEN}[OK]${NC} $*"
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

err() {
  echo -e "${RED}[ERROR]${NC} $*" >&2
}

pause() {
  echo
  read -rp "按回车继续..."
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "请使用 root 权限运行：sudo $0"
    exit 1
  fi
}

trim() {
  local s="$*"
  echo "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

lower() {
  echo "$*" | tr '[:upper:]' '[:lower:]'
}

upper() {
  echo "$*" | tr '[:lower:]' '[:upper:]'
}

ensure_dir() {
  mkdir -p "$APP_DIR"
}

install_self_copy() {
  ensure_dir

  if [[ -f "${0}" ]]; then
    install -m 0755 "$0" "$SCRIPT_COPY" 2>/dev/null || true
  fi
}

# ============================================================
# 系统依赖
# ============================================================

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  elif command -v apk >/dev/null 2>&1; then
    echo "apk"
  elif command -v pacman >/dev/null 2>&1; then
    echo "pacman"
  else
    echo "unknown"
  fi
}

install_dependencies() {
  local pm
  pm="$(detect_pkg_manager)"

  info "检查并安装依赖：curl tar gzip grep sed awk sort ss dig"

  case "$pm" in
    apt)
      apt-get update
      apt-get install -y curl tar gzip grep sed gawk coreutils iproute2 dnsutils ca-certificates
      ;;
    dnf)
      dnf install -y curl tar gzip grep sed gawk coreutils iproute bind-utils ca-certificates
      ;;
    yum)
      yum install -y curl tar gzip grep sed gawk coreutils iproute bind-utils ca-certificates
      ;;
    apk)
      apk add --no-cache curl tar gzip grep sed gawk coreutils iproute2 bind-tools ca-certificates
      ;;
    pacman)
      pacman -Sy --noconfirm curl tar gzip grep sed gawk coreutils iproute2 bind ca-certificates
      ;;
    *)
      warn "无法识别包管理器，请自行确保已安装 curl、tar、ss、dig。"
      ;;
  esac

  ok "依赖检查完成"
}

detect_arch() {
  local arch
  arch="$(uname -m)"

  case "$arch" in
    x86_64 | amd64)
      echo "amd64"
      ;;
    aarch64 | arm64)
      echo "arm64"
      ;;
    armv7l | armv7)
      echo "armv7"
      ;;
    armv6l | armv6)
      echo "armv6"
      ;;
    i386 | i686)
      echo "386"
      ;;
    *)
      err "暂不支持的架构：$arch"
      exit 1
      ;;
  esac
}

# ============================================================
# 配置文件
# ============================================================

create_default_files() {
  ensure_dir
  install_self_copy

  if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" << 'EOF'
# dnsproxy 基础配置
# 注意：这里是普通默认 DNS，不是解锁 DNS。
# 未命中分流规则的普通域名会走 DEFAULT_UPSTREAMS。
LISTEN_ADDR="127.0.0.1"
LISTEN_PORT="53"
DEFAULT_UPSTREAMS="1.1.1.1:53 8.8.8.8:53"
BOOTSTRAP_UPSTREAMS="1.1.1.1:53 8.8.8.8:53"
EOF
    ok "已创建默认配置：$CONFIG_FILE"
  fi

  if [[ ! -f "$SOURCE_FILE" ]]; then
    cat > "$SOURCE_FILE" << 'EOF'
# 在线规则源配置
# 格式：
# 分组名|规则URL|解锁DNS或DoH上游
#
# 示例：
# YouTube|https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/YouTube/YouTube.list|https://你的解锁服务商/doh
#
# 说明：
# - 本脚本不会内置默认解锁 DNS / DoH。
# - 请从 DNS 解锁服务商获取上游地址。
# - 推荐平台：
#   1. https://dns.akile.ai/
#   2. https://gaidns.com/
EOF
    ok "已创建规则源配置：$SOURCE_FILE"
  fi

  if [[ ! -f "$UPSTREAM_FILE" ]]; then
    cat > "$UPSTREAM_FILE" << 'EOF'
# dnsproxy upstream rules
# 当前还没有规则。
# 请运行脚本菜单：
# 3. 在线规则分组管理
# 或者在主菜单直接输入：
# dns
EOF
    ok "已创建空规则文件：$UPSTREAM_FILE"
  fi
}

load_config() {
  create_default_files
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
}

save_config_value() {
  local key="$1"
  local value="$2"

  create_default_files

  if grep -q "^${key}=" "$CONFIG_FILE"; then
    sed -i "s|^${key}=.*|${key}=\"${value}\"|" "$CONFIG_FILE"
  else
    echo "${key}=\"${value}\"" >> "$CONFIG_FILE"
  fi
}

# ============================================================
# DNS 上游规范化
# ============================================================

is_valid_ipv4() {
  local ip="$1"
  local IFS='.'
  local -a parts
  read -r -a parts <<< "$ip"

  [[ "${#parts[@]}" -eq 4 ]] || return 1

  local p
  for p in "${parts[@]}"; do
    [[ "$p" =~ ^[0-9]+$ ]] || return 1
    (( p >= 0 && p <= 255 )) || return 1
  done

  return 0
}

normalize_upstream() {
  local upstream
  upstream="$(trim "$1")"

  if [[ "$upstream" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "${upstream}:53"
    return 0
  fi

  echo "$upstream"
}

validate_upstream() {
  local upstream
  upstream="$(trim "$1")"

  [[ -n "$upstream" ]] || return 1

  if [[ "$upstream" =~ ^https:// ]]; then return 0; fi
  if [[ "$upstream" =~ ^http:// ]]; then return 0; fi
  if [[ "$upstream" =~ ^tls:// ]]; then return 0; fi
  if [[ "$upstream" =~ ^quic:// ]]; then return 0; fi
  if [[ "$upstream" =~ ^sdns:// ]]; then return 0; fi
  if [[ "$upstream" =~ ^tcp:// ]]; then return 0; fi
  if [[ "$upstream" =~ ^udp:// ]]; then return 0; fi
  if [[ "$upstream" =~ ^h3:// ]]; then return 0; fi

  if [[ "$upstream" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    is_valid_ipv4 "$upstream"
    return $?
  fi

  if [[ "$upstream" =~ ^(([0-9]{1,3}\.){3}[0-9]{1,3}):([0-9]{1,5})$ ]]; then
    local ip="${BASH_REMATCH[1]}"
    local port="${BASH_REMATCH[4]}"
    is_valid_ipv4 "$ip" || return 1
    (( port >= 1 && port <= 65535 )) || return 1
    return 0
  fi

  if [[ "$upstream" =~ ^[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]]; then
    return 0
  fi

  return 1
}

ask_unlock_upstream() {
  local upstream confirm

  echo
  echo "============================================================"
  echo " 配置解锁 DNS / DoH 上游"
  echo "============================================================"
  echo
  echo "本脚本不会内置任何默认解锁 DNS。"
  echo "请从你的 DNS 解锁服务商获取。"
  echo
  echo "推荐获取平台："
  echo "1. AKile DNS: https://dns.akile.ai/"
  echo "2. GaiDNS:    https://gaidns.com/"
  echo
  echo "支持输入格式："
  echo "  DoH:        https://example.com/doh"
  echo "  IPv4 DNS:   1.2.3.4"
  echo "  IPv4+端口:  1.2.3.4:53"
  echo "  DoT:        tls://example.com"
  echo "  DoQ:        quic://example.com"
  echo "  TCP DNS:    tcp://1.2.3.4"
  echo "  UDP DNS:    udp://1.2.3.4"
  echo

  while true; do
    read -rp "请输入解锁 DNS / DoH 上游地址: " upstream
    upstream="$(normalize_upstream "$upstream")"

    if ! validate_upstream "$upstream"; then
      warn "上游格式不合法，请重新输入。"
      continue
    fi

    echo
    echo "当前解锁上游：$upstream"
    read -rp "确认使用？[Y/n]: " confirm
    confirm="${confirm:-Y}"

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
      echo "$upstream"
      return 0
    fi
  done
}

# ============================================================
# dnsproxy 安装
# ============================================================

get_latest_dnsproxy_url() {
  local arch="$1"
  local api url

  api="https://api.github.com/repos/AdguardTeam/dnsproxy/releases/latest"

  url="$(curl -fsSL "$api" \
    | grep "browser_download_url" \
    | grep "linux-${arch}" \
    | grep "tar.gz" \
    | head -n 1 \
    | sed 's/.*"browser_download_url": "\(.*\)".*/\1/' || true)"

  if [[ -n "$url" ]]; then
    echo "$url"
    return 0
  fi

  echo "https://github.com/AdguardTeam/dnsproxy/releases/download/${DNSPROXY_FALLBACK_VERSION}/dnsproxy-linux-${arch}-${DNSPROXY_FALLBACK_VERSION}.tar.gz"
}

create_runner() {
  ensure_dir

  cat > "$RUNNER_PATH" << 'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/dnsproxy"
BIN_PATH="${APP_DIR}/dnsproxy"
CONFIG_FILE="${APP_DIR}/config.env"
UPSTREAM_FILE="${APP_DIR}/upstream.txt"

if [[ ! -x "$BIN_PATH" ]]; then
  echo "dnsproxy not found: $BIN_PATH" >&2
  exit 1
fi

if [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1}"
LISTEN_PORT="${LISTEN_PORT:-53}"
DEFAULT_UPSTREAMS="${DEFAULT_UPSTREAMS:-1.1.1.1:53 8.8.8.8:53}"
BOOTSTRAP_UPSTREAMS="${BOOTSTRAP_UPSTREAMS:-1.1.1.1:53 8.8.8.8:53}"

cmd=("$BIN_PATH" -l "$LISTEN_ADDR" -p "$LISTEN_PORT")

for upstream in $DEFAULT_UPSTREAMS; do
  [[ -n "$upstream" ]] && cmd+=(-u "$upstream")
done

if [[ -s "$UPSTREAM_FILE" ]]; then
  cmd+=(-u "$UPSTREAM_FILE")
fi

for bootstrap in $BOOTSTRAP_UPSTREAMS; do
  [[ -n "$bootstrap" ]] && cmd+=(-b "$bootstrap")
done

exec "${cmd[@]}"
EOF

  chmod +x "$RUNNER_PATH"
  ok "已创建运行脚本：$RUNNER_PATH"
}

create_systemd_service() {
  cat > "$SERVICE_FILE" << EOF
[Unit]
Description=AdGuard dnsproxy - DNS split by online rules
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${RUNNER_PATH}
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  ok "已创建 systemd 服务：$SERVICE_FILE"
}

install_or_update_dnsproxy() {
  require_root
  ensure_dir
  install_dependencies
  create_default_files

  local arch url tmp tgz extracted_bin
  arch="$(detect_arch)"
  url="$(get_latest_dnsproxy_url "$arch")"
  tmp="$(mktemp -d)"
  tgz="${tmp}/dnsproxy.tar.gz"

  info "系统架构：linux-${arch}"
  info "下载 dnsproxy：$url"

  if ! curl -fL --retry 3 --connect-timeout 15 -o "$tgz" "$url"; then
    err "dnsproxy 下载失败"
    rm -rf "$tmp"
    return 1
  fi

  tar xzf "$tgz" -C "$tmp"

  extracted_bin="$(find "$tmp" -type f -name dnsproxy | head -n 1 || true)"

  if [[ -z "$extracted_bin" ]]; then
    err "未找到 dnsproxy 可执行文件"
    rm -rf "$tmp"
    return 1
  fi

  install -m 0755 "$extracted_bin" "$BIN_PATH"
  rm -rf "$tmp"

  create_runner
  create_systemd_service

  ok "dnsproxy 安装 / 更新完成"
  "$BIN_PATH" --version || true

  echo
  read -rp "是否立即启动 dnsproxy？[Y/n]: " start_now
  start_now="${start_now:-Y}"

  if [[ "$start_now" =~ ^[Yy]$ ]]; then
    handle_port_conflict || true
    systemctl daemon-reload
    systemctl enable dnsproxy
    systemctl restart dnsproxy
    ok "dnsproxy 已启动"
  fi
}

# ============================================================
# 端口检测
# ============================================================

show_port_53_usage() {
  if command -v ss >/dev/null 2>&1; then
    ss -lntup 2>/dev/null | grep -E '(:53\s|:53$)' || true
  else
    warn "系统没有 ss 命令，无法检测 53 端口。"
  fi
}

is_port_53_used() {
  if command -v ss >/dev/null 2>&1; then
    ss -lntup 2>/dev/null | grep -qE '(:53\s|:53$)'
  else
    return 1
  fi
}

handle_port_conflict() {
  load_config

  if [[ "${LISTEN_PORT:-53}" != "53" ]]; then
    return 0
  fi

  if ! is_port_53_used; then
    return 0
  fi

  echo
  warn "检测到 53 端口可能已被占用："
  show_port_53_usage
  echo
  echo "请选择："
  echo "1. 继续，不处理"
  echo "2. 尝试停止并禁用 systemd-resolved"
  echo "3. 将 dnsproxy 监听端口改为 5353"
  echo "0. 返回"
  echo

  read -rp "请输入选项: " choice

  case "$choice" in
    1)
      warn "继续启动，若失败请查看日志。"
      ;;
    2)
      if systemctl list-unit-files | grep -q '^systemd-resolved.service'; then
        systemctl disable --now systemd-resolved || true
        ok "已尝试停止并禁用 systemd-resolved"
      else
        warn "未发现 systemd-resolved.service"
      fi
      ;;
    3)
      save_config_value "LISTEN_PORT" "5353"
      ok "已将监听端口改为 5353"
      warn "如果你要系统直接使用 dnsproxy，仍然建议监听 53。"
      ;;
    0)
      return 1
      ;;
    *)
      warn "无效选项，继续不处理。"
      ;;
  esac
}

# ============================================================
# 普通默认 DNS
# ============================================================

configure_default_dns() {
  require_root
  load_config

  echo
  echo "============================================================"
  echo " 配置普通默认 DNS"
  echo "============================================================"
  echo
  echo "说明：这里不是解锁 DNS。"
  echo "没有命中分流规则的普通域名，会走这里配置的 DNS。"
  echo
  echo "当前默认 DNS：${DEFAULT_UPSTREAMS:-未配置}"
  echo
  echo "请选择："
  echo "1. Cloudflare: 1.1.1.1 / 1.0.0.1"
  echo "2. Google:     8.8.8.8 / 8.8.4.4"
  echo "3. Quad9:      9.9.9.9 / 149.112.112.112"
  echo "4. 自定义"
  echo "0. 返回"
  echo

  read -rp "请输入选项: " choice

  local dns1 dns2 upstreams

  case "$choice" in
    1)
      upstreams="1.1.1.1:53 1.0.0.1:53"
      ;;
    2)
      upstreams="8.8.8.8:53 8.8.4.4:53"
      ;;
    3)
      upstreams="9.9.9.9:53 149.112.112.112:53"
      ;;
    4)
      read -rp "请输入第一个普通 DNS: " dns1
      read -rp "请输入第二个普通 DNS，可留空: " dns2
      dns1="$(normalize_upstream "$dns1")"
      dns2="$(normalize_upstream "$dns2")"

      if ! validate_upstream "$dns1"; then
        err "第一个 DNS 格式不合法"
        pause
        return 1
      fi

      if [[ -n "$dns2" ]] && ! validate_upstream "$dns2"; then
        err "第二个 DNS 格式不合法"
        pause
        return 1
      fi

      upstreams="$dns1"
      [[ -n "$dns2" ]] && upstreams="${upstreams} ${dns2}"
      ;;
    0)
      return 0
      ;;
    *)
      warn "无效选项"
      pause
      return 1
      ;;
  esac

  save_config_value "DEFAULT_UPSTREAMS" "$upstreams"
  save_config_value "BOOTSTRAP_UPSTREAMS" "$upstreams"

  ok "普通默认 DNS 已更新：$upstreams"

  if systemctl is-active --quiet dnsproxy; then
    systemctl restart dnsproxy
    ok "dnsproxy 已重启"
  fi

  pause
}

# ============================================================
# 在线规则管理
# ============================================================

list_rule_sources() {
  create_default_files

  echo
  echo "当前在线规则源："
  echo "------------------------------------------------------------"

  local n=0
  while IFS='|' read -r group url upstream; do
    group="$(trim "${group:-}")"
    url="$(trim "${url:-}")"
    upstream="$(trim "${upstream:-}")"

    [[ -z "$group" ]] && continue
    [[ "$group" =~ ^# ]] && continue

    n=$((n + 1))
    echo "${n}. 分组：$group"
    echo "   URL：$url"
    echo "   上游：$upstream"
    echo
  done < "$SOURCE_FILE"

  if [[ "$n" -eq 0 ]]; then
    echo "暂无已启用的在线规则源。"
  fi

  echo "------------------------------------------------------------"
}

upsert_rule_source() {
  local group="$1"
  local url="$2"
  local upstream="$3"

  create_default_files

  local tmp
  tmp="$(mktemp)"

  awk -F'|' -v g="$group" '
    BEGIN { OFS="|" }
    /^[[:space:]]*#/ { print; next }
    /^[[:space:]]*$/ { print; next }
    {
      name=$1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
      if (name != g) print
    }
  ' "$SOURCE_FILE" > "$tmp"

  echo "${group}|${url}|${upstream}" >> "$tmp"
  mv "$tmp" "$SOURCE_FILE"
}

add_builtin_rule_source() {
  local i choice idx group url upstream

  echo
  echo "可选内置在线规则链接："
  echo "------------------------------------------------------------"

  for i in "${!BUILTIN_RULE_NAMES[@]}"; do
    echo "$((i + 1)). ${BUILTIN_RULE_NAMES[$i]}"
    echo "   ${BUILTIN_RULE_URLS[$i]}"
  done

  echo "0. 返回"
  echo

  read -rp "请选择规则分组: " choice

  if [[ "$choice" == "0" ]]; then
    return 0
  fi

  if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
    warn "无效选项"
    return 1
  fi

  idx=$((choice - 1))

  if (( idx < 0 || idx >= ${#BUILTIN_RULE_NAMES[@]} )); then
    warn "无效选项"
    return 1
  fi

  group="${BUILTIN_RULE_NAMES[$idx]}"
  url="${BUILTIN_RULE_URLS[$idx]}"
  upstream="$(ask_unlock_upstream)"

  upsert_rule_source "$group" "$url" "$upstream"
  ok "已添加 / 更新规则源：$group"
}

add_custom_rule_source() {
  local group url upstream

  echo
  echo "============================================================"
  echo " 添加自定义在线规则源"
  echo "============================================================"
  echo
  echo "规则源应为 Clash .list 格式，例如："
  echo "DOMAIN-SUFFIX,youtube.com"
  echo "DOMAIN,example.com"
  echo
  echo "脚本只转换 DOMAIN / DOMAIN-SUFFIX。"
  echo "IP-CIDR、DOMAIN-KEYWORD 等会被忽略。"
  echo

  read -rp "请输入分组名称，例如 Netflix / ChatGPT / YouTube: " group
  group="$(trim "$group")"

  if [[ -z "$group" || "$group" == *"|"* ]]; then
    err "分组名不能为空，也不能包含 |"
    pause
    return 1
  fi

  read -rp "请输入在线规则 URL: " url
  url="$(trim "$url")"

  if [[ ! "$url" =~ ^https?:// ]]; then
    err "规则 URL 必须以 http:// 或 https:// 开头"
    pause
    return 1
  fi

  upstream="$(ask_unlock_upstream)"

  upsert_rule_source "$group" "$url" "$upstream"
  ok "已添加 / 更新自定义规则源：$group"
}

remove_rule_source() {
  create_default_files
  list_rule_sources

  echo
  read -rp "请输入要删除的分组名称，留空返回: " group
  group="$(trim "$group")"

  [[ -z "$group" ]] && return 0

  local tmp
  tmp="$(mktemp)"

  awk -F'|' -v g="$group" '
    BEGIN { OFS="|" }
    /^[[:space:]]*#/ { print; next }
    /^[[:space:]]*$/ { print; next }
    {
      name=$1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
      if (name != g) print
    }
  ' "$SOURCE_FILE" > "$tmp"

  mv "$tmp" "$SOURCE_FILE"
  ok "已删除分组：$group"
}

update_all_rule_sources_upstream() {
  create_default_files

  local upstream tmp count
  upstream="$(ask_unlock_upstream)"
  tmp="$(mktemp)"
  count=0

  awk -F'|' -v u="$upstream" '
    BEGIN { OFS="|" }
    /^[[:space:]]*#/ { print; next }
    /^[[:space:]]*$/ { print; next }
    {
      print $1, $2, u
    }
  ' "$SOURCE_FILE" > "$tmp"

  count="$(awk -F'|' '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    { n++ }
    END { print n+0 }
  ' "$SOURCE_FILE")"

  mv "$tmp" "$SOURCE_FILE"

  ok "已将全部规则分组的解锁上游修改为：$upstream"
  ok "影响分组数量：$count"
}

update_one_rule_source_upstream() {
  create_default_files
  list_rule_sources

  local group upstream tmp exists
  echo
  read -rp "请输入要修改的分组名称: " group
  group="$(trim "$group")"

  if [[ -z "$group" ]]; then
    warn "分组名不能为空"
    return 1
  fi

  exists="$(awk -F'|' -v g="$group" '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    {
      name=$1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
      if (name == g) found=1
    }
    END { print found+0 }
  ' "$SOURCE_FILE")"

  if [[ "$exists" != "1" ]]; then
    warn "没有找到分组：$group"
    return 1
  fi

  upstream="$(ask_unlock_upstream)"
  tmp="$(mktemp)"

  awk -F'|' -v g="$group" -v u="$upstream" '
    BEGIN { OFS="|" }
    /^[[:space:]]*#/ { print; next }
    /^[[:space:]]*$/ { print; next }
    {
      name=$1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
      if (name == g) {
        print $1, $2, u
      } else {
        print
      }
    }
  ' "$SOURCE_FILE" > "$tmp"

  mv "$tmp" "$SOURCE_FILE"

  ok "已修改分组 ${group} 的解锁上游为：$upstream"
}

unlock_dns_menu() {
  while true; do
    clear
    echo "============================================================"
    echo " 配置解锁 DNS / DoH 上游"
    echo "============================================================"
    echo
    echo "你可以在主菜单直接输入 dns / doh / unlock 打开这里。"
    echo
    echo "推荐获取 DNS 解锁服务："
    echo "1. https://dns.akile.ai/"
    echo "2. https://gaidns.com/"
    echo
    echo "当前规则源："
    list_rule_sources
    echo
    echo "菜单："
    echo "1. 修改全部已有规则分组的解锁 DNS / DoH"
    echo "2. 修改指定规则分组的解锁 DNS / DoH"
    echo "3. 添加内置规则分组并输入解锁 DNS / DoH"
    echo "4. 添加自定义规则链接并输入解锁 DNS / DoH"
    echo "5. 更新并转换在线规则"
    echo "0. 返回主菜单"
    echo

    read -rp "请输入选项: " choice

    case "$(lower "$(trim "$choice")")" in
      1)
        update_all_rule_sources_upstream
        pause
        ;;
      2)
        update_one_rule_source_upstream
        pause
        ;;
      3)
        add_builtin_rule_source
        pause
        ;;
      4)
        add_custom_rule_source
        pause
        ;;
      5)
        update_online_rules
        pause
        ;;
      0|q|quit|exit)
        return 0
        ;;
      *)
        warn "无效选项"
        pause
        ;;
    esac
  done
}

manage_rule_sources_menu() {
  while true; do
    clear
    echo "============================================================"
    echo " 在线规则分组管理"
    echo "============================================================"
    echo
    list_rule_sources
    echo
    echo "1. 添加内置在线规则链接"
    echo "2. 添加自定义在线规则链接"
    echo "3. 删除规则分组"
    echo "4. 修改全部规则分组的解锁 DNS / DoH"
    echo "5. 修改指定规则分组的解锁 DNS / DoH"
    echo "6. 更新并转换在线规则"
    echo "0. 返回主菜单"
    echo

    read -rp "请输入选项: " choice

    case "$(lower "$(trim "$choice")")" in
      1)
        add_builtin_rule_source
        pause
        ;;
      2)
        add_custom_rule_source
        pause
        ;;
      3)
        remove_rule_source
        pause
        ;;
      4)
        update_all_rule_sources_upstream
        pause
        ;;
      5)
        update_one_rule_source_upstream
        pause
        ;;
      6)
        update_online_rules
        pause
        ;;
      0|q|quit|exit)
        return 0
        ;;
      dns|doh|unlock)
        unlock_dns_menu
        ;;
      *)
        warn "无效选项"
        pause
        ;;
    esac
  done
}

# ============================================================
# 规则转换
# ============================================================

is_valid_domain() {
  local domain
  domain="$(trim "$1")"
  domain="$(lower "$domain")"

  [[ -n "$domain" ]] || return 1

  domain="${domain#+.}"
  domain="${domain#*.}"

  [[ -n "$domain" ]] || return 1
  [[ "$domain" =~ ^[a-z0-9._-]+$ ]] || return 1
  [[ ! "$domain" =~ ^[.-] ]] || return 1
  [[ ! "$domain" =~ [.-]$ ]] || return 1

  return 0
}

clean_domain_value() {
  local domain
  domain="$(trim "$1")"
  domain="$(lower "$domain")"

  domain="${domain%\"}"
  domain="${domain#\"}"
  domain="${domain%\'}"
  domain="${domain#\'}"

  domain="${domain#+.}"
  domain="${domain#*.}"

  echo "$domain"
}

convert_rule_line() {
  local line="$1"
  local upstream="$2"
  local group="$3"

  line="${line//$'\r'/}"
  line="$(trim "$line")"

  line="$(echo "$line" | sed 's/^[[:space:]]*-[[:space:]]*//')"
  line="$(trim "$line")"

  [[ -z "$line" ]] && return 0
  [[ "$line" =~ ^# ]] && return 0
  [[ "$line" =~ ^// ]] && return 0
  [[ "$line" =~ ^\; ]] && return 0
  [[ "$line" == "payload:" ]] && return 0
  [[ "$line" =~ ^payload: ]] && return 0

  if [[ "$line" != *,* ]]; then
    echo "[$group] ignored unsupported line: $line" >> "$IGNORED_LOG"
    return 0
  fi

  local type value
  type="${line%%,*}"
  value="${line#*,}"

  value="${value%%,*}"

  type="$(upper "$(trim "$type")")"
  value="$(clean_domain_value "$value")"

  case "$type" in
    DOMAIN|DOMAIN-SUFFIX)
      if is_valid_domain "$value"; then
        echo "[/${value}/]${upstream}" >> "$TMP_FILE"
      else
        echo "[$group] invalid domain: $line" >> "$IGNORED_LOG"
      fi
      ;;

    DOMAIN-KEYWORD)
      echo "[$group] ignored DOMAIN-KEYWORD: $line" >> "$IGNORED_LOG"
      ;;

    DOMAIN-WILDCARD)
      echo "[$group] ignored DOMAIN-WILDCARD: $line" >> "$IGNORED_LOG"
      ;;

    IP-CIDR|IP-CIDR6|IP-ASN|GEOIP|PROCESS-NAME|PROCESS-PATH|USER-AGENT|URL-REGEX|DST-PORT|SRC-PORT|RULE-SET|GEOSITE)
      echo "[$group] ignored non-domain rule: $line" >> "$IGNORED_LOG"
      ;;

    *)
      echo "[$group] ignored unknown rule: $line" >> "$IGNORED_LOG"
      ;;
  esac
}

download_and_convert_group() {
  local group="$1"
  local url="$2"
  local upstream="$3"

  group="$(trim "$group")"
  url="$(trim "$url")"
  upstream="$(normalize_upstream "$(trim "$upstream")")"

  if [[ -z "$group" || -z "$url" || -z "$upstream" ]]; then
    err "规则源配置错误：${group}|${url}|${upstream}"
    return 1
  fi

  if [[ ! "$url" =~ ^https?:// ]]; then
    err "规则 URL 非法：$url"
    return 1
  fi

  if ! validate_upstream "$upstream"; then
    err "上游地址非法：$upstream"
    return 1
  fi

  echo
  info "正在更新分组：$group"
  info "规则 URL：$url"
  info "解锁上游：$upstream"

  echo "" >> "$TMP_FILE"
  echo "# ---------- ${group} ----------" >> "$TMP_FILE"

  local content
  if ! content="$(curl -fsSL --retry 3 --connect-timeout 15 "$url")"; then
    err "下载失败：$group"
    return 1
  fi

  while IFS= read -r line; do
    convert_rule_line "$line" "$upstream" "$group"
  done <<< "$content"

  ok "分组转换完成：$group"
}

update_online_rules() {
  require_root
  ensure_dir
  create_default_files

  : > "$TMP_FILE"
  : > "$IGNORED_LOG"

  {
    echo "# =================================================="
    echo "# dnsproxy upstream rules"
    echo "# Auto generated at: $(date '+%F %T')"
    echo "# Source file: $SOURCE_FILE"
    echo "# =================================================="
    echo
  } >> "$TMP_FILE"

  local success_count=0
  local total_count=0

  while IFS='|' read -r group url upstream; do
    group="$(trim "${group:-}")"
    url="$(trim "${url:-}")"
    upstream="$(trim "${upstream:-}")"

    [[ -z "$group" ]] && continue
    [[ "$group" =~ ^# ]] && continue

    total_count=$((total_count + 1))

    if download_and_convert_group "$group" "$url" "$upstream"; then
      success_count=$((success_count + 1))
    else
      warn "分组更新失败：$group"
    fi
  done < "$SOURCE_FILE"

  if [[ "$total_count" -eq 0 ]]; then
    rm -f "$TMP_FILE"
    warn "没有配置任何在线规则源。"
    echo "你可以在主菜单输入 dns，然后添加规则分组。"
    return 1
  fi

  if [[ "$success_count" -eq 0 ]]; then
    rm -f "$TMP_FILE"
    err "所有规则源都更新失败，未覆盖旧规则。"
    return 1
  fi

  local dedup_file
  dedup_file="$(mktemp)"

  {
    grep '^#' "$TMP_FILE" || true
    grep '^\[/' "$TMP_FILE" | sort -u || true
  } > "$dedup_file"

  mv "$dedup_file" "$UPSTREAM_FILE"
  rm -f "$TMP_FILE"

  local rule_count ignored_count
  rule_count="$(grep -c '^\[/' "$UPSTREAM_FILE" || true)"
  ignored_count="$(wc -l < "$IGNORED_LOG" 2>/dev/null || echo 0)"

  ok "规则更新完成：$UPSTREAM_FILE"
  ok "有效规则数量：$rule_count"
  ok "忽略规则数量：$ignored_count"
  info "忽略详情：$IGNORED_LOG"

  if systemctl is-active --quiet dnsproxy; then
    systemctl restart dnsproxy
    ok "dnsproxy 已重启"
  else
    warn "dnsproxy 当前未运行。可执行：systemctl start dnsproxy"
  fi
}

# ============================================================
# 自动更新
# ============================================================

install_update_timer() {
  require_root
  ensure_dir
  install_self_copy

  if [[ ! -x "$SCRIPT_COPY" ]]; then
    err "没有找到脚本副本：$SCRIPT_COPY"
    err "请先运行：1. 安装 / 更新 dnsproxy"
    pause
    return 1
  fi

  cat > "$UPDATE_SERVICE_FILE" << EOF
[Unit]
Description=Update dnsproxy online rules

[Service]
Type=oneshot
ExecStart=${SCRIPT_COPY} --update-rules
EOF

  cat > "${APP_DIR}/update-rules.sh" << EOF
#!/usr/bin/env bash
exec ${SCRIPT_COPY} --update-rules
EOF

  chmod +x "${APP_DIR}/update-rules.sh"

  cat > "$UPDATE_TIMER_FILE" << 'EOF'
[Unit]
Description=Run dnsproxy rule update daily

[Timer]
OnCalendar=*-*-* 04:30:00
Persistent=true
RandomizedDelaySec=600

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now dnsproxy-rule-update.timer

  ok "已启用自动更新规则 timer"
  systemctl list-timers | grep dnsproxy || true
  pause
}

disable_update_timer() {
  require_root

  systemctl disable --now dnsproxy-rule-update.timer 2>/dev/null || true
  rm -f "$UPDATE_TIMER_FILE" "$UPDATE_SERVICE_FILE"

  systemctl daemon-reload

  ok "已禁用规则自动更新 timer"
  pause
}

# ============================================================
# 系统 DNS
# ============================================================

apply_system_dns() {
  require_root
  load_config

  echo
  echo "============================================================"
  echo " 应用系统 DNS"
  echo "============================================================"
  echo
  echo "这会把系统 DNS 指向 dnsproxy："
  echo "nameserver ${LISTEN_ADDR}"
  echo
  echo "当前 dnsproxy 监听：${LISTEN_ADDR}:${LISTEN_PORT}"
  echo

  if [[ "${LISTEN_PORT}" != "53" ]]; then
    warn "当前监听端口不是 53。"
    warn "resolv.conf 不能指定端口，所以系统 DNS 可能无法直接使用它。"
    warn "建议把 LISTEN_PORT 改回 53。"
    pause
    return 1
  fi

  read -rp "确认修改 /etc/resolv.conf？[y/N]: " confirm
  confirm="${confirm:-N}"

  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    warn "已取消"
    pause
    return 0
  fi

  if command -v chattr >/dev/null 2>&1; then
    chattr -i "$RESOLV_CONF" 2>/dev/null || true
  fi

  if [[ ! -f "$RESOLV_BACKUP" ]]; then
    if [[ -e "$RESOLV_CONF" ]]; then
      cp -aL "$RESOLV_CONF" "$RESOLV_BACKUP" || true
      ok "已备份：$RESOLV_BACKUP"
    fi
  else
    warn "备份已存在：$RESOLV_BACKUP"
  fi

  rm -f "$RESOLV_CONF"
  cat > "$RESOLV_CONF" << EOF
nameserver ${LISTEN_ADDR}
options edns0 trust-ad
EOF

  ok "已写入 $RESOLV_CONF"

  echo
  read -rp "是否锁定 /etc/resolv.conf 防止被覆盖？不建议默认开启。[y/N]: " lock_confirm
  lock_confirm="${lock_confirm:-N}"

  if [[ "$lock_confirm" =~ ^[Yy]$ ]]; then
    if command -v chattr >/dev/null 2>&1; then
      chattr +i "$RESOLV_CONF"
      ok "已锁定 /etc/resolv.conf"
      warn "以后要修改 DNS，请先执行：chattr -i /etc/resolv.conf"
    else
      warn "系统没有 chattr，无法锁定。"
    fi
  fi

  pause
}

restore_system_dns() {
  require_root

  if command -v chattr >/dev/null 2>&1; then
    chattr -i "$RESOLV_CONF" 2>/dev/null || true
  fi

  if [[ -f "$RESOLV_BACKUP" ]]; then
    rm -f "$RESOLV_CONF"
    cp -a "$RESOLV_BACKUP" "$RESOLV_CONF"
    ok "已恢复备份：$RESOLV_BACKUP -> $RESOLV_CONF"
  else
    warn "没有找到备份：$RESOLV_BACKUP"
    warn "将写入一个临时公共 DNS 配置。"
    cat > "$RESOLV_CONF" << 'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
  fi

  pause
}

# ============================================================
# 状态、日志、测试
# ============================================================

show_status() {
  echo
  echo "============================================================"
  echo " dnsproxy 状态"
  echo "============================================================"
  echo

  if [[ -x "$BIN_PATH" ]]; then
    "$BIN_PATH" --version || true
  else
    warn "dnsproxy 未安装：$BIN_PATH"
  fi

  echo
  echo "配置文件：$CONFIG_FILE"
  [[ -f "$CONFIG_FILE" ]] && cat "$CONFIG_FILE" || true

  echo
  list_rule_sources

  echo
  echo "有效 upstream 规则数量："
  if [[ -f "$UPSTREAM_FILE" ]]; then
    grep -c '^\[/' "$UPSTREAM_FILE" || true
  else
    echo "0"
  fi

  echo
  echo "systemd 状态："
  systemctl status dnsproxy --no-pager || true

  echo
  echo "53 端口占用："
  show_port_53_usage

  pause
}

show_logs() {
  journalctl -u dnsproxy -n 100 --no-pager || true
  echo
  read -rp "是否继续实时查看日志？[y/N]: " follow
  follow="${follow:-N}"

  if [[ "$follow" =~ ^[Yy]$ ]]; then
    journalctl -u dnsproxy -f
  fi
}

test_dns() {
  load_config

  local domain server port

  server="${LISTEN_ADDR:-127.0.0.1}"
  port="${LISTEN_PORT:-53}"

  echo
  read -rp "请输入要测试的域名，例如 youtube.com: " domain
  domain="$(trim "$domain")"

  if [[ -z "$domain" ]]; then
    warn "域名不能为空"
    pause
    return 1
  fi

  if ! command -v dig >/dev/null 2>&1; then
    warn "dig 未安装，正在尝试安装依赖。"
    install_dependencies
  fi

  echo
  info "测试：dig +short @${server} -p ${port} ${domain}"
  echo "------------------------------------------------------------"
  dig +short @"$server" -p "$port" "$domain" || true
  echo "------------------------------------------------------------"

  echo
  info "完整查询："
  dig @"$server" -p "$port" "$domain" || true

  pause
}

preview_upstream_rules() {
  if [[ ! -f "$UPSTREAM_FILE" ]]; then
    warn "规则文件不存在：$UPSTREAM_FILE"
    pause
    return 1
  fi

  echo
  echo "前 100 行规则："
  echo "------------------------------------------------------------"
  sed -n '1,100p' "$UPSTREAM_FILE"
  echo "------------------------------------------------------------"
  pause
}

preview_ignored_rules() {
  if [[ ! -f "$IGNORED_LOG" ]]; then
    warn "忽略日志不存在：$IGNORED_LOG"
    pause
    return 1
  fi

  echo
  echo "前 200 行忽略规则："
  echo "------------------------------------------------------------"
  sed -n '1,200p' "$IGNORED_LOG"
  echo "------------------------------------------------------------"
  pause
}

# ============================================================
# 服务控制
# ============================================================

start_dnsproxy() {
  require_root
  handle_port_conflict || true
  systemctl daemon-reload
  systemctl enable dnsproxy
  systemctl restart dnsproxy
  ok "dnsproxy 已启动 / 重启"
  pause
}

stop_dnsproxy() {
  require_root
  systemctl stop dnsproxy || true
  ok "dnsproxy 已停止"
  pause
}

# ============================================================
# 卸载
# ============================================================

uninstall_dnsproxy() {
  require_root

  echo
  warn "将卸载 dnsproxy，并删除："
  echo "$APP_DIR"
  echo "$SERVICE_FILE"
  echo "$UPDATE_SERVICE_FILE"
  echo "$UPDATE_TIMER_FILE"
  echo
  echo "可选恢复 /etc/resolv.conf。"
  echo

  read -rp "确认卸载？[y/N]: " confirm
  confirm="${confirm:-N}"

  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    warn "已取消"
    pause
    return 0
  fi

  if command -v chattr >/dev/null 2>&1; then
    chattr -i "$RESOLV_CONF" 2>/dev/null || true
  fi

  systemctl disable --now dnsproxy 2>/dev/null || true
  systemctl disable --now dnsproxy-rule-update.timer 2>/dev/null || true

  rm -f "$SERVICE_FILE" "$UPDATE_SERVICE_FILE" "$UPDATE_TIMER_FILE"
  systemctl daemon-reload

  read -rp "是否恢复 /etc/resolv.conf 备份？[Y/n]: " restore
  restore="${restore:-Y}"

  if [[ "$restore" =~ ^[Yy]$ ]]; then
    if [[ -f "$RESOLV_BACKUP" ]]; then
      rm -f "$RESOLV_CONF"
      cp -a "$RESOLV_BACKUP" "$RESOLV_CONF"
      ok "已恢复 /etc/resolv.conf"
    else
      warn "没有找到备份，跳过恢复。"
    fi
  fi

  rm -rf "$APP_DIR"

  ok "dnsproxy 已卸载"
  pause
}

# ============================================================
# 主菜单
# ============================================================

main_menu() {
  require_root
  create_default_files

  while true; do
    clear
    echo "============================================================"
    echo " AdGuard dnsproxy 在线规则 DNS 分流解锁脚本"
    echo "============================================================"
    echo
    echo "推荐获取 DNS 解锁服务："
    echo "1. https://dns.akile.ai/"
    echo "2. https://gaidns.com/"
    echo
    echo "说明："
    echo "- 本脚本不内置默认解锁 DNS / DoH。"
    echo "- 解锁上游需要你自己从服务商获取并输入。"
    echo "- 普通 IPv4 DNS 例如 1.1.1.1 支持作为 dnsproxy 上游。"
    echo "- 但 1.1.1.1 是普通公共 DNS，不是解锁 DNS。"
    echo
    echo "快捷命令："
    echo "- 输入 dns / doh / unlock 可直接配置解锁 DNS / DoH。"
    echo
    echo "菜单："
    echo "1. 安装 / 更新 dnsproxy"
    echo "2. 配置普通默认 DNS"
    echo "3. 在线规则分组管理"
    echo "4. 更新并转换在线规则"
    echo "5. 启动 / 重启 dnsproxy"
    echo "6. 停止 dnsproxy"
    echo "7. 应用系统 DNS 到 127.0.0.1"
    echo "8. 恢复系统 DNS 备份"
    echo "9. 测试域名解析"
    echo "10. 查看状态"
    echo "11. 查看日志"
    echo "12. 预览生成的 upstream 规则"
    echo "13. 查看被忽略的规则"
    echo "14. 启用规则自动更新"
    echo "15. 禁用规则自动更新"
    echo "16. 卸载 dnsproxy"
    echo "0. 退出"
    echo

    read -rp "请输入选项: " choice
    choice="$(lower "$(trim "$choice")")"

    case "$choice" in
      dns|doh|unlock)
        unlock_dns_menu
        ;;
      1)
        install_or_update_dnsproxy
        pause
        ;;
      2)
        configure_default_dns
        ;;
      3)
        manage_rule_sources_menu
        ;;
      4)
        update_online_rules
        pause
        ;;
      5)
        start_dnsproxy
        ;;
      6)
        stop_dnsproxy
        ;;
      7)
        apply_system_dns
        ;;
      8)
        restore_system_dns
        ;;
      9)
        test_dns
        ;;
      10)
        show_status
        ;;
      11)
        show_logs
        pause
        ;;
      12)
        preview_upstream_rules
        ;;
      13)
        preview_ignored_rules
        ;;
      14)
        install_update_timer
        ;;
      15)
        disable_update_timer
        ;;
      16)
        uninstall_dnsproxy
        ;;
      0|q|quit|exit)
        exit 0
        ;;
      *)
        warn "无效选项"
        pause
        ;;
    esac
  done
}

# ============================================================
# 参数模式
# ============================================================

if [[ "${1:-}" == "--update-rules" ]]; then
  require_root
  update_online_rules
  exit 0
fi

main_menu
