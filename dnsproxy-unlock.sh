#!/usr/bin/env bash

# ============================================================
# AdGuard dnsproxy 在线规则 DNS 分流解锁脚本
# 功能：
# - 安装 / 更新 AdGuard dnsproxy
# - 在线拉取 Clash .list 规则
# - 转换 DOMAIN / DOMAIN-SUFFIX 为 dnsproxy upstream 格式
# - 不内置默认解锁 DNS / DoH
# - 用户自行输入解锁 DNS / DoH / DoT / DoQ / IPv4 DNS
# - 支持 systemd 服务
# - 支持 systemd timer 自动更新规则
# - 支持测试解析、状态查看、系统 DNS 管理、备份 / 恢复、卸载恢复
# ============================================================

set -Eeuo pipefail

APP_NAME="dnsproxy-unlock"
APP_DIR="/opt/dnsproxy"
BIN_PATH="${APP_DIR}/dnsproxy"
RUNNER_PATH="${APP_DIR}/run-dnsproxy.sh"
CONFIG_FILE="${APP_DIR}/config.env"
SOURCE_FILE="${APP_DIR}/rule-sources.conf"
UPSTREAM_FILE="${APP_DIR}/upstream.txt"
IGNORED_LOG="${APP_DIR}/ignored-rules.log"
TMP_FILE="${APP_DIR}/upstream.txt.tmp"
LOCK_FILE="${APP_DIR}/.update.lock"

SERVICE_FILE="/etc/systemd/system/dnsproxy.service"
UPDATE_SERVICE_FILE="/etc/systemd/system/dnsproxy-rule-update.service"
UPDATE_TIMER_FILE="/etc/systemd/system/dnsproxy-rule-update.timer"

RESOLV_CONF="/etc/resolv.conf"
RESOLV_BACKUP="/etc/resolv.conf.bak.dnsproxy"
RESOLV_LINK_BACKUP="/etc/resolv.conf.bak.dnsproxy.link"
RESOLV_BACKUP_DIR="/etc/dnsproxy-resolv-backups"

DNSPROXY_FALLBACK_VERSION="v0.79.0"
MENU_SCRIPT_PATH="${APP_DIR}/dnsproxy-unlock.sh"
DNS_CMD_PATH="/usr/local/bin/dns"

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m"

# 内置规则分组（可直接选择，无需手填 URL）
# URL 统一按 blackmatrix7 规则仓库推导：
# https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/<Group>/<Group>.list
BUILTIN_RULE_NAMES=(
  "YouTube"
  "Netflix"
  "Disney"
  "TikTok"
  "Telegram"
  "OpenAI"
  "Claude"
  "Gemini"
  "Spotify"
  "Bahamut"
)

BUILTIN_RULE_BASE_URL="https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash"


# AKile DNS 候选上游。这里只做延迟测速：使用 dig 对同一测试域名多次查询，取平均响应时间；不代表一定解锁成功。
AKILE_DNS_LIST=(
  "66.66.66.66"
  "45.207.157.146"
  "108.160.138.51"
  "139.180.133.239"
  "45.76.83.113"
  "45.76.71.83"
  "45.63.99.176"
  "166.0.199.207"
)

# GaiDNS DoH 候选上游。这里只做连接延迟测速；不代表一定解锁成功。
GAIDNS_DOH_LIST=(
  "https://hk.gaidns.top/doh"
  "https://sg.gaidns.top/doh"
  "https://us.gaidns.top/doh"
)

DNS_SPEED_TEST_DOMAIN="www.google.com"
DNS_SPEED_TEST_COUNT="5"
DNS_SPEED_TEST_TIMEOUT="1"

# ============================================================
# 基础输出
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

require_systemd() {
  if ! command -v systemctl >/dev/null 2>&1; then
    err "当前系统没有 systemctl，本脚本依赖 systemd 管理 dnsproxy 服务和自动更新 timer。"
    err "暂不支持 OpenRC / SysVinit / 无 systemd 的容器环境。"
    exit 1
  fi

  if [[ ! -d /run/systemd/system ]]; then
    err "当前环境未检测到正在运行的 systemd：/run/systemd/system 不存在。"
    err "本脚本需要 systemd 管理服务、开机启动和规则自动更新 timer。"
    err "请在支持 systemd 的 VPS / 服务器上运行，或先启用 systemd 后再执行。"
    exit 1
  fi
}

# FIX: 使用 printf 替代 echo，避免含反引号或 $(...) 的输入被 shell 展开
trim() {
  local s="$1"
  printf '%s' "$s" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
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

# ============================================================
# 系统检测和依赖安装
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

# FIX: 先检测关键工具是否已存在，避免每次都执行 apt-get update
install_dependencies() {
  local pm
  pm="$(detect_pkg_manager)"

  if command -v curl  >/dev/null 2>&1 && \
     command -v dig   >/dev/null 2>&1 && \
     command -v ss    >/dev/null 2>&1 && \
     command -v awk   >/dev/null 2>&1 && \
     command -v flock >/dev/null 2>&1; then
    ok "依赖已满足，跳过安装"
    return 0
  fi

  info "检查并安装依赖：curl tar gzip grep sed awk sort ss dig flock"

  case "$pm" in
    apt)
      apt-get update -q
      apt-get install -y curl tar gzip grep sed gawk coreutils iproute2 dnsutils util-linux ca-certificates
      ;;
    dnf)
      dnf install -y curl tar gzip grep sed gawk coreutils iproute bind-utils util-linux ca-certificates
      ;;
    yum)
      yum install -y curl tar gzip grep sed gawk coreutils iproute bind-utils util-linux ca-certificates
      ;;
    apk)
      apk add --no-cache curl tar gzip grep sed gawk coreutils iproute2 bind-tools util-linux ca-certificates
      ;;
    pacman)
      pacman -Sy --noconfirm curl tar gzip grep sed gawk coreutils iproute2 bind util-linux ca-certificates
      ;;
    *)
      warn "无法识别包管理器，请自行确保已安装 curl、tar、ss、dig、flock。"
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

create_default_config_if_missing() {
  ensure_dir

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
# 3. 添加在线规则分组
# 4. 更新并转换在线规则
EOF
    ok "已创建空规则文件：$UPSTREAM_FILE"
  fi
}

load_config() {
  create_default_config_if_missing
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
}

# FIX: 改用删除旧行+追加新行，避免 sed 的 | 分隔符与值内容冲突
# FIX: 写入 config.env 时使用 Bash 安全转义，避免 source 配置文件时被特殊字符破坏或执行。
save_config_value() {
  local key="$1"
  local value="$2"
  local quoted_value

  create_default_config_if_missing

  if [[ ! "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
    err "配置键名非法：$key"
    return 1
  fi

  # 删除已有的同名 key 行（key 只允许大写字母、数字和下划线，模式安全）
  sed -i "/^${key}=/d" "$CONFIG_FILE"

  # 使用 Bash 的 %q 生成可被 source 安全读取的字面量。
  printf -v quoted_value '%q' "$value"
  printf '%s=%s\n' "$key" "$quoted_value" >> "$CONFIG_FILE"
}

# ============================================================
# upstream 规范化与校验
# ============================================================

normalize_upstream() {
  local upstream
  upstream="$(trim "$1")"

  # 纯 IPv4 自动补 :53
  if [[ "$upstream" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "${upstream}:53"
    return 0
  fi

  # 纯 IPv6 自动补成 [IPv6]:53，避免与端口分隔符混淆。
  # 已带协议的 DoH/DoT/DoQ/TCP/UDP 不处理。
  if [[ "$upstream" != *"://"* && "$upstream" != \[*\] && "$upstream" =~ ^[0-9A-Fa-f:]+$ && "$upstream" == *:* ]]; then
    echo "[${upstream}]:53"
    return 0
  fi

  echo "$upstream"
}

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

is_valid_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 1
  (( port >= 1 && port <= 65535 )) || return 1
  return 0
}

is_valid_hostname() {
  local host="$1"
  local label
  local IFS='.'
  local -a labels

  [[ -n "$host" ]] || return 1
  [[ "$host" == "localhost" ]] && return 0
  [[ "$host" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
  [[ "$host" != .* && "$host" != *. && "$host" != *..* ]] || return 1

  read -r -a labels <<< "$host"
  (( ${#labels[@]} >= 2 )) || return 1

  for label in "${labels[@]}"; do
    [[ -n "$label" ]] || return 1
    (( ${#label} <= 63 )) || return 1
    [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
  done

  return 0
}

validate_host_port() {
  local hostport="$1"
  local host port

  [[ -n "$hostport" ]] || return 1
  [[ "$hostport" != */* ]] || return 1
  [[ "$hostport" != *@* ]] || return 1

  # [IPv6] 或 [IPv6]:port
  if [[ "$hostport" =~ ^\[([0-9A-Fa-f:]+)\](:([0-9]{1,5}))?$ ]]; then
    [[ "${BASH_REMATCH[1]}" == *:* ]] || return 1
    if [[ -n "${BASH_REMATCH[3]:-}" ]]; then
      is_valid_port "${BASH_REMATCH[3]}" || return 1
    fi
    return 0
  fi

  # 未加 [] 的 IPv6 不允许带协议使用，避免和端口分隔符混淆。
  if [[ "$hostport" == *:*:* ]]; then
    return 1
  fi

  if [[ "$hostport" == *:* ]]; then
    host="${hostport%%:*}"
    port="${hostport##*:}"
    is_valid_port "$port" || return 1
  else
    host="$hostport"
  fi

  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    is_valid_ipv4 "$host"
    return $?
  fi

  is_valid_hostname "$host"
}

validate_url_upstream() {
  local upstream="$1"
  local scheme rest hostport

  [[ "$upstream" =~ ^(https|tls|quic|sdns|tcp|udp|h3)://(.+)$ ]] || return 1
  scheme="${BASH_REMATCH[1]}"
  rest="${BASH_REMATCH[2]}"

  [[ -n "$rest" ]] || return 1

  # 拒绝空白、引号、反引号和常见 shell 元字符，避免写入 config.env 后造成歧义。
  # 注意：http:// 不再视为合法 DoH，上游 URL 建议使用 https://。
  [[ "$rest" != *[[:space:]]* ]] || return 1
  [[ "$rest" != *\"* ]] || return 1
  [[ "$rest" != *\'* ]] || return 1
  [[ "$rest" != *\`* ]] || return 1
  [[ "$rest" != *\$* ]] || return 1
  [[ "$rest" != *\;* ]] || return 1
  [[ "$rest" != *\|* ]] || return 1
  [[ "$rest" != *\&* ]] || return 1
  [[ "$rest" != *\<* ]] || return 1
  [[ "$rest" != *\>* ]] || return 1

  case "$scheme" in
    sdns)
      # DNS stamp。保持相对宽松，但仍限制为常见 URL-safe 字符。
      [[ "$rest" =~ ^[A-Za-z0-9._~+=/-]+$ ]] || return 1
      return 0
      ;;
    https|h3)
      # DoH / HTTP3 DoH：允许 path / query，但 host 部分必须合法。
      hostport="${rest%%/*}"
      validate_host_port "$hostport"
      return $?
      ;;
    tls|quic|tcp|udp)
      # DoT / DoQ / TCP / UDP：只接受 host[:port] 或 [IPv6][:port]。
      validate_host_port "$rest"
      return $?
      ;;
  esac

  return 1
}

validate_upstream() {
  local upstream
  upstream="$(trim "$1")"

  [[ -n "$upstream" ]] || return 1

  # 带协议的上游：DoH / DoT / DoQ / DNSCrypt stamp / TCP / UDP / HTTP3 DoH。
  # 不接受 http://，DoH 请使用 https://。
  if [[ "$upstream" == *"://"* ]]; then
    validate_url_upstream "$upstream"
    return $?
  fi

  # IPv4
  if [[ "$upstream" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    is_valid_ipv4 "$upstream"
    return $?
  fi

  # IPv4:port
  if [[ "$upstream" =~ ^(([0-9]{1,3}\.){3}[0-9]{1,3}):([0-9]{1,5})$ ]]; then
    local ip="${BASH_REMATCH[1]}"
    local port="${BASH_REMATCH[3]}"
    is_valid_ipv4 "$ip" || return 1
    is_valid_port "$port" || return 1
    return 0
  fi

  # IPv6，推荐格式：[2606:4700:4700::1111]:53
  if [[ "$upstream" =~ ^\[([0-9A-Fa-f:]+)\]:([0-9]{1,5})$ ]]; then
    local port="${BASH_REMATCH[2]}"
    [[ "${BASH_REMATCH[1]}" == *:* ]] || return 1
    is_valid_port "$port" || return 1
    return 0
  fi

  # 纯 IPv6，不带端口。normalize_upstream 会自动转成 [IPv6]:53。
  if [[ "$upstream" =~ ^[0-9A-Fa-f:]+$ && "$upstream" == *:* ]]; then
    return 0
  fi

  # 域名:端口
  if [[ "$upstream" == *:* ]]; then
    local host="${upstream%%:*}"
    local port="${upstream##*:}"
    is_valid_hostname "$host" || return 1
    is_valid_port "$port" || return 1
    return 0
  fi

  # 纯域名
  is_valid_hostname "$upstream"
}

ASKED_UPSTREAM=""

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
      ASKED_UPSTREAM="$upstream"
      return 0
    fi
  done
}

# ============================================================
# 安装 dnsproxy
# ============================================================

# FIX: 校验 GitHub API 返回的下载 URL 必须来自 github.com/AdguardTeam
get_latest_dnsproxy_url() {
  local arch="$1"
  local api url

  api="https://api.github.com/repos/AdguardTeam/dnsproxy/releases/latest"

  url="$(curl -fsSL --connect-timeout 10 "$api" \
    | grep "browser_download_url" \
    | grep "linux-${arch}" \
    | grep "tar.gz" \
    | head -n 1 \
    | sed 's/.*"browser_download_url": "\(.*\)".*/\1/' || true)"

  if [[ -n "$url" ]]; then
    if [[ "$url" =~ ^https://github\.com/AdguardTeam/ ]]; then
      echo "$url"
      return 0
    else
      warn "GitHub API 返回了不可信的下载地址，使用内置回退版本。"
    fi
  fi

  echo "https://github.com/AdguardTeam/dnsproxy/releases/download/${DNSPROXY_FALLBACK_VERSION}/dnsproxy-linux-${arch}-${DNSPROXY_FALLBACK_VERSION}.tar.gz"
}

install_or_update_dnsproxy() {
  require_root
  ensure_dir
  install_dependencies

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
    exit 1
  fi

  tar xzf "$tgz" -C "$tmp"

  extracted_bin="$(find "$tmp" -type f -name dnsproxy | head -n 1 || true)"

  if [[ -z "$extracted_bin" ]]; then
    err "未找到 dnsproxy 可执行文件"
    rm -rf "$tmp"
    exit 1
  fi

  install -m 0755 "$extracted_bin" "$BIN_PATH"
  rm -rf "$tmp"

  create_default_config_if_missing

  info "安装流程：自动配置普通默认 DNS（根据 IPv4 / IPv6 使用 Cloudflare + Google）"
  local auto_default_upstreams
  if auto_default_upstreams="$(build_auto_default_upstreams)"; then
    save_config_value "DEFAULT_UPSTREAMS" "$auto_default_upstreams"
    save_config_value "BOOTSTRAP_UPSTREAMS" "$auto_default_upstreams"
    ok "普通默认 DNS 已自动配置：$auto_default_upstreams"
  else
    warn "普通默认 DNS 自动配置失败，保留当前配置。"
    warn "安装完成后可进入菜单 2「系统 DNS 管理」配置普通默认 DNS。"
  fi

  install_menu_command
  create_runner
  create_systemd_service

  ok "dnsproxy 安装 / 更新完成"
  "$BIN_PATH" --version || true

  echo
  read -rp "是否立即启动 dnsproxy？[Y/n]: " start_now
  start_now="${start_now:-Y}"

  if [[ "$start_now" =~ ^[Yy]$ ]]; then
    if ! handle_port_conflict; then
      warn "已取消启动 dnsproxy。"
      return 0
    fi
    systemctl daemon-reload
    systemctl enable dnsproxy
    systemctl restart dnsproxy
    ok "dnsproxy 已启动"
    verify_dnsproxy_running
  fi
}


# FIX: 检测 BASH_SOURCE[0] 是否有效（curl|bash 管道执行时为空或 /dev/stdin）
# FIX: 安装 dns 命令前检测是否与系统已有命令冲突
install_menu_command() {
  ensure_dir

  local script_source="${BASH_SOURCE[0]:-}"

  # 管道执行时无法获取脚本路径，跳过菜单命令安装
  if [[ -z "$script_source" || "$script_source" == "/dev/stdin" ]]; then
    warn "检测到以管道方式运行，跳过菜单命令安装。"
    warn "请将脚本下载到本地后重新执行，以启用 'dns' 快捷命令。"
    return 0
  fi

  script_source="$(readlink -f -- "$script_source")"
  local target_source
  target_source="$(readlink -f -- "$MENU_SCRIPT_PATH" 2>/dev/null || true)"

  if [[ "$script_source" != "$target_source" ]]; then
    install -m 0755 "$script_source" "$MENU_SCRIPT_PATH"
  fi

  # 检测 dns 命令是否已被其他程序占用
  if [[ -e "$DNS_CMD_PATH" ]] && ! grep -q "dnsproxy" "$DNS_CMD_PATH" 2>/dev/null; then
    warn "$DNS_CMD_PATH 已存在且不属于本脚本（可能是系统命令）"
    read -rp "确认覆盖？[y/N]: " confirm
    confirm="${confirm:-N}"
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
      warn "已跳过创建 'dns' 快捷命令"
      return 0
    fi
  fi

  cat > "$DNS_CMD_PATH" << EOF
#!/usr/bin/env bash
exec "${MENU_SCRIPT_PATH}" "\$@"
EOF

  chmod +x "$DNS_CMD_PATH"
  ok "已创建命令：dns -> $DNS_CMD_PATH"
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

# ============================================================
# 启动后健康检查
# ============================================================

# FIX: 新增函数，重启服务后自动验证解析是否正常
verify_dnsproxy_running() {
  load_config

  local server="${LISTEN_ADDR:-127.0.0.1}"
  local port="${LISTEN_PORT:-53}"

  info "等待 dnsproxy 就绪..."
  sleep 1

  if ! command -v dig >/dev/null 2>&1; then
    warn "dig 未安装，跳过解析验证。"
    return 0
  fi

  if dig +short +time=2 +tries=1 @"$server" -p "$port" cloudflare.com >/dev/null 2>&1; then
    ok "解析测试通过（@${server}:${port} -> cloudflare.com）"
  else
    warn "解析测试失败，dnsproxy 可能未正常工作。"
    warn "请查看日志：journalctl -u dnsproxy -n 30 --no-pager"
  fi
}

# ============================================================
# 53 端口冲突处理
# ============================================================

# 获取所有 53 端口监听行。
# 使用 ss -H 去掉表头，避免 grep 到标题行。
get_port_53_usage() {
  if command -v ss >/dev/null 2>&1; then
    ss -H -lntup 2>/dev/null | awk '$5 ~ /:53$/ { print }' || true
  else
    return 1
  fi
}

show_port_53_usage() {
  if ! command -v ss >/dev/null 2>&1; then
    warn "系统没有 ss 命令，无法检测 53 端口。"
    return 0
  fi

  local usage
  usage="$(get_port_53_usage || true)"

  if [[ -n "$usage" ]]; then
    printf '%s\n' "$usage"
  else
    echo "未发现 53 端口监听。"
  fi
}

is_port_53_used() {
  local usage
  usage="$(get_port_53_usage || true)"
  [[ -n "$usage" ]]
}

# 判断 53 端口是否真的与当前 dnsproxy 监听地址冲突。
# 重点修复：如果 53 端口是 dnsproxy 自己占用，不算冲突。
# 同时避免把 127.0.0.53:53 这类不影响 127.0.0.1:53 的监听误判为冲突。
get_port_53_conflict_usage() {
  local listen_addr="${1:-127.0.0.1}"

  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi

  get_port_53_usage | awk -v la="$listen_addr" '
    {
      local_addr = $5
      conflict = 0

      # 如果 dnsproxy 配置为通配监听，则任何 53 端口监听都可能冲突。
      if (la == "0.0.0.0" || la == "::" || la == "[::]" || la == "*") {
        conflict = 1
      }

      # 精确匹配当前监听地址。
      if (local_addr == la ":53" || local_addr == "[" la "]:53") {
        conflict = 1
      }

      # 通配监听会占住端口，通常会影响 127.0.0.1:53。
      if (local_addr == "0.0.0.0:53" || local_addr == "*:53" || local_addr == "[::]:53" || local_addr == ":::53") {
        conflict = 1
      }

      if (conflict) {
        print
      }
    }
  ' | grep -v 'users:(("dnsproxy"' || true
}

is_port_53_conflicted() {
  local listen_addr="${1:-127.0.0.1}"
  local conflicts
  conflicts="$(get_port_53_conflict_usage "$listen_addr" || true)"
  [[ -n "$conflicts" ]]
}

handle_port_conflict() {
  load_config

  if [[ "${LISTEN_PORT:-53}" != "53" ]]; then
    return 0
  fi

  local listen_addr all_usage conflict_usage
  listen_addr="${LISTEN_ADDR:-127.0.0.1}"
  all_usage="$(get_port_53_usage || true)"

  # 没有任何 53 端口监听，不冲突。
  if [[ -z "$all_usage" ]]; then
    return 0
  fi

  conflict_usage="$(get_port_53_conflict_usage "$listen_addr" || true)"

  # 只有 dnsproxy 自己占用，或者其他地址占用但不影响当前监听地址，不弹冲突菜单。
  if [[ -z "$conflict_usage" ]]; then
    if printf '%s\n' "$all_usage" | grep -q 'users:(("dnsproxy"'; then
      info "53 端口当前由 dnsproxy 使用，属于正常状态，跳过冲突处理。"
    else
      info "53 端口已有监听，但不影响当前监听地址 ${listen_addr}:53，跳过冲突处理。"
    fi
    return 0
  fi

  echo
  warn "检测到 ${listen_addr}:53 可能被非 dnsproxy 进程占用："
  printf '%s\n' "$conflict_usage"
  echo
  echo "全部 53 端口监听情况："
  show_port_53_usage
  echo
  echo "如果 53 端口被 systemd-resolved、dnsmasq、named 等占用，dnsproxy 可能启动失败。"
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
# 普通默认 DNS 自动检测
# ============================================================

has_ipv4_network() {
  if command -v ip >/dev/null 2>&1; then
    ip -4 route get 1.1.1.1 >/dev/null 2>&1 && return 0
    ip -4 addr show scope global 2>/dev/null | grep -q 'inet ' && return 0
  fi

  return 1
}

has_ipv6_network() {
  if command -v ip >/dev/null 2>&1; then
    ip -6 route get 2606:4700:4700::1111 >/dev/null 2>&1 && return 0
    if ip -6 route show default 2>/dev/null | grep -q '^default' && \
       ip -6 addr show scope global 2>/dev/null | grep -q 'inet6 '; then
      return 0
    fi
  fi

  return 1
}

build_auto_default_upstreams() {
  local -a upstream_list=()
  local has_v4="否"
  local has_v6="否"

  if has_ipv4_network; then
    has_v4="是"
    upstream_list+=("1.1.1.1:53" "8.8.8.8:53")
  fi

  if has_ipv6_network; then
    has_v6="是"
    upstream_list+=("[2606:4700:4700::1111]:53" "[2001:4860:4860::8888]:53")
  fi

  info "检测结果：IPv4=${has_v4}，IPv6=${has_v6}" >&2

  if (( ${#upstream_list[@]} == 0 )); then
    return 1
  fi

  printf '%s' "${upstream_list[*]}"
}

# ============================================================
# 普通默认 DNS 配置
# ============================================================

configure_default_dns() {
  require_root
  load_config

  echo
  echo "============================================================"
  echo " 配置普通默认 DNS"
  echo "============================================================"
  echo
  echo "说明："
  echo "这里不是解锁 DNS。"
  echo "没有命中分流规则的普通域名，会走这里配置的 DNS。"
  echo
  echo "当前默认 DNS：${DEFAULT_UPSTREAMS:-未配置}"
  echo
  echo "请选择："
  echo "1. 自动配置：检测服务器 IPv4 / IPv6，使用 Cloudflare + Google"
  echo "2. Cloudflare IPv4: 1.1.1.1 / 1.0.0.1"
  echo "3. Google IPv4:     8.8.8.8 / 8.8.4.4"
  echo "4. Quad9 IPv4:      9.9.9.9 / 149.112.112.112"
  echo "5. 自定义"
  echo "0. 返回"
  echo

  read -rp "请输入选项: " choice

  local dns1 dns2 upstreams

  case "$choice" in
    1)
      if ! upstreams="$(build_auto_default_upstreams)"; then
        err "自动检测失败：未检测到可用 IPv4 或 IPv6 网络。"
        warn "请检查服务器网络，或选择自定义 DNS。"
        pause
        return 1
      fi
      ok "自动配置结果：$upstreams"
      ;;
    2)
      upstreams="1.1.1.1:53 1.0.0.1:53"
      ;;
    3)
      upstreams="8.8.8.8:53 8.8.4.4:53"
      ;;
    4)
      upstreams="9.9.9.9:53 149.112.112.112:53"
      ;;
    5)
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
# 在线规则源管理
# ============================================================

list_rule_sources() {
  create_default_config_if_missing

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
    echo "   上游：$upstream"
    echo
  done < "$SOURCE_FILE"

  if [[ "$n" -eq 0 ]]; then
    echo "暂无已启用的在线规则源。"
  fi

  echo "------------------------------------------------------------"
}

build_builtin_rule_url() {
  local group="$1"
  echo "${BUILTIN_RULE_BASE_URL}/${group}/${group}.list"
}

SELECTED_RULE_GROUPS=()

select_builtin_rule_groups() {
  local i selected group idx token
  SELECTED_RULE_GROUPS=()

  echo
  echo "可选内置规则分组："
  echo "------------------------------------------------------------"
  for i in "${!BUILTIN_RULE_NAMES[@]}"; do
    echo "$((i + 1)). ${BUILTIN_RULE_NAMES[$i]}"
  done
  echo "a. 全选内置分组"
  echo "v. 查看某个分组的规则 URL"
  echo "0. 返回"
  echo
  echo "支持多选：例如 1,2,6 或 1 2 6"
  read -rp "请选择规则分组: " selected
  selected="$(trim "$selected")"

  [[ -z "$selected" || "$selected" == "0" ]] && return 1

  if [[ "$selected" =~ ^[Vv]$ ]]; then
    read -rp "输入分组编号查看 URL: " token
    if [[ "$token" =~ ^[0-9]+$ ]]; then
      idx=$((token - 1))
      if (( idx >= 0 && idx < ${#BUILTIN_RULE_NAMES[@]} )); then
        group="${BUILTIN_RULE_NAMES[$idx]}"
        info "$group -> $(build_builtin_rule_url "$group")"
      else
        warn "编号无效"
      fi
    else
      warn "编号无效"
    fi
    return 1
  fi

  if [[ "$selected" =~ ^[Aa]$ ]]; then
    for i in "${!BUILTIN_RULE_NAMES[@]}"; do
      SELECTED_RULE_GROUPS+=("${BUILTIN_RULE_NAMES[$i]}")
    done
    return 0
  fi

  selected="${selected//,/ }"
  local seen=" "
  for token in $selected; do
    if ! [[ "$token" =~ ^[0-9]+$ ]]; then
      warn "已跳过无效输入：$token"
      continue
    fi

    idx=$((token - 1))
    if (( idx < 0 || idx >= ${#BUILTIN_RULE_NAMES[@]} )); then
      warn "已跳过无效编号：$token"
      continue
    fi

    group="${BUILTIN_RULE_NAMES[$idx]}"
    if [[ "$seen" == *" $group "* ]]; then
      continue
    fi
    seen="${seen}${group} "
    SELECTED_RULE_GROUPS+=("$group")
  done

  if (( ${#SELECTED_RULE_GROUPS[@]} == 0 )); then
    warn "没有选择任何有效分组"
    return 1
  fi

  return 0
}

upsert_selected_builtin_rule_groups() {
  local upstream="$1"
  local provider_name="${2:-解锁上游}"
  local group url added=0

  upstream="$(normalize_upstream "$upstream")"
  if ! validate_upstream "$upstream"; then
    err "上游地址非法：$upstream"
    return 1
  fi

  for group in "${SELECTED_RULE_GROUPS[@]}"; do
    url="$(build_builtin_rule_url "$group")"
    upsert_rule_source "$group" "$url" "$upstream"
    added=$((added + 1))
  done

  ok "已使用 ${provider_name} 添加 / 更新 ${added} 个内置分组"
  ok "解锁上游：$upstream"
}

run_ipv4_dns_latency_test() {
  local domain="${DNS_SPEED_TEST_DOMAIN:-www.google.com}"
  local count="${DNS_SPEED_TEST_COUNT:-5}"
  local timeout="${DNS_SPEED_TEST_TIMEOUT:-1}"
  local -a dns_list=("$@")
  local tmpdir dns i t safe result_file result best_avg best_dns

  if ! command -v dig >/dev/null 2>&1; then
    warn "dig 未安装，正在尝试安装依赖。"
    install_dependencies
  fi

  if ! command -v dig >/dev/null 2>&1; then
    err "dig 仍然不可用，无法测速。"
    return 1
  fi

  tmpdir="$(mktemp -d)"
  result_file="${tmpdir}/result"

  echo
  echo "AKile DNS 延迟测试"
  echo "测试域名：$domain"
  echo "测试次数：${count} 次 / DNS，超时：${timeout}s"
  echo "------------------------------------------------------------"
  info "正在进行延迟测速，请稍候..."

  for dns in "${dns_list[@]}"; do
    safe="${dns//./_}"
    safe="${safe//:/_}"
    for ((i = 1; i <= count; i++)); do
      (
        t="$(dig @"$dns" "$domain" +stats +time="$timeout" +tries=1 2>/dev/null | awk '/Query time/ {print $4; exit}')"
        if [[ "$t" =~ ^[0-9]+$ ]]; then
          echo "$dns $t"
        else
          echo "$dns 1000"
        fi
      ) > "${tmpdir}/result_${safe}_${i}" &
    done
  done

  wait
  cat "${tmpdir}"/result_* > "$result_file" 2>/dev/null || true

  if [[ ! -s "$result_file" ]]; then
    rm -rf "$tmpdir"
    err "测速失败：未获取到任何结果"
    return 1
  fi

  result="$(awk '
    {
      sum[$1] += $2
      cnt[$1]++
    }
    END {
      for (dns in sum) {
        avg = sum[dns] / cnt[dns]
        printf "%d %s\n", avg, dns
      }
    }
  ' "$result_file" | sort -n)"

  echo
  echo "平均响应时间："
  echo "------------------------------------------------------------"
  echo "$result" | awk '{printf "  %s ms\t%s\n", $1, $2}'
  echo "------------------------------------------------------------"

  best_avg="$(echo "$result" | head -n 1 | awk '{print $1}')"
  best_dns="$(echo "$result" | head -n 1 | awk '{print $2}')"

  if [[ -z "$best_dns" || -z "$best_avg" || "$best_avg" -ge 1000 ]]; then
    rm -rf "$tmpdir"
    err "所有 AKile DNS 延迟测速均超时，未能选出候选 DNS。"
    return 1
  fi

  ASKED_UPSTREAM="$(normalize_upstream "$best_dns")"
  ok "最低延迟 AKile DNS：${ASKED_UPSTREAM}（${best_avg}ms）"

  echo
  read -rp "确认使用当前最低延迟的 AKile DNS？[Y/n]: " confirm
  confirm="${confirm:-Y}"
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    rm -rf "$tmpdir"
    return 0
  fi

  echo
  echo "请选择要使用的 AKile DNS："
  mapfile -t sorted_lines <<< "$result"
  for i in "${!sorted_lines[@]}"; do
    local avg dns_ip
    avg="$(awk '{print $1}' <<< "${sorted_lines[$i]}")"
    dns_ip="$(awk '{print $2}' <<< "${sorted_lines[$i]}")"
    echo "$((i + 1)). ${dns_ip}:53 (${avg}ms)"
  done
  echo "0. 取消"
  echo

  read -rp "请输入选项: " choice
  if [[ "$choice" == "0" || -z "$choice" ]]; then
    rm -rf "$tmpdir"
    warn "已取消 AKile DNS 配置"
    return 1
  fi

  if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#sorted_lines[@]} )); then
    rm -rf "$tmpdir"
    err "无效选项"
    return 1
  fi

  best_dns="$(awk '{print $2}' <<< "${sorted_lines[$((choice - 1))]}")"
  ASKED_UPSTREAM="$(normalize_upstream "$best_dns")"
  ok "已选择 AKile DNS：$ASKED_UPSTREAM"

  rm -rf "$tmpdir"
  return 0
}

select_akile_upstream() {
  ASKED_UPSTREAM=""
  run_ipv4_dns_latency_test "${AKILE_DNS_LIST[@]}"
}

run_https_latency_test() {
  local -a urls=("$@")
  local url t ms result best_ms best_url

  if ! command -v curl >/dev/null 2>&1; then
    warn "curl 未安装，正在尝试安装依赖。"
    install_dependencies
  fi

  if ! command -v curl >/dev/null 2>&1; then
    err "curl 仍然不可用，无法测速。"
    return 1
  fi

  echo
  echo "GaiDNS DoH 连接延迟测试"
  echo "------------------------------------------------------------"

  result=""
  for url in "${urls[@]}"; do
    t="$(curl -o /dev/null -s -L --connect-timeout 3 --max-time 5 -w '%{time_total}' "$url" 2>/dev/null || echo "5")"
    ms="$(awk -v t="$t" 'BEGIN { printf "%d", t * 1000 }')"
    [[ -n "$ms" ]] || ms="5000"
    printf '  %s ms\t%s\n' "$ms" "$url"
    result+="${ms} ${url}"$'\n'
  done

  best_ms="$(printf '%s' "$result" | sort -n | head -n 1 | awk '{print $1}')"
  best_url="$(printf '%s' "$result" | sort -n | head -n 1 | cut -d' ' -f2-)"

  if [[ -z "$best_url" || -z "$best_ms" || "$best_ms" -ge 5000 ]]; then
    err "GaiDNS DoH 连接延迟测速失败，未能选出候选上游。"
    return 1
  fi

  ASKED_UPSTREAM="$best_url"
  echo "------------------------------------------------------------"
  ok "最低连接延迟 GaiDNS DoH：${ASKED_UPSTREAM}（${best_ms}ms）"
}

select_gaidns_upstream() {
  local choice confirm
  ASKED_UPSTREAM=""

  echo
  echo "请选择 GaiDNS DoH 上游："
  echo "1. 香港：${GAIDNS_DOH_LIST[0]}"
  echo "2. 新加坡：${GAIDNS_DOH_LIST[1]}"
  echo "3. 美国：${GAIDNS_DOH_LIST[2]}"
  echo "4. 自动延迟测速选择最低连接延迟"
  echo "0. 返回"
  echo
  read -rp "请输入选项: " choice

  case "$choice" in
    1)
      ASKED_UPSTREAM="${GAIDNS_DOH_LIST[0]}"
      ;;
    2)
      ASKED_UPSTREAM="${GAIDNS_DOH_LIST[1]}"
      ;;
    3)
      ASKED_UPSTREAM="${GAIDNS_DOH_LIST[2]}"
      ;;
    4)
      run_https_latency_test "${GAIDNS_DOH_LIST[@]}" || return 1
      echo
      read -rp "确认使用该 GaiDNS DoH？[Y/n]: " confirm
      confirm="${confirm:-Y}"
      [[ "$confirm" =~ ^[Yy]$ ]] || return 1
      ;;
    0|"")
      return 1
      ;;
    *)
      warn "无效选项"
      return 1
      ;;
  esac

  if ! validate_upstream "$ASKED_UPSTREAM"; then
    err "GaiDNS 上游格式非法：$ASKED_UPSTREAM"
    return 1
  fi

  ok "已选择 GaiDNS DoH：$ASKED_UPSTREAM"
  return 0
}

post_rule_source_apply_prompt() {
  local apply_now

  echo
  read -rp "是否立即一键应用（更新规则 + dnsproxy 接管系统 DNS）？[y/N]: " apply_now
  apply_now="${apply_now:-N}"

  if [[ "$apply_now" =~ ^[Yy]$ ]]; then
    apply_rules_and_enable_system_dns
  else
    ok "规则分组配置已保存，可继续配置其他分组，稍后再一键应用。"
    pause
  fi
}

add_builtin_rule_source() {
  select_builtin_rule_groups || return 0
  ask_unlock_upstream
  upsert_selected_builtin_rule_groups "$ASKED_UPSTREAM" "手动解锁上游"
  post_rule_source_apply_prompt
}

add_akile_rule_source() {
  select_builtin_rule_groups || return 0
  select_akile_upstream || return 1
  upsert_selected_builtin_rule_groups "$ASKED_UPSTREAM" "AKile DNS"
  post_rule_source_apply_prompt
}

add_gaidns_rule_source() {
  select_builtin_rule_groups || return 0
  select_gaidns_upstream || return 1
  upsert_selected_builtin_rule_groups "$ASKED_UPSTREAM" "GaiDNS DoH"
  post_rule_source_apply_prompt
}

add_custom_rule_source() {
  local group url upstream

  echo
  echo "============================================================"
  echo " 添加自定义在线规则源"
  echo "============================================================"
  echo
  echo "可只输入分组名自动推导 URL（默认开启）。"

  read -rp "请输入分组名称，例如 Netflix / ChatGPT / YouTube: " group
  group="$(trim "$group")"

  if [[ -z "$group" || "$group" == *"|"* ]]; then
    err "分组名不能为空，也不能包含 |"
    pause
    return 1
  fi

  read -rp "是否按分组名自动推导规则 URL？[Y/n]: " auto_url
  auto_url="${auto_url:-Y}"

  if [[ "$auto_url" =~ ^[Yy]$ ]]; then
    url="$(build_builtin_rule_url "$group")"
  else
    read -rp "请输入在线规则 URL: " url
    url="$(trim "$url")"
    if [[ ! "$url" =~ ^https?:// ]]; then
      err "规则 URL 必须以 http:// 或 https:// 开头"
      pause
      return 1
    fi
  fi

  ask_unlock_upstream
  upstream="$ASKED_UPSTREAM"
  upsert_rule_source "$group" "$url" "$upstream"
  ok "已添加 / 更新自定义规则源：$group"
}


upsert_rule_source() {
  local group="$1"
  local url="$2"
  local upstream="$3"

  create_default_config_if_missing

  local tmp
  tmp="$(mktemp)"

  # 删除同名分组
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

remove_rule_source() {
  create_default_config_if_missing
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

manage_rule_sources_menu() {
  while true; do
    clear
    echo "============================================================"
    echo " 在线规则分组管理"
    echo "============================================================"
    echo
    list_rule_sources
    echo
    echo "1. 选择内置规则分组（手动输入解锁上游）"
    echo "2. 使用 AKile DNS 延迟测速添加内置分组"
    echo "3. 使用 GaiDNS DoH 添加内置分组"
    echo "4. 添加自定义分组（可自动推导 URL）"
    echo "5. 删除规则分组"
    echo "6. 一键应用（更新规则 + dnsproxy 接管系统 DNS）"
    echo "0. 返回主菜单"
    echo

    read -rp "请输入选项: " choice

    case "$choice" in
      1)
        add_builtin_rule_source
        ;;
      2)
        add_akile_rule_source
        ;;
      3)
        add_gaidns_rule_source
        ;;
      4)
        add_custom_rule_source
        ;;
      5)
        remove_rule_source
        pause
        ;;
      6)
        apply_rules_and_enable_system_dns
        ;;
      0)
        return 0
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

  # 去除常见前缀（仅处理 +. 和 *.）
  domain="${domain#+.}"
  if [[ "$domain" == \*.* ]]; then
    domain="${domain#*.}"
  fi

  [[ -n "$domain" ]] || return 1

  # 不允许明显非法字符
  [[ "$domain" =~ ^[a-z0-9._-]+$ ]] || return 1

  # 不允许以点或横线开头/结尾
  [[ ! "$domain" =~ ^[.-] ]] || return 1
  [[ ! "$domain" =~ [.-]$ ]] || return 1

  return 0
}

clean_domain_value() {
  local domain
  domain="$(trim "$1")"
  domain="$(lower "$domain")"

  # 去掉 Clash rule-provider yaml 的引号
  domain="${domain%\"}"
  domain="${domain#\"}"
  domain="${domain%\'}"
  domain="${domain#\'}"

  # 去掉通配和 +. 前缀
  domain="${domain#+.}"
  if [[ "$domain" == \*.* ]]; then
    domain="${domain#*.}"
  fi

  echo "$domain"
}

convert_rule_line() {
  local line="$1"
  local upstream="$2"
  local group="$3"

  line="${line//$'\r'/}"
  line="$(trim "$line")"

  # 兼容 YAML rule-provider:
  # - DOMAIN-SUFFIX,example.com
  line="$(echo "$line" | sed 's/^[[:space:]]*-[[:space:]]*//')"
  line="$(trim "$line")"

  [[ -z "$line" ]] && return 0

  # 跳过注释
  [[ "$line" =~ ^# ]] && return 0
  [[ "$line" =~ ^// ]] && return 0
  [[ "$line" =~ ^\; ]] && return 0

  # 跳过 yaml 结构
  [[ "$line" == "payload:" ]] && return 0
  [[ "$line" =~ ^payload: ]] && return 0

  if [[ "$line" != *,* ]]; then
    echo "[$group] ignored unsupported line: $line" >> "$IGNORED_LOG"
    return 0
  fi

  local type value
  type="${line%%,*}"
  value="${line#*,}"

  # 删除第三字段，例如 no-resolve
  value="${value%%,*}"

  type="$(upper "$(trim "$type")")"
  value="$(clean_domain_value "$value")"

  case "$type" in
    DOMAIN)
      # Clash 的 DOMAIN 是精确域名规则；dnsproxy 的 [/$value/] 规则通常会同时覆盖该域名和子域名。
      # dnsproxy upstream 文件没有完全等价的 Clash DOMAIN 精确匹配表达，所以这里保留原转换方式，并在生成文件头部写明语义差异。
      if is_valid_domain "$value"; then
        echo "[/${value}/]${upstream}" >> "$TMP_FILE"
      else
        echo "[$group] invalid domain: $line" >> "$IGNORED_LOG"
      fi
      ;;

    DOMAIN-SUFFIX)
      # Clash 的 DOMAIN-SUFFIX 与 dnsproxy [/$value/] 的使用目的更接近：让该域名及其子域名走指定上游。
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
      # dnsproxy 没有 Clash DOMAIN-WILDCARD 的完全等价表达。
      # 为避免复杂 wildcard 误伤，默认忽略；如需支持 *.example.com，建议改用 DOMAIN-SUFFIX,example.com。
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

# FIX: 使用 flock 防止并发更新破坏规则文件
# FIX: 修复去重逻辑，改用 awk 保序去重，不再分离注释和规则
update_online_rules() {
  require_root
  ensure_dir
  create_default_config_if_missing

  if ! command -v flock >/dev/null 2>&1; then
    err "缺少 flock 命令，无法安全更新规则。请安装 util-linux 后重试。"
    return 1
  fi

  # 并发锁：同一时间只允许一个更新进程运行
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    warn "另一个规则更新进程正在运行，请稍后再试。"
    exec 9>&-
    return 1
  fi

  : > "$TMP_FILE"
  : > "$IGNORED_LOG"

  {
    echo "# =================================================="
    echo "# dnsproxy upstream rules"
    echo "# Auto generated at: $(date '+%F %T')"
    echo "# Source file: $SOURCE_FILE"
    echo "# Note:"
    echo "# - Clash DOMAIN and DOMAIN-SUFFIX are both converted to dnsproxy [/<domain>/]<upstream>."
    echo "# - dnsproxy [/<domain>/] usually covers the domain and its subdomains."
    echo "# - Therefore Clash DOMAIN exact-match semantics cannot be preserved perfectly."
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
    exec 9>&-
    warn "没有配置任何在线规则源。"
    echo "请先添加规则源。"
    return 1
  fi

  if [[ "$success_count" -eq 0 ]]; then
    rm -f "$TMP_FILE"
    exec 9>&-
    err "所有规则源都更新失败，未覆盖旧规则。"
    return 1
  fi

  # 规则去重：注释行原样保留，规则行（[/.../)按内容去重，保持原始顺序
  local dedup_file
  dedup_file="$(mktemp)"

  awk '
    /^#/            { print; next }
    /^[[:space:]]*$/ { print; next }
    !seen[$0]++     { print }
  ' "$TMP_FILE" > "$dedup_file"

  mv "$dedup_file" "$UPSTREAM_FILE"
  rm -f "$TMP_FILE"

  # 释放锁
  exec 9>&-

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
# 自动更新 timer
# ============================================================

install_update_timer() {
  require_root
  ensure_dir

  cat > "$UPDATE_SERVICE_FILE" << EOF
[Unit]
Description=Update dnsproxy online rules

[Service]
Type=oneshot
ExecStart=${APP_DIR}/update-rules.sh
EOF

  cat > "${APP_DIR}/update-rules.sh" << EOF
#!/usr/bin/env bash
exec "${MENU_SCRIPT_PATH}" --update-rules
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
# 系统 DNS 设置
# ============================================================


# 询问是否锁定 /etc/resolv.conf，防止重启或网络服务覆盖。
ask_lock_resolv_conf() {
  echo
  read -rp "是否锁定 /etc/resolv.conf 防止被覆盖？不建议默认开启。[y/N]: " lock_confirm
  lock_confirm="${lock_confirm:-N}"

  if [[ "$lock_confirm" =~ ^[Yy]$ ]]; then
    set_resolv_conf_lock_state lock
    return $?
  else
    ok "未锁定 /etc/resolv.conf"
  fi

  return 0
}

get_resolv_conf_attr_target_path() {
  # chattr / lsattr 对符号链接本身支持有限。
  # 如果 /etc/resolv.conf 是符号链接，则返回其真实目标文件；否则返回 /etc/resolv.conf。
  local target

  if [[ -L "$RESOLV_CONF" ]]; then
    target="$(readlink -f "$RESOLV_CONF" 2>/dev/null || true)"
    if [[ -n "$target" ]]; then
      printf '%s\n' "$target"
      return 0
    fi
  fi

  printf '%s\n' "$RESOLV_CONF"
}

get_resolv_conf_lock_status() {
  local target attrs

  if [[ ! -e "$RESOLV_CONF" && ! -L "$RESOLV_CONF" ]]; then
    echo "不存在"
    return 0
  fi

  target="$(get_resolv_conf_attr_target_path)"
  if [[ ! -e "$target" ]]; then
    echo "未知（符号链接目标不存在）"
    return 0
  fi

  if ! command -v lsattr >/dev/null 2>&1; then
    echo "未知（系统无 lsattr）"
    return 0
  fi

  attrs="$(lsattr "$target" 2>/dev/null | awk '{print $1}' || true)"

  if [[ "$attrs" == *i* ]]; then
    if [[ "$target" != "$RESOLV_CONF" ]]; then
      echo "已锁定（目标文件）"
    else
      echo "已锁定"
    fi
  else
    if [[ "$target" != "$RESOLV_CONF" ]]; then
      echo "未锁定（目标文件）"
    else
      echo "未锁定"
    fi
  fi
}

set_resolv_conf_lock_state() {
  local state="$1" target

  if ! command -v chattr >/dev/null 2>&1; then
    warn "系统没有 chattr，无法修改 /etc/resolv.conf 锁定状态。"
    return 1
  fi

  if [[ ! -e "$RESOLV_CONF" && ! -L "$RESOLV_CONF" ]]; then
    warn "$RESOLV_CONF 不存在，无法修改锁定状态。"
    return 1
  fi

  target="$(get_resolv_conf_attr_target_path)"
  if [[ ! -e "$target" ]]; then
    warn "$RESOLV_CONF 是失效符号链接，目标不存在，无法修改锁定状态。"
    warn "当前链接目标：$(readlink "$RESOLV_CONF" 2>/dev/null || true)"
    return 1
  fi

  if [[ "$target" != "$RESOLV_CONF" ]]; then
    warn "检测到 $RESOLV_CONF 是符号链接，将修改真实目标文件锁定状态：$target"
  fi

  case "$state" in
    lock)
      if chattr +i "$target" 2>/dev/null; then
        ok "已锁定：$target"
        warn "以后要修改系统 DNS，请先在 系统 DNS 管理 中执行：解锁 /etc/resolv.conf"
        return 0
      fi
      warn "锁定失败，可能是文件系统不支持 chattr +i。"
      return 1
      ;;
    unlock)
      if chattr -i "$target" 2>/dev/null; then
        ok "已解锁：$target"
        return 0
      fi
      warn "解锁失败，可能是文件系统不支持 chattr -i。"
      return 1
      ;;
    *)
      err "未知锁定操作：$state"
      return 1
      ;;
  esac
}

lock_resolv_conf_manual() {
  require_root
  echo
  warn "锁定后，系统网络服务、DHCP、systemd-resolved、NetworkManager 可能无法覆盖 DNS。"
  read -rp "确认锁定 /etc/resolv.conf？[y/N]: " confirm
  confirm="${confirm:-N}"

  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    set_resolv_conf_lock_state lock
  else
    warn "已取消锁定。"
  fi
}

unlock_resolv_conf_manual() {
  require_root
  echo
  read -rp "确认解锁 /etc/resolv.conf？[Y/n]: " confirm
  confirm="${confirm:-Y}"

  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    set_resolv_conf_lock_state unlock
  else
    warn "已取消解锁。"
  fi
}

ensure_resolv_backup_dir() {
  mkdir -p "$RESOLV_BACKUP_DIR"
}

get_resolv_conf_link_target() {
  if [[ -L "$RESOLV_CONF" ]]; then
    readlink "$RESOLV_CONF" 2>/dev/null || true
  fi
}

resolve_resolv_link_target_path() {
  local link_target="${1:-}"

  [[ -n "$link_target" ]] || return 1

  if [[ "$link_target" == /* ]]; then
    printf '%s\n' "$link_target"
  else
    printf '%s\n' "/etc/${link_target}"
  fi
}

get_backup_first_nameserver() {
  local file="$1"
  awk '/^nameserver[[:space:]]+/ {print $2; exit}' "$file" 2>/dev/null || true
}

create_resolv_conf_backup() {
  local reason="${1:-manual}"
  local ts backup_file meta_file link_file link_target real_target first_ns

  if [[ ! -e "$RESOLV_CONF" && ! -L "$RESOLV_CONF" ]]; then
    err "$RESOLV_CONF 不存在，无法备份。"
    return 1
  fi

  if [[ -L "$RESOLV_CONF" ]]; then
    real_target="$(readlink -f "$RESOLV_CONF" 2>/dev/null || true)"
    if [[ -z "$real_target" || ! -e "$real_target" ]]; then
      err "$RESOLV_CONF 是失效符号链接，目标不存在，无法备份内容。"
      warn "当前链接目标：$(readlink "$RESOLV_CONF" 2>/dev/null || true)"
      return 1
    fi
  fi

  ensure_resolv_backup_dir

  ts="$(date '+%Y%m%d-%H%M%S')"
  backup_file="${RESOLV_BACKUP_DIR}/resolv.conf.${ts}"
  if [[ -e "$backup_file" ]]; then
    backup_file="${RESOLV_BACKUP_DIR}/resolv.conf.${ts}.$$"
  fi
  meta_file="${backup_file}.meta"
  link_file="${backup_file}.link"

  if ! cp -aL "$RESOLV_CONF" "$backup_file"; then
    err "备份失败：无法复制 $RESOLV_CONF"
    return 1
  fi

  link_target="$(get_resolv_conf_link_target)"
  real_target="$(readlink -f "$RESOLV_CONF" 2>/dev/null || true)"
  first_ns="$(get_backup_first_nameserver "$backup_file")"

  if [[ -n "$link_target" ]]; then
    printf '%s\n' "$link_target" > "$link_file"
  else
    rm -f "$link_file"
  fi

  cat > "$meta_file" << EOF
created_at=$(date '+%F %T')
reason=${reason}
source=${RESOLV_CONF}
was_symlink=$([[ -n "$link_target" ]] && echo yes || echo no)
link_target=${link_target}
real_target=${real_target}
first_nameserver=${first_ns}
EOF

  # 同步一份固定路径备份，兼容旧版恢复逻辑和卸载逻辑。
  cp -a "$backup_file" "$RESOLV_BACKUP"
  if [[ -n "$link_target" ]]; then
    printf '%s\n' "$link_target" > "$RESOLV_LINK_BACKUP"
  else
    rm -f "$RESOLV_LINK_BACKUP"
  fi

  ok "已创建系统 DNS 备份：$backup_file"
  ok "已更新默认备份：$RESOLV_BACKUP"
  if [[ -n "$link_target" ]]; then
    ok "已记录 /etc/resolv.conf 符号链接：$link_target"
  fi

  return 0
}

backup_resolv_conf_once() {
  if [[ -f "$RESOLV_BACKUP" ]]; then
    warn "默认备份已存在：$RESOLV_BACKUP"
    warn "如需重新备份，请进入：系统 DNS 管理 -> 创建新的系统 DNS 备份。"
    return 0
  fi

  create_resolv_conf_backup "auto-before-apply"
}

RESOLV_WRITE_PATH=""

prepare_resolv_conf_write_path() {
  local allow_replace_broken="${1:-no}"
  local link_target abs_target

  RESOLV_WRITE_PATH="$RESOLV_CONF"

  if [[ -L "$RESOLV_CONF" ]]; then
    link_target="$(readlink "$RESOLV_CONF" 2>/dev/null || true)"
    abs_target="$(readlink -f "$RESOLV_CONF" 2>/dev/null || true)"

    warn "检测到 $RESOLV_CONF 是符号链接：$link_target"

    if [[ -z "$abs_target" ]]; then
      err "$RESOLV_CONF 的符号链接目标不存在，已拒绝自动删除该链接。"
      if [[ "$allow_replace_broken" == "yes" ]]; then
        warn "为避免系统 DNS 失效，将替换这个失效链接为普通 resolv.conf 文件。"
        rm -f "$RESOLV_CONF"
        RESOLV_WRITE_PATH="$RESOLV_CONF"
        return 0
      fi
      return 1
    fi

    warn "为避免误删 systemd-resolved / NetworkManager 管理的链接，将保留符号链接，只写入目标文件：$abs_target"

    if [[ "$abs_target" == /run/systemd/resolve/* || "$link_target" == *systemd/resolve* ]]; then
      warn "该 resolv.conf 疑似由 systemd-resolved 管理，后续可能被 systemd-resolved 覆盖。"
      warn "如需稳定接管，建议先在端口冲突菜单中停止并禁用 systemd-resolved。"
    fi

    RESOLV_WRITE_PATH="$abs_target"
  fi

  return 0
}

write_dnsproxy_resolv_conf() {
  local mode="${1:-safe}"

  prepare_resolv_conf_write_path "no" || return 1

  cat > "$RESOLV_WRITE_PATH" << EOF
nameserver ${LISTEN_ADDR}
options edns0 trust-ad
EOF

  if [[ "$RESOLV_WRITE_PATH" != "$RESOLV_CONF" ]]; then
    ok "已写入 resolv.conf 符号链接目标：$RESOLV_WRITE_PATH"
  else
    ok "已写入 $RESOLV_CONF"
  fi

  ok "已应用系统 DNS 到 ${LISTEN_ADDR}"
  return 0
}

restore_resolv_conf_backup_pair() {
  local backup_file="$1"
  local link_file="${2:-}"
  local link_target target_path target_dir

  if [[ ! -f "$backup_file" ]]; then
    err "备份文件不存在：$backup_file"
    return 1
  fi

  if command -v chattr >/dev/null 2>&1; then
    chattr -i "$RESOLV_CONF" 2>/dev/null || true
  fi

  if [[ -n "$link_file" && -f "$link_file" ]]; then
    link_target="$(cat "$link_file" 2>/dev/null || true)"
  else
    link_target=""
  fi

  if [[ -n "$link_target" ]]; then
    target_path="$(resolve_resolv_link_target_path "$link_target" || true)"
    target_dir="$(dirname "$target_path")"

    if [[ -n "$target_path" && -d "$target_dir" ]]; then
      if command -v chattr >/dev/null 2>&1; then
        chattr -i "$target_path" 2>/dev/null || true
      fi

      if cp -a "$backup_file" "$target_path"; then
        rm -f "$RESOLV_CONF"
        ln -s "$link_target" "$RESOLV_CONF"
        ok "已恢复 /etc/resolv.conf 符号链接：$link_target"
        ok "已恢复备份内容到链接目标：$target_path"
        return 0
      else
        warn "写入符号链接目标失败：$target_path"
      fi
    else
      warn "原符号链接目标目录不存在：$target_dir"
      warn "将恢复为普通 /etc/resolv.conf 文件。"
    fi
  fi

  rm -f "$RESOLV_CONF"
  cp -a "$backup_file" "$RESOLV_CONF"
  ok "已恢复备份：$backup_file -> $RESOLV_CONF"
  return 0
}

restore_resolv_conf_from_backup() {
  [[ -f "$RESOLV_BACKUP" ]] || return 1
  restore_resolv_conf_backup_pair "$RESOLV_BACKUP" "$RESOLV_LINK_BACKUP"
}

build_fallback_resolv_conf_content() {
  local -a nameservers=()
  local has_v4="否"
  local has_v6="否"

  # 与“配置普通默认 DNS”的自动检测逻辑保持一致：
  # - 检测到 IPv4：写入 Cloudflare + Google IPv4
  # - 检测到 IPv6：额外写入 Cloudflare + Google IPv6
  # resolv.conf 只能写 IP，不能写端口，所以这里不带 :53，也不使用 [IPv6] 格式。
  if has_ipv4_network; then
    has_v4="是"
    nameservers+=("1.1.1.1" "8.8.8.8")
  fi

  if has_ipv6_network; then
    has_v6="是"
    nameservers+=("2606:4700:4700::1111" "2001:4860:4860::8888")
  fi

  info "临时公共 DNS 检测结果：IPv4=${has_v4}，IPv6=${has_v6}" >&2

  # 极简系统或网络异常时，ip route 可能检测失败。
  # 为了避免恢复/卸载后完全没有 DNS，至少写入 IPv4 公共 DNS。
  if (( ${#nameservers[@]} == 0 )); then
    warn "未检测到可用 IPv4 / IPv6 网络，仍写入 IPv4 公共 DNS 作为兜底。" >&2
    nameservers+=("1.1.1.1" "8.8.8.8")
  fi

  local ns
  for ns in "${nameservers[@]}"; do
    printf 'nameserver %s
' "$ns"
  done
}

write_fallback_resolv_conf() {
  if command -v chattr >/dev/null 2>&1; then
    chattr -i "$RESOLV_CONF" 2>/dev/null || true
  fi

  if ! prepare_resolv_conf_write_path "yes"; then
    return 1
  fi

  build_fallback_resolv_conf_content > "$RESOLV_WRITE_PATH"

  local dns_summary
  dns_summary="$(awk '/^nameserver[[:space:]]+/ { if (n++) printf " / "; printf "%s", $2 } END { print "" }' "$RESOLV_WRITE_PATH")"

  if [[ "$RESOLV_WRITE_PATH" != "$RESOLV_CONF" ]]; then
    ok "已写入临时公共 DNS 到符号链接目标：$RESOLV_WRITE_PATH"
  else
    ok "已写入临时公共 DNS"
  fi

  ok "当前临时公共 DNS：$dns_summary"
}

show_current_resolv_conf_info() {
  echo
  echo "当前 /etc/resolv.conf："
  echo "------------------------------------------------------------"

  if [[ -L "$RESOLV_CONF" ]]; then
    echo "类型：符号链接"
    echo "链接目标：$(readlink "$RESOLV_CONF" 2>/dev/null || true)"
    echo "真实路径：$(readlink -f "$RESOLV_CONF" 2>/dev/null || echo '目标不存在')"
  elif [[ -f "$RESOLV_CONF" ]]; then
    echo "类型：普通文件"
  elif [[ -e "$RESOLV_CONF" ]]; then
    echo "类型：存在，但不是普通文件"
  else
    echo "类型：不存在"
  fi

  echo "锁定状态：$(get_resolv_conf_lock_status)"
  echo "首个 nameserver：$(get_system_dns_status)"
  echo
  echo "内容预览："
  if [[ -e "$RESOLV_CONF" || -L "$RESOLV_CONF" ]]; then
    sed -n '1,12p' "$RESOLV_CONF" 2>/dev/null || true
  else
    echo "无"
  fi
  echo "------------------------------------------------------------"
}

show_resolv_backup_status() {
  local history_count=0

  if [[ -d "$RESOLV_BACKUP_DIR" ]]; then
    history_count="$(find "$RESOLV_BACKUP_DIR" -maxdepth 1 -type f -name 'resolv.conf.*' ! -name '*.meta' ! -name '*.link' 2>/dev/null | wc -l | awk '{print $1}')"
  fi

  echo
  echo "系统 DNS 备份状态："
  echo "------------------------------------------------------------"
  if [[ -f "$RESOLV_BACKUP" ]]; then
    echo "默认备份：存在（$RESOLV_BACKUP）"
    echo "默认备份首个 nameserver：$(get_backup_first_nameserver "$RESOLV_BACKUP")"
  else
    echo "默认备份：不存在"
  fi

  if [[ -f "$RESOLV_LINK_BACKUP" ]]; then
    echo "默认符号链接记录：$(cat "$RESOLV_LINK_BACKUP" 2>/dev/null || true)"
  else
    echo "默认符号链接记录：无"
  fi

  echo "历史备份目录：$RESOLV_BACKUP_DIR"
  echo "历史备份数量：$history_count"
  echo "------------------------------------------------------------"
}

list_resolv_conf_backups() {
  local n=0 file meta link ns created was_symlink link_target

  echo
  echo "可用系统 DNS 备份："
  echo "------------------------------------------------------------"

  if [[ -f "$RESOLV_BACKUP" ]]; then
    n=$((n + 1))
    ns="$(get_backup_first_nameserver "$RESOLV_BACKUP")"
    echo "${n}. 默认备份"
    echo "   文件：$RESOLV_BACKUP"
    echo "   首个 nameserver：${ns:-未知}"
    if [[ -f "$RESOLV_LINK_BACKUP" ]]; then
      echo "   原类型：符号链接 -> $(cat "$RESOLV_LINK_BACKUP" 2>/dev/null || true)"
    else
      echo "   原类型：普通文件 / 未记录"
    fi
    echo
  fi

  if [[ -d "$RESOLV_BACKUP_DIR" ]]; then
    while IFS= read -r file; do
      [[ -f "$file" ]] || continue
      n=$((n + 1))
      meta="${file}.meta"
      link="${file}.link"
      ns="$(get_backup_first_nameserver "$file")"
      created=""
      was_symlink=""
      link_target=""
      if [[ -f "$meta" ]]; then
        created="$(awk -F= '/^created_at=/ {print substr($0, index($0,$2)); exit}' "$meta" 2>/dev/null || true)"
        was_symlink="$(awk -F= '/^was_symlink=/ {print $2; exit}' "$meta" 2>/dev/null || true)"
        link_target="$(awk -F= '/^link_target=/ {print substr($0, index($0,$2)); exit}' "$meta" 2>/dev/null || true)"
      fi
      if [[ -z "$link_target" && -f "$link" ]]; then
        link_target="$(cat "$link" 2>/dev/null || true)"
      fi

      echo "${n}. 历史备份：$(basename "$file")"
      echo "   文件：$file"
      echo "   时间：${created:-未知}"
      echo "   首个 nameserver：${ns:-未知}"
      if [[ "$was_symlink" == "yes" || -n "$link_target" ]]; then
        echo "   原类型：符号链接 -> ${link_target:-未知}"
      else
        echo "   原类型：普通文件"
      fi
      echo
    done < <(find "$RESOLV_BACKUP_DIR" -maxdepth 1 -type f -name 'resolv.conf.*' ! -name '*.meta' ! -name '*.link' 2>/dev/null | sort -r)
  fi

  if [[ "$n" -eq 0 ]]; then
    echo "暂无备份。"
  fi

  echo "------------------------------------------------------------"
}

restore_resolv_conf_from_selected_backup() {
  local -a backup_files=()
  local -a link_files=()
  local -a labels=()
  local file choice i ns

  if [[ -f "$RESOLV_BACKUP" ]]; then
    backup_files+=("$RESOLV_BACKUP")
    link_files+=("$RESOLV_LINK_BACKUP")
    labels+=("默认备份")
  fi

  if [[ -d "$RESOLV_BACKUP_DIR" ]]; then
    while IFS= read -r file; do
      [[ -f "$file" ]] || continue
      backup_files+=("$file")
      link_files+=("${file}.link")
      labels+=("历史备份：$(basename "$file")")
    done < <(find "$RESOLV_BACKUP_DIR" -maxdepth 1 -type f -name 'resolv.conf.*' ! -name '*.meta' ! -name '*.link' 2>/dev/null | sort -r)
  fi

  if (( ${#backup_files[@]} == 0 )); then
    warn "没有找到任何系统 DNS 备份。"
    return 1
  fi

  echo
  echo "请选择要恢复的备份："
  echo "------------------------------------------------------------"
  for i in "${!backup_files[@]}"; do
    ns="$(get_backup_first_nameserver "${backup_files[$i]}")"
    echo "$((i + 1)). ${labels[$i]}"
    echo "   文件：${backup_files[$i]}"
    echo "   首个 nameserver：${ns:-未知}"
    if [[ -f "${link_files[$i]}" ]]; then
      echo "   原类型：符号链接 -> $(cat "${link_files[$i]}" 2>/dev/null || true)"
    else
      echo "   原类型：普通文件 / 未记录"
    fi
  done
  echo "0. 取消"
  echo "------------------------------------------------------------"

  read -rp "请输入选项: " choice
  if [[ -z "$choice" || "$choice" == "0" ]]; then
    warn "已取消恢复。"
    return 0
  fi

  if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#backup_files[@]} )); then
    err "无效选项"
    return 1
  fi

  echo
  warn "即将恢复：${labels[$((choice - 1))]}"
  warn "当前 $RESOLV_CONF 会被覆盖。"
  read -rp "确认恢复？[y/N]: " confirm
  confirm="${confirm:-N}"
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    warn "已取消恢复。"
    return 0
  fi

  restore_resolv_conf_backup_pair "${backup_files[$((choice - 1))]}" "${link_files[$((choice - 1))]}"
}

manage_system_dns_menu() {
  require_root

  while true; do
    clear
    echo "============================================================"
    echo " 系统 DNS 管理"
    echo "============================================================"
    load_config
    show_current_resolv_conf_info
    show_resolv_backup_status
    echo
    echo "普通默认 DNS：${DEFAULT_UPSTREAMS:-未配置}"
    echo "dnsproxy 监听：${LISTEN_ADDR:-127.0.0.1}:${LISTEN_PORT:-53}"
    echo
    echo "请选择："
    echo "1. 配置普通默认 DNS（未命中分流规则时使用）"
    echo "2. 应用系统 DNS 到 dnsproxy（写入 /etc/resolv.conf）"
    echo "3. 创建新的系统 DNS 备份"
    echo "4. 查看所有系统 DNS 备份"
    echo "5. 恢复默认系统 DNS 备份"
    echo "6. 选择历史备份恢复"
    echo "7. 写入临时公共 DNS（自动检测 IPv4 / IPv6）"
    echo "8. 锁定 /etc/resolv.conf 防止被覆盖"
    echo "9. 解锁 /etc/resolv.conf"
    echo "0. 返回主菜单"
    echo

    read -rp "请输入选项: " choice

    case "$choice" in
      1)
        configure_default_dns
        ;;
      2)
        apply_system_dns
        ;;
      3)
        create_resolv_conf_backup "manual"
        pause
        ;;
      4)
        list_resolv_conf_backups
        pause
        ;;
      5)
        if [[ -f "$RESOLV_BACKUP" ]]; then
          warn "即将恢复默认备份：$RESOLV_BACKUP"
          read -rp "确认恢复？[y/N]: " confirm
          confirm="${confirm:-N}"
          if [[ "$confirm" =~ ^[Yy]$ ]]; then
            restore_resolv_conf_from_backup
          else
            warn "已取消恢复。"
          fi
        else
          warn "没有找到默认备份：$RESOLV_BACKUP"
        fi
        pause
        ;;
      6)
        restore_resolv_conf_from_selected_backup
        pause
        ;;
      7)
        warn "这会根据机器 IPv4 / IPv6 网络情况写入临时公共 DNS。"
        read -rp "确认写入？[y/N]: " confirm
        confirm="${confirm:-N}"
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
          write_fallback_resolv_conf
        else
          warn "已取消。"
        fi
        pause
        ;;
      8)
        lock_resolv_conf_manual
        pause
        ;;
      9)
        unlock_resolv_conf_manual
        pause
        ;;
      0)
        return 0
        ;;
      *)
        warn "无效选项"
        pause
        ;;
    esac
  done
}

# 兼容旧函数名：旧菜单项已合并进“系统 DNS 管理”。
manage_system_dns_backup_menu() {
  manage_system_dns_menu
}

restore_system_dns() {
  require_root

  if command -v chattr >/dev/null 2>&1; then
    chattr -i "$RESOLV_CONF" 2>/dev/null || true
  fi

  if restore_resolv_conf_from_backup; then
    :
  else
    warn "没有找到备份：$RESOLV_BACKUP"
    warn "将写入一个临时公共 DNS 配置。"
    write_fallback_resolv_conf
  fi

  pause
}

apply_rules_and_enable_system_dns() {
  require_root

  echo
  info "开始一键应用：更新规则 -> 启动/重启 dnsproxy -> dnsproxy 接管系统 DNS"

  if ! update_online_rules; then
    err "规则更新失败，已停止后续步骤。"
    pause
    return 1
  fi

  if ! handle_port_conflict; then
    warn "已取消一键应用。"
    pause
    return 1
  fi
  systemctl daemon-reload
  systemctl enable dnsproxy
  systemctl restart dnsproxy
  ok "dnsproxy 已启动 / 重启"
  verify_dnsproxy_running

  if apply_system_dns_auto; then
    ok "已完成一键应用"
  else
    warn "已更新规则并启动 dnsproxy，但系统 DNS 应用失败。"
  fi

  pause
}

apply_system_dns_auto() {
  require_root
  load_config

  if [[ "${LISTEN_PORT}" != "53" ]]; then
    warn "当前监听端口不是 53，跳过系统 DNS 自动应用。"
    return 1
  fi

  if command -v chattr >/dev/null 2>&1; then
    chattr -i "$RESOLV_CONF" 2>/dev/null || true
  fi

  backup_resolv_conf_once

  if ! write_dnsproxy_resolv_conf "auto"; then
    warn "未修改 /etc/resolv.conf。"
    return 1
  fi
  ask_lock_resolv_conf || true
  return 0
}

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

  if [[ "${LISTEN_ADDR}" != "127.0.0.1" ]]; then
    warn "当前监听地址不是 127.0.0.1，请确认你知道自己在做什么。"
  fi

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

  backup_resolv_conf_once

  if ! write_dnsproxy_resolv_conf "manual"; then
    warn "未修改 /etc/resolv.conf。"
    pause
    return 1
  fi

  ask_lock_resolv_conf || true

  pause
}

restore_system_dns() {
  require_root

  if command -v chattr >/dev/null 2>&1; then
    chattr -i "$RESOLV_CONF" 2>/dev/null || true
  fi

  if restore_resolv_conf_from_backup; then
    :
  else
    warn "没有找到备份：$RESOLV_BACKUP"
    warn "将写入一个临时公共 DNS 配置。"
    write_fallback_resolv_conf
  fi

  pause
}

# ============================================================
# 状态和测试
# ============================================================

get_dnsproxy_install_status() {
  if [[ -x "$BIN_PATH" ]]; then
    echo "已安装"
  else
    echo "未安装"
  fi
}

get_dnsproxy_run_status() {
  if systemctl is-active --quiet dnsproxy; then
    echo "运行中"
  else
    echo "未运行"
  fi
}

get_rule_update_timer_status() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "未知"
    return 0
  fi

  if systemctl is-enabled --quiet dnsproxy-rule-update.timer 2>/dev/null; then
    if systemctl is-active --quiet dnsproxy-rule-update.timer 2>/dev/null; then
      echo "已启用"
    else
      echo "已启用但未运行"
    fi
  else
    echo "未启用"
  fi
}

get_system_dns_status() {
  if [[ -f "$RESOLV_CONF" ]]; then
    local ns
    ns="$(awk '/^nameserver[[:space:]]+/ {print $2; exit}' "$RESOLV_CONF" 2>/dev/null || true)"
    if [[ -n "$ns" ]]; then
      echo "$ns"
    else
      echo "未知"
    fi
  else
    echo "不存在"
  fi
}

get_dns_resolution_mode() {
  local ns
  ns="$(get_system_dns_status)"

  if [[ "$ns" == "127.0.0.1" ]]; then
    echo "已接管(走本机dnsproxy)"
  elif [[ "$ns" == "未知" || "$ns" == "不存在" ]]; then
    echo "未知"
  else
    echo "外部DNS(${ns})"
  fi
}

get_system_dnsproxy_usage_status() {
  load_config
  local ns
  ns="$(get_system_dns_status)"

  if [[ "$ns" == "${LISTEN_ADDR}" && "${LISTEN_PORT}" == "53" ]]; then
    echo "已使用"
  else
    echo "未使用"
  fi
}

show_status() {
  echo
  echo "================================================------------"
  echo " dnsproxy 状态"
  echo "================================================------------"
  echo "实时状态总览："
  echo "- dnsproxy 安装状态：$(get_dnsproxy_install_status)"
  echo "- dnsproxy 运行状态：$(get_dnsproxy_run_status)"
  echo "- 规则自动更新状态：$(get_rule_update_timer_status)"
  echo "- 系统是否使用 dnsproxy 解析：$(get_system_dnsproxy_usage_status)"
  echo "- 当前系统 DNS：$(get_system_dns_status)"
  echo "- resolv.conf 锁定状态：$(get_resolv_conf_lock_status)"
  if [[ -f "$RESOLV_BACKUP" ]]; then
    echo "- 系统 DNS 默认备份：存在"
  else
    echo "- 系统 DNS 默认备份：不存在"
  fi
  echo "- DNS 解析模式：$(get_dns_resolution_mode)"
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
  echo "规则源：$SOURCE_FILE"
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
  if ! handle_port_conflict; then
    warn "已取消启动 / 重启 dnsproxy。"
    pause
    return 1
  fi
  systemctl daemon-reload
  systemctl enable dnsproxy
  systemctl restart dnsproxy
  ok "dnsproxy 已启动 / 重启"
  verify_dnsproxy_running
  pause
}

stop_dnsproxy() {
  require_root
  systemctl stop dnsproxy || true
  ok "dnsproxy 已停止"
  pause
}

restart_dnsproxy() {
  require_root
  systemctl restart dnsproxy
  ok "dnsproxy 已重启"
  verify_dnsproxy_running
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

  # 只删除属于本脚本的 dns 命令
  if [[ -e "$DNS_CMD_PATH" ]] && grep -q "dnsproxy" "$DNS_CMD_PATH" 2>/dev/null; then
    rm -f "$DNS_CMD_PATH"
  fi

  rm -f "$MENU_SCRIPT_PATH"
  systemctl daemon-reload

  read -rp "是否恢复 /etc/resolv.conf 备份？[Y/n]: " restore
  restore="${restore:-Y}"

  if [[ "$restore" =~ ^[Yy]$ ]]; then
    if restore_resolv_conf_from_backup; then
      ok "已恢复 /etc/resolv.conf"
    else
      warn "没有找到备份，将写入临时公共 DNS，避免卸载后系统无法解析域名。"
      write_fallback_resolv_conf
    fi
  else
    local current_ns
    current_ns="$(get_system_dns_status)"
    if [[ "$current_ns" == "127.0.0.1" || "$current_ns" == "::1" ]]; then
      warn "当前系统 DNS 仍指向本机。dnsproxy 卸载后本机 DNS 会失效，将写入临时公共 DNS。"
      write_fallback_resolv_conf
    fi
  fi

  rm -rf "$APP_DIR"

  ok "dnsproxy 已卸载"
  pause
}

# ============================================================
# 主菜单
# ============================================================

# 主菜单 UI 辅助函数
# 说明：用 ANSI 光标定位把右边框固定在同一列，避免 ANSI 颜色码、中文宽字符或终端字体导致右侧边框不对齐。
MENU_RIGHT_COL=58

menu_cyan_fixed_right() {
  local left_part="${1:-}"
  local right_part="${2:-}"

  printf '  %b%s' "${CYAN}" "$left_part"
  printf '\033[%sG%s%b\n' "$MENU_RIGHT_COL" "$right_part" "${NC}"
}

menu_blue_fixed_right() {
  local left_part="${1:-}"
  local right_part="${2:-}"

  printf '  %b%s' "${BLUE}" "$left_part"
  printf '\033[%sG%s%b\n' "$MENU_RIGHT_COL" "$right_part" "${NC}"
}

menu_cyan_line() {
  local _visible_len="${1:-0}"  # 兼容旧调用参数，不再使用
  local content="${2:-}"

  printf '  %b%b' "${CYAN}║${NC}" "$content"
  printf '\033[%sG%b\n' "$MENU_RIGHT_COL" "${CYAN}║${NC}"
}

menu_blue_line() {
  local _visible_len="${1:-0}"  # 兼容旧调用参数，不再使用
  local content="${2:-}"

  printf '  %b%b' "${BLUE}│${NC}" "$content"
  printf '\033[%sG%b\n' "$MENU_RIGHT_COL" "${BLUE}│${NC}"
}

# 状态总览专用：把状态值固定到同一列，避免中文宽度差异导致“● 状态”不对齐。
MENU_STATUS_VALUE_COL=31

menu_blue_status_line() {
  local label="${1:-}"
  local value="${2:-}"

  printf '  %b  %s' "${BLUE}│${NC}" "$label"
  printf '\033[%sG%b' "$MENU_STATUS_VALUE_COL" "$value"
  printf '\033[%sG%b\n' "$MENU_RIGHT_COL" "${BLUE}│${NC}"
}

# FIX: install_menu_command 移到循环外，只在启动时执行一次
main_menu() {
  require_root
  create_default_config_if_missing
  install_menu_command

  while true; do
    local install_status run_status sys_dns_status timer_status
    install_status="$(get_dnsproxy_install_status)"
    run_status="$(get_dnsproxy_run_status)"
    sys_dns_status="$(get_system_dnsproxy_usage_status)"
    timer_status="$(get_rule_update_timer_status)"

    local install_icon run_icon dns_icon timer_icon
    if [[ "$install_status" == "已安装" ]]; then
      install_icon="${GREEN}●${NC} 已安装"
    else
      install_icon="${RED}●${NC} 未安装"
    fi
    if [[ "$run_status" == "运行中" ]]; then
      run_icon="${GREEN}●${NC} 运行中"
    else
      run_icon="${RED}●${NC} 未运行"
    fi
    if [[ "$sys_dns_status" == "已使用" ]]; then
      dns_icon="${GREEN}●${NC} 已接管"
    else
      dns_icon="${YELLOW}●${NC} 未接管"
    fi
    if [[ "$timer_status" == "已启用" ]]; then
      timer_icon="${GREEN}●${NC} 已启用"
    elif [[ "$timer_status" == "已启用但未运行" ]]; then
      timer_icon="${YELLOW}●${NC} 已启用但未运行"
    else
      timer_icon="${YELLOW}●${NC} 未启用"
    fi

    clear
    menu_cyan_fixed_right "╔══════════════════════════════════════════════════════" "╗"
    menu_cyan_line 0 ""
    menu_cyan_line 0 "    ┌─ AdGuard dnsproxy ── DNS 分流解锁管理 ─┐"
    menu_cyan_line 0 "    └────────────────────────────────────────┘"
    menu_cyan_line 0 ""
    menu_cyan_fixed_right "╚══════════════════════════════════════════════════════" "╝"
    echo
    menu_blue_fixed_right "┌─ 状态总览 ───────────────────────────────────────────" "┐"
    menu_blue_status_line "dnsproxy 安装状态：" "$install_icon"
    menu_blue_status_line "dnsproxy 运行状态：" "$run_icon"
    menu_blue_status_line "系统 DNS 接管状态：" "$dns_icon"
    menu_blue_status_line "规则自动更新状态：" "$timer_icon"
    menu_blue_fixed_right "└──────────────────────────────────────────────────────" "┘"
    echo
    menu_blue_fixed_right "┌──────────────────────────────────────────────────────" "┐"
    menu_blue_line 0 "  ${CYAN}◈ 推荐 DNS 解锁服务${NC}"
    menu_blue_line 0 "    ${YELLOW}▸${NC} AKile DNS   ${GREEN}https://dns.akile.ai/${NC}"
    menu_blue_line 0 "    ${YELLOW}▸${NC} GaiDNS      ${GREEN}https://gaidns.com/${NC}"
    menu_blue_fixed_right "└──────────────────────────────────────────────────────" "┘"
    echo
    menu_cyan_fixed_right "╔══ 安装与配置 ════════════════════════════════════════" "╗"
    menu_cyan_line 0 "  ${GREEN} 1)${NC} 安装 / 更新 dnsproxy"
    menu_cyan_line 0 "  ${GREEN} 2)${NC} 系统 DNS 管理"
    menu_cyan_line 0 "  ${GREEN} 3)${NC} 在线规则分组管理"
    menu_cyan_line 0 "  ${GREEN} 4)${NC} 一键应用（更新规则 + dnsproxy 接管系统 DNS）"
    menu_cyan_fixed_right "╠══ 服务控制 ══════════════════════════════════════════" "╣"
    menu_cyan_line 0 "  ${GREEN} 5)${NC} 启动 / 重启 dnsproxy"
    menu_cyan_line 0 "  ${GREEN} 6)${NC} 停止 dnsproxy"
    menu_cyan_fixed_right "╠══ 查看与调试 ════════════════════════════════════════" "╣"
    menu_cyan_line 0 "  ${GREEN} 7)${NC} 测试域名解析"
    menu_cyan_line 0 "  ${GREEN} 8)${NC} 查看状态"
    menu_cyan_line 0 "  ${GREEN} 9)${NC} 查看日志"
    menu_cyan_line 0 "  ${GREEN}10)${NC} 预览生成的 upstream 规则"
    menu_cyan_line 0 "  ${GREEN}11)${NC} 查看被忽略的规则"
    menu_cyan_fixed_right "╠══ 高级功能 ══════════════════════════════════════════" "╣"
    menu_cyan_line 0 "  ${GREEN}12)${NC} 启用规则自动更新（systemd timer）"
    menu_cyan_line 0 "  ${GREEN}13)${NC} 禁用规则自动更新"
    menu_cyan_line 0 "  ${RED}14)${NC} 卸载 dnsproxy"
    menu_cyan_fixed_right "╠══════════════════════════════════════════════════════" "╣"
    menu_cyan_line 0 "  ${YELLOW} 0)${NC} 退出"
    menu_cyan_fixed_right "╚══════════════════════════════════════════════════════" "╝"
    echo

    read -rp "  请输入选项: " choice

    case "$choice" in
      1)
        install_or_update_dnsproxy
        pause
        ;;
      2)
        manage_system_dns_menu
        ;;
      3)
        manage_rule_sources_menu
        ;;
      4)
        apply_rules_and_enable_system_dns
        ;;
      5)
        start_dnsproxy
        ;;
      6)
        stop_dnsproxy
        ;;
      7)
        test_dns
        ;;
      8)
        show_status
        ;;
      9)
        show_logs
        pause
        ;;
      10)
        preview_upstream_rules
        ;;
      11)
        preview_ignored_rules
        ;;
      12)
        install_update_timer
        ;;
      13)
        disable_update_timer
        ;;
      14)
        uninstall_dnsproxy
        ;;
      0)
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
  require_systemd
  update_online_rules
  exit 0
fi

require_systemd
main_menu
