#!/usr/bin/env bash
set -euo pipefail

# One-click installer for cm-agent (Linux + systemd preferred).
#
# Example:
#   curl -fsSL https://raw.githubusercontent.com/haokexi/cm-agent/main/install.sh | sudo bash -s -- \
#     --server http://1.2.3.4:9879 \
#     --agent-token "1:xxxx" \
#     --remote-write-url "http://1.2.3.4:8428/api/v1/write" \
#     --remote-write-bearer-token "yyyy"
#
# Notes:
# - agent token format is "<node_id>:<secret>" (also used to derive node_id label automatically).
# - this installer writes config to /etc/cm-agent/config.yaml and installs a systemd unit.

REPO="haokexi/cm-agent"
SERVICE_NAME="cm-agent"
BIN_PATH="/usr/local/bin/cm-agent"
CONFIG_DIR="/etc/cm-agent"
CONFIG_PATH="/etc/cm-agent/config.yaml"
DATA_DIR="/var/lib/cm-agent"
SPOOL_DIR="/var/lib/cm-agent/spool"
SPOOL_MAX_BYTES="104857600" # 100MiB
SCRAPE_INTERVAL="15s"
CONTEXT_PATH="/cloudmonitor"
VERSION="latest"
GITHUB_PROXY=""

SERVER=""
AGENT_TOKEN=""
RW_URL=""
RW_BEARER=""
ENABLE_TERMINAL="true"
TLS_INSECURE="false"

NO_SERVICE="false"
UNINSTALL="false"

log() { echo "[cm-agent] $*"; }
die() { echo "[cm-agent] ERROR: $*" >&2; exit 1; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "please run as root (use sudo)"
  fi
}

usage() {
  cat <<EOF
cm-agent installer

Usage:
  install.sh [options]

Options:
  --version <tag|latest>                 Release tag (default: latest)
  --ghproxy <prefix>                     GitHub proxy prefix (optional), e.g. https://mirror.ghproxy.com

  --server <http(s)://host:port>         cloud-monitor server base address (required if --enable-terminal)
  --context-path </cloudmonitor>         server context path (default: /cloudmonitor)
  --agent-token <node_id:secret>         agent long token (required)

  --remote-write-url <url>               remote_write URL (required)
  --remote-write-bearer-token <token>    remote_write bearer token (required)

  --scrape-interval <dur>                default 15s
  --spool-max-bytes <bytes>              default 104857600 (100MiB)
  --spool-dir <dir>                      default /var/lib/cm-agent/spool
  --data-dir <dir>                       default /var/lib/cm-agent

  --enable-terminal <true|false>         default true
  --terminal-tls-insecure <true|false>   default false

  --no-service                           install binary+config only, do not create/start systemd unit
  --uninstall                            stop service and remove installed files
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --ghproxy) GITHUB_PROXY="${2:-}"; shift 2 ;;
    --server) SERVER="${2:-}"; shift 2 ;;
    --context-path) CONTEXT_PATH="${2:-}"; shift 2 ;;
    --agent-token) AGENT_TOKEN="${2:-}"; shift 2 ;;
    --remote-write-url) RW_URL="${2:-}"; shift 2 ;;
    --remote-write-bearer-token) RW_BEARER="${2:-}"; shift 2 ;;
    --scrape-interval) SCRAPE_INTERVAL="${2:-}"; shift 2 ;;
    --spool-max-bytes) SPOOL_MAX_BYTES="${2:-}"; shift 2 ;;
    --spool-dir) SPOOL_DIR="${2:-}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
    --enable-terminal) ENABLE_TERMINAL="${2:-}"; shift 2 ;;
    --terminal-tls-insecure) TLS_INSECURE="${2:-}"; shift 2 ;;
    --no-service) NO_SERVICE="true"; shift ;;
    --uninstall) UNINSTALL="true"; shift ;;
    *) die "unknown arg: $1" ;;
  esac
done

if [[ "${UNINSTALL}" == "true" ]]; then
  need_root
  log "uninstalling..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    systemctl disable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service" || true
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f "${BIN_PATH}" || true
  rm -rf "${CONFIG_DIR}" || true
  rm -rf "${DATA_DIR}" || true
  log "uninstall done"
  exit 0
fi

need_root

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
[[ "${os}" == "linux" ]] || die "only linux is supported by this installer"

arch="$(uname -m)"
case "${arch}" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) die "unsupported arch: ${arch}" ;;
esac

if [[ -z "${AGENT_TOKEN}" ]]; then
  die "--agent-token is required (format: <node_id>:<secret>)"
fi
if [[ -z "${RW_URL}" ]]; then
  die "--remote-write-url is required"
fi
if [[ -z "${RW_BEARER}" ]]; then
  die "--remote-write-bearer-token is required"
fi
if [[ "${ENABLE_TERMINAL}" == "true" && -z "${SERVER}" ]]; then
  die "--server is required when --enable-terminal=true"
fi

resolve_latest_tag() {
  local url="https://github.com/${REPO}/releases/latest"
  # Follow redirects and extract final path segment "vX.Y.Z" from Location header.
  local loc
  loc="$(curl -fsSLI "${url}" | awk -F': ' 'tolower($1)=="location"{print $2}' | tail -n 1 | tr -d '\r')"
  [[ -n "${loc}" ]] || die "failed to resolve latest version (no Location header)"
  echo "${loc##*/}"
}

tag="${VERSION}"
if [[ "${VERSION}" == "latest" ]]; then
  tag="$(resolve_latest_tag)"
fi

asset="cm-agent-linux-${arch}.tgz"
base="https://github.com/${REPO}/releases/download/${tag}/${asset}"
if [[ -n "${GITHUB_PROXY}" ]]; then
  base="${GITHUB_PROXY%/}/${base}"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

log "downloading ${asset} (${tag})..."
curl -fsSL -o "${tmp}/${asset}" "${base}"

sha_asset="${asset}.sha256"
sha_url="https://github.com/${REPO}/releases/download/${tag}/${sha_asset}"
if [[ -n "${GITHUB_PROXY}" ]]; then
  sha_url="${GITHUB_PROXY%/}/${sha_url}"
fi
if curl -fsSL -o "${tmp}/${sha_asset}" "${sha_url}" >/dev/null 2>&1; then
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${tmp}" && sha256sum -c "${sha_asset}") || die "sha256 verify failed"
  elif command -v shasum >/dev/null 2>&1; then
    # shasum expects "hash  file", same as our generated format.
    (cd "${tmp}" && shasum -a 256 -c "${sha_asset}") || die "sha256 verify failed"
  else
    log "sha tool not found; skipping checksum verify"
  fi
else
  log "sha256 file not found; skipping checksum verify"
fi

log "extracting..."
tar -C "${tmp}" -xzf "${tmp}/${asset}"
[[ -f "${tmp}/cm-agent-linux-${arch}" ]] || die "archive missing cm-agent-linux-${arch}"

log "installing binary to ${BIN_PATH}..."
install -m 0755 "${tmp}/cm-agent-linux-${arch}" "${BIN_PATH}"

log "writing config to ${CONFIG_PATH}..."
mkdir -p "${CONFIG_DIR}"
mkdir -p "${DATA_DIR}"
mkdir -p "${SPOOL_DIR}"

cat >"${CONFIG_PATH}" <<EOF
log:
  level: info

scrape:
  interval: ${SCRAPE_INTERVAL}

collectors:
  disable_defaults: false
  filters: []

labels:
  job: node
  instance: ""
  extra: {}

remote_write:
  url: "${RW_URL}"
  bearer_token: "${RW_BEARER}"
  timeout: 10s
  max_series_per_request: 2000
  spool:
    dir: "${SPOOL_DIR}"
    max_bytes: ${SPOOL_MAX_BYTES}
    max_files: 2000
  flush:
    max_files: 200

probes:
  job: blackbox
  timeout: 2s
  icmp: []
  tcp: []

terminal:
  enabled: ${ENABLE_TERMINAL}
  server: "${SERVER}"
  context_path: "${CONTEXT_PATH}"
  agent_token: "${AGENT_TOKEN}"
  dial_timeout: 10s
  ping_interval: 30s
  tls_insecure_skip_verify: ${TLS_INSECURE}
  shell: "/bin/bash"
  shell_args: ["-l"]
  max_sessions: 1
  max_duration: 0s
  idle_timeout: 0s
EOF

chmod 0600 "${CONFIG_PATH}"

if [[ "${NO_SERVICE}" == "true" ]]; then
  log "--no-service set; installation finished."
  log "run: ${BIN_PATH} --config.file=${CONFIG_PATH}"
  exit 0
fi

if ! command -v systemctl >/dev/null 2>&1; then
  log "systemctl not found; installation finished without service."
  log "run: ${BIN_PATH} --config.file=${CONFIG_PATH}"
  exit 0
fi

log "installing systemd service ${SERVICE_NAME}.service..."
cat >"/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=cm-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} --config.file=${CONFIG_PATH}
WorkingDirectory=${DATA_DIR}
Restart=always
RestartSec=2
TimeoutStopSec=10
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

log "done. logs: journalctl -u ${SERVICE_NAME} -f"

