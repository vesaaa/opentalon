#!/usr/bin/env bash
set -euo pipefail

REPO="vesaaa/opentalon"

usage() {
  cat <<EOF
Usage:
  $0 <server|agent> [--version vX.Y.Z]   # 安装并注册为服务（向后兼容）
  $0 install <server|agent> [--version vX.Y.Z]
  $0 uninstall <server|agent>            # 仅卸载服务，不删除二进制

Examples:
  # 安装最新版本的 Server 并注册为系统服务
  bash <(curl -L https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh) server

  # 安装指定版本的 Agent
  bash <(curl -L https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh) agent --version v0.1.15

  # 卸载 Server 服务
  bash <(curl -L https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh) uninstall server
EOF
  exit 1
}

ACTION="install"
MODE=""

if [[ $# -lt 1 ]]; then
  usage
fi

case "$1" in
  install|uninstall)
    ACTION="$1"
    shift || true
    ;;
  server|agent)
    ACTION="install"   # 向后兼容旧用法：第一个参数就是模式
    ;;
  *)
    echo "Invalid first argument: $1"
    usage
    ;;
esac

MODE="${1:-}"
if [[ -z "${MODE}" ]]; then
  usage
fi
case "${MODE}" in
  server|agent) ;;
  *) echo "Invalid mode: ${MODE}"; usage ;;
esac
shift || true

VERSION="latest"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:-}"
      shift 2 || true
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      ;;
  esac
done

INSTALL_DIR="/usr/local/bin"
INSTALL_BIN="${INSTALL_DIR}/opentalon"

if [[ "${ACTION}" == "uninstall" ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "This script needs root to uninstall services."
    echo "Please re-run with sudo:"
    echo "  sudo bash $0 uninstall ${MODE}"
    exit 1
  fi

  # 若 opentalon 在 PATH 中，则直接用；否则尝试 /usr/local/bin/opentalon
  if command -v opentalon >/dev/null 2>&1; then
    OP="opentalon"
  elif [[ -x "${INSTALL_BIN}" ]]; then
    OP="${INSTALL_BIN}"
  else
    echo "opentalon binary not found; nothing to uninstall."
    exit 0
  fi

  echo "Unregistering ${MODE} service via '${OP} uninstall --mode ${MODE}'..."
  "${OP}" uninstall --mode "${MODE}"
  echo "Done."
  exit 0
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }
}

http_get() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$url"
  else
    echo "Need curl or wget to download binaries."
    exit 1
  fi
}

detect_latest_tag() {
  http_get "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

if [[ "${VERSION}" == "latest" ]]; then
  echo "Detecting latest release tag from GitHub..."
  VERSION="$(detect_latest_tag || true)"
  if [[ -z "${VERSION}" ]]; then
    echo "Failed to detect latest tag; falling back to 'latest' download URLs."
    VERSION="latest"
  else
    echo "Latest release: ${VERSION}"
  fi
fi

UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"

case "${UNAME_S}" in
  Linux)   OS="linux" ;;
  Darwin)  OS="darwin" ;;
  *) echo "Unsupported OS: ${UNAME_S}"; exit 1 ;;
esac

case "${UNAME_M}" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  armv7l|armv7) ARCH="armv7" ;;
  *) echo "Unsupported architecture: ${UNAME_M}"; exit 1 ;;
esac

BIN_NAME="opentalon-${OS}-${ARCH}"
if [[ "${OS}" == "windows" ]]; then
  BIN_NAME="opentalon-windows-amd64.exe"
fi

if [[ "${VERSION}" == "latest" ]]; then
  URL="https://github.com/${REPO}/releases/latest/download/${BIN_NAME}"
else
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${BIN_NAME}"
fi

echo "Downloading ${BIN_NAME} (${VERSION}) from:"
echo "  ${URL}"

TMP_BIN="$(mktemp -t opentalon.XXXXXX)"
http_get "${URL}" > "${TMP_BIN}"
chmod +x "${TMP_BIN}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script needs root to install to ${INSTALL_DIR} and register services."
  echo "Please re-run with sudo:"
  echo "  sudo bash $0 install ${MODE} ${VERSION:+--version ${VERSION}}"
  exit 1
fi

mkdir -p "${INSTALL_DIR}"
mv "${TMP_BIN}" "${INSTALL_BIN}"
echo "Installed opentalon to ${INSTALL_BIN}"

echo "Registering ${MODE} service via 'opentalon install --mode ${MODE}'..."
"${INSTALL_BIN}" install --mode "${MODE}"

echo "Done."

