#!/usr/bin/env bash
set -euo pipefail

REPO="vesaaa/opentalon"

usage() {
  cat <<EOF
Usage: $0 <server|agent> [--version vX.Y.Z]

Examples:
  # 安装最新版本的 Server 并注册为系统服务
  bash <(curl -L https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh) server

  # 安装指定版本的 Agent
  bash <(curl -L https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh) agent --version v0.1.15
EOF
  exit 1
}

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

INSTALL_DIR="/usr/local/bin"
INSTALL_BIN="${INSTALL_DIR}/opentalon"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script needs root to install to ${INSTALL_DIR} and register services."
  echo "Please re-run with sudo:"
  echo "  sudo bash $0 ${MODE} ${VERSION:+--version ${VERSION}}"
  exit 1
fi

mkdir -p "${INSTALL_DIR}"
mv "${TMP_BIN}" "${INSTALL_BIN}"
echo "Installed opentalon to ${INSTALL_BIN}"

echo "Registering ${MODE} service via 'opentalon install --mode ${MODE}'..."
"${INSTALL_BIN}" install --mode "${MODE}"

echo "Done."

