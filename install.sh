#!/bin/sh
# Zentinel installer — downloads the latest release binary for your platform.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/copyleftdev/zentinel/main/install.sh | sh
#
# Options:
#   INSTALL_DIR=/usr/local/bin  (default: /usr/local/bin, or ~/.local/bin if no sudo)
#   VERSION=v0.4.0              (default: latest)

set -e

REPO="copyleftdev/zentinel"
INSTALL_DIR="${INSTALL_DIR:-}"
VERSION="${VERSION:-latest}"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  linux)  PLATFORM="linux" ;;
  darwin) PLATFORM="macos" ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64)  ARCH="x86_64" ;;
  arm64|aarch64) ARCH="aarch64" ;;
  *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

ARTIFACT="zent-${PLATFORM}-${ARCH}"

# Resolve version
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  if [ -z "$VERSION" ]; then
    echo "Failed to fetch latest version"
    exit 1
  fi
fi

# Determine install directory
if [ -z "$INSTALL_DIR" ]; then
  if [ -w /usr/local/bin ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
  fi
fi

URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARTIFACT}.tar.gz"

echo "Zentinel ${VERSION}"
echo "  Platform: ${PLATFORM}-${ARCH}"
echo "  Install:  ${INSTALL_DIR}/zent"
echo ""

# Download and extract
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "Downloading ${URL}..."
curl -fsSL "$URL" -o "$TMPDIR/${ARTIFACT}.tar.gz"

cd "$TMPDIR"
tar xzf "${ARTIFACT}.tar.gz"
chmod +x "${ARTIFACT}"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "${ARTIFACT}" "${INSTALL_DIR}/zent"
else
  echo "Need sudo to install to ${INSTALL_DIR}"
  sudo mv "${ARTIFACT}" "${INSTALL_DIR}/zent"
fi

echo ""
echo "Installed: $(${INSTALL_DIR}/zent help 2>&1 | head -1 || echo 'zent')"
echo ""
echo "Usage:"
echo "  zent scan src/*.py --config rules/python-security.yaml"
echo "  zent serve --port 8000"
