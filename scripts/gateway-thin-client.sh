#!/usr/bin/env sh
set -eu

APP_NAME="gateway-thin-client"
INSTALL_ROOT="${GATEWAY_THIN_CLIENT_HOME:-$HOME/.local/share/$APP_NAME}"
BIN_DIR="${GATEWAY_THIN_CLIENT_BIN:-$HOME/.local/bin}"
BIN_PATH="$BIN_DIR/gateway-cli"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PYTHON_BIN="${GATEWAY_THIN_CLIENT_PYTHON:-python3}"
VENDOR_DIR="$INSTALL_ROOT/vendor"
BROWSERS_DIR="$INSTALL_ROOT/ms-playwright"
VERSION=$(PYTHONPATH="$REPO_ROOT/cli" "$PYTHON_BIN" -c 'from gateway_cli import __version__; print(__version__)')

usage() {
  cat <<EOF
gateway-thin-client $VERSION

Usage:
  $0 install
  $0 update
  $0 uninstall
  $0 version

Environment:
  GATEWAY_THIN_CLIENT_HOME    install directory, default: $HOME/.local/share/$APP_NAME
  GATEWAY_THIN_CLIENT_BIN     launcher directory, default: $HOME/.local/bin
  GATEWAY_THIN_CLIENT_PYTHON  Python executable, default: python3
EOF
}

install_client() {
  mkdir -p "$INSTALL_ROOT" "$BIN_DIR"
  rm -rf "$INSTALL_ROOT/gateway_cli" "$VENDOR_DIR" "$BROWSERS_DIR" "$INSTALL_ROOT/venv"
  cp -R "$REPO_ROOT/cli/gateway_cli" "$INSTALL_ROOT/gateway_cli"

  "$PYTHON_BIN" -m pip install --quiet --upgrade --target "$VENDOR_DIR" \
    'websockets>=12,<16' \
    'playwright>=1.55,<2' \
    'rich>=13,<15' \
    'httpx>=0.27,<1' \
    'mcp>=1.28.1,<2'

  PLAYWRIGHT_BROWSERS_PATH="$BROWSERS_DIR" \
  PYTHONPATH="$VENDOR_DIR:$INSTALL_ROOT" \
    "$PYTHON_BIN" -m playwright install chromium

  cat > "$BIN_PATH" <<EOF
#!/usr/bin/env sh
export PYTHONPATH="$VENDOR_DIR:$INSTALL_ROOT\${PYTHONPATH:+:\$PYTHONPATH}"
export PLAYWRIGHT_BROWSERS_PATH="\${PLAYWRIGHT_BROWSERS_PATH:-$BROWSERS_DIR}"
exec "$PYTHON_BIN" -m gateway_cli "\$@"
EOF
  chmod +x "$BIN_PATH"
  printf 'Installed gateway-cli %s at %s\n' "$VERSION" "$BIN_PATH"
  printf 'Bundled Python packages at %s\n' "$VENDOR_DIR"
  printf 'Bundled Playwright browsers at %s\n' "$BROWSERS_DIR"
}

uninstall_client() {
  rm -f "$BIN_PATH"
  rm -rf "$INSTALL_ROOT"
  printf 'Removed gateway-cli from %s\n' "$BIN_PATH"
}

case "${1:-}" in
  install|update)
    install_client
    ;;
  uninstall|remove)
    uninstall_client
    ;;
  version)
    printf 'gateway-thin-client %s\n' "$VERSION"
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
