#!/usr/bin/env sh
set -eu

APP_NAME="gateway-thin-client"
INSTALL_ROOT="${GATEWAY_THIN_CLIENT_HOME:-$HOME/.local/share/$APP_NAME}"
BIN_DIR="${GATEWAY_THIN_CLIENT_BIN:-$HOME/.local/bin}"
BIN_PATH="$BIN_DIR/gateway-cli"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
VERSION=$(PYTHONPATH="$REPO_ROOT/cli" python3 -c 'from gateway_cli import __version__; print(__version__)')

usage() {
  cat <<EOF
gateway-thin-client $VERSION

Usage:
  $0 install
  $0 update
  $0 uninstall
  $0 version

Environment:
  GATEWAY_THIN_CLIENT_HOME  install directory, default: $HOME/.local/share/$APP_NAME
  GATEWAY_THIN_CLIENT_BIN   launcher directory, default: $HOME/.local/bin
EOF
}

install_client() {
  mkdir -p "$INSTALL_ROOT" "$BIN_DIR"
  rm -rf "$INSTALL_ROOT/gateway_cli"
  cp -R "$REPO_ROOT/cli/gateway_cli" "$INSTALL_ROOT/gateway_cli"
  python3 -m venv "$INSTALL_ROOT/venv"
  "$INSTALL_ROOT/venv/bin/python" -m pip install --quiet --upgrade pip
  "$INSTALL_ROOT/venv/bin/python" -m pip install --quiet 'websockets>=12,<16'
  cat > "$BIN_PATH" <<EOF
#!/usr/bin/env sh
PYTHONPATH="$INSTALL_ROOT" exec "$INSTALL_ROOT/venv/bin/python" -m gateway_cli "\$@"
EOF
  chmod +x "$BIN_PATH"
  printf 'Installed gateway-cli %s at %s\n' "$VERSION" "$BIN_PATH"
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
