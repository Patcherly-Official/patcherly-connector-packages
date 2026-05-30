#!/bin/bash
# Universal Connector Installer for Patcherly (OAuth pairing)
#
# Usage:
#   curl -sSL https://api.patcherly.com/api/public/install.sh | sudo bash
#
# After install, pair the connector with a target via the OAuth Device
# Authorization Grant flow:
#   cd /opt/patcherly-connector && ./start.sh login
#
# Environment overrides:
#   API_BASE             override the API host (default https://api.patcherly.com)
#   ARTIFACT_BASE        override the GitHub release for connector packages
#   AGENT_TYPE           force connector type (nodejs|python|php); auto-detects
#   INSTALL_DIR          install path (default /opt/patcherly-connector)
set -e

# Injected by the API when served; fallback to env or default for direct runs
PATCHERLY_API_BASE="${PATCHERLY_API_BASE:-__PATCHERLY_API_BASE__}"
[ "$PATCHERLY_API_BASE" = "__PATCHERLY_API_BASE__" ] && PATCHERLY_API_BASE="${API_BASE:-https://api.patcherly.com}"
API_BASE="${PATCHERLY_API_BASE%/}"

ARTIFACT_BASE="${ARTIFACT_BASE:-__PATCHERLY_ARTIFACT_BASE__}"
[ "$ARTIFACT_BASE" = "__PATCHERLY_ARTIFACT_BASE__" ] && ARTIFACT_BASE="${CONNECTOR_ARTIFACT_BASE_URL:-https://github.com/Patcherly-Official/patcherly-connector-packages/releases/download/connector-packages}"
ARTIFACT_BASE="${ARTIFACT_BASE%/}"

: "${PATCHERLY_CONNECTOR_RELEASE:=1.46.0}"

INSTALL_DIR="${INSTALL_DIR:-/opt/patcherly-connector}"
AGENT_TYPE="${AGENT_TYPE:-auto}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Starting Patcherly Connector Installer..."
log_info "API base: $API_BASE"
log_info "Connector release track: $PATCHERLY_CONNECTOR_RELEASE"

detect_environment() {
  [ "$AGENT_TYPE" != "auto" ] && return
  log_info "Detecting environment..."
  if [ -f "package.json" ] && command -v node >/dev/null 2>&1; then
    AGENT_TYPE="nodejs"
    return
  fi
  if [ -f "requirements.txt" ] || [ -f "pyproject.toml" ] || [ -d "venv" ]; then
    if command -v python3 >/dev/null 2>&1; then
      AGENT_TYPE="python"
      return
    fi
  fi
  if [ -f "composer.json" ] || ls *.php >/dev/null 2>&1; then
    if command -v php >/dev/null 2>&1; then
      AGENT_TYPE="php"
      return
    fi
  fi
  log_warn "Could not auto-detect environment. Falling back to system checks."
  if command -v node >/dev/null 2>&1; then
    AGENT_TYPE="nodejs"
  elif command -v python3 >/dev/null 2>&1; then
    AGENT_TYPE="python"
  elif command -v php >/dev/null 2>&1; then
    AGENT_TYPE="php"
  else
    log_error "No supported runtime (Node.js, Python, PHP) found."
    exit 1
  fi
}

write_env() {
  # OAuth credentials are written by `patcherly login`; we only seed SERVER_URL
  # so the CLI knows where to talk on first run.
  printf 'SERVER_URL=%s\n' "$API_BASE" > "$INSTALL_DIR/.env"
}

install_nodejs() {
  log_info "Installing Node.js connector..."
  mkdir -p "$INSTALL_DIR"
  TMP_ARCHIVE="/tmp/patcherly-node-agent.$$.tar.gz"
  if curl -sSLf -o "$TMP_ARCHIVE" "$ARTIFACT_BASE/node-agent.tar.gz" 2>/dev/null; then
    tar xzf "$TMP_ARCHIVE" -C "$INSTALL_DIR"
    rm -f "$TMP_ARCHIVE"
    log_info "Downloaded Node.js connector package."
  else
    log_warn "Could not download node-agent.tar.gz; install will need manual fix-up in $INSTALL_DIR."
  fi
  if [ ! -f "$INSTALL_DIR/package.json" ]; then
    echo '{"name":"patcherly-agent","private":true,"dependencies":{"dotenv":"^16.0.0"}}' > "$INSTALL_DIR/package.json"
  fi
  cat > "$INSTALL_DIR/start.sh" <<EOF
#!/bin/bash
cd "$INSTALL_DIR"
[ ! -d "node_modules" ] && npm install --production
case "\${1:-run}" in
  login)
    exec node ./node_modules/.bin/patcherly login --api-base "$API_BASE"
    ;;
  *)
    exec node node_agent.js
    ;;
esac
EOF
  chmod +x "$INSTALL_DIR/start.sh"
  write_env
  log_info "Node.js connector installed to $INSTALL_DIR"
}

install_python() {
  log_info "Installing Python connector..."
  mkdir -p "$INSTALL_DIR"
  TMP_ARCHIVE="/tmp/patcherly-python-agent.$$.tar.gz"
  if curl -sSLf -o "$TMP_ARCHIVE" "$ARTIFACT_BASE/python-agent.tar.gz" 2>/dev/null; then
    tar xzf "$TMP_ARCHIVE" -C "$INSTALL_DIR"
    rm -f "$TMP_ARCHIVE"
    log_info "Downloaded Python connector package."
  else
    log_warn "Could not download python-agent.tar.gz; install will need manual fix-up in $INSTALL_DIR."
  fi
  [ ! -d "$INSTALL_DIR/venv" ] && python3 -m venv "$INSTALL_DIR/venv"
  "$INSTALL_DIR/venv/bin/pip" install -q httpx python-dotenv 2>/dev/null || true
  cat > "$INSTALL_DIR/start.sh" <<EOF
#!/bin/bash
cd "$INSTALL_DIR"
case "\${1:-run}" in
  login)
    exec ./venv/bin/python patcherly_cli.py login --api-base "$API_BASE"
    ;;
  *)
    exec ./venv/bin/python python_agent.py
    ;;
esac
EOF
  chmod +x "$INSTALL_DIR/start.sh"
  write_env
  log_info "Python connector installed to $INSTALL_DIR"
}

install_php() {
  log_info "Installing PHP connector..."
  mkdir -p "$INSTALL_DIR"
  TMP_ARCHIVE="/tmp/patcherly-php-agent.$$.zip"
  if curl -sSLf -o "$TMP_ARCHIVE" "$ARTIFACT_BASE/php-agent.zip" 2>/dev/null; then
    (cd "$INSTALL_DIR" && unzip -o -q "$TMP_ARCHIVE" 2>/dev/null) || true
    rm -f "$TMP_ARCHIVE"
    log_info "Downloaded PHP connector package."
  else
    log_warn "Could not download php-agent.zip; install will need manual fix-up in $INSTALL_DIR."
  fi
  cat > "$INSTALL_DIR/start.sh" <<EOF
#!/bin/bash
cd "$INSTALL_DIR"
case "\${1:-run}" in
  login)
    exec php patcherly_cli.php login --api-base "$API_BASE"
    ;;
  *)
    exec php php_agent.php
    ;;
esac
EOF
  chmod +x "$INSTALL_DIR/start.sh"
  write_env
  log_info "PHP connector installed to $INSTALL_DIR"
}

detect_environment
log_info "Selected connector type: $AGENT_TYPE"
case "$AGENT_TYPE" in
  nodejs) install_nodejs ;;
  python) install_python ;;
  php)    install_php ;;
  *)      log_error "Unknown connector type: $AGENT_TYPE"; exit 1 ;;
esac

log_info "Installation complete."
log_info "Next step: pair this connector with a target via OAuth:"
log_info "  cd $INSTALL_DIR && ./start.sh login"
log_info "Then start the connector with: $INSTALL_DIR/start.sh"

if command -v systemctl >/dev/null 2>&1; then
  log_info "Setting up systemd service (start after you have completed pairing)..."
  cat > /etc/systemd/system/patcherly-agent.service <<EOF
[Unit]
Description=Patcherly Connector Agent
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/start.sh
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable patcherly-agent
  log_info "Systemd unit 'patcherly-agent' enabled. Run 'systemctl start patcherly-agent' after pairing."
fi
