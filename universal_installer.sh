#!/bin/bash
# Universal Connector Installer for Patcherly
# Usage (token-based): curl -sSL https://api.patcherly.com/api/public/install.sh | sudo bash -s -- --token <token>
# Usage (key-based):   curl -sSL https://api.patcherly.com/api/public/install.sh | sudo API_KEY=... bash
# API_BASE is injected when served; override with env API_BASE if needed.
set -e

# Injected by API when serving (single source of truth); fallback for direct run
PATCHERLY_API_BASE="${PATCHERLY_API_BASE:-__PATCHERLY_API_BASE__}"
[ "$PATCHERLY_API_BASE" = "__PATCHERLY_API_BASE__" ] && PATCHERLY_API_BASE="${API_BASE:-https://api.patcherly.com}"
API_BASE="${PATCHERLY_API_BASE%/}"

# Artifact base URL for connector packages (php-agent.zip, node-agent.tar.gz, python-agent.tar.gz)
# Injected when served; default points to GitHub Release "connector-packages"
ARTIFACT_BASE="${ARTIFACT_BASE:-__PATCHERLY_ARTIFACT_BASE__}"
[ "$ARTIFACT_BASE" = "__PATCHERLY_ARTIFACT_BASE__" ] && ARTIFACT_BASE="${CONNECTOR_ARTIFACT_BASE_URL:-https://github.com/Patcherly-Official/patcherly-connector-packages/releases/download/connector-packages}"
ARTIFACT_BASE="${ARTIFACT_BASE%/}"

# Configuration (may be set by token redemption)
API_KEY="${API_KEY:-}"
SERVER_URL="${SERVER_URL:-}"
INSTALL_DIR="${INSTALL_DIR:-/opt/patcherly-connector}"
AGENT_TYPE="${AGENT_TYPE:-auto}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse args for --token
INSTALL_TOKEN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --token)
      shift
      [ -n "$1" ] && INSTALL_TOKEN="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

# Token flow: redeem token for API key and server URL
if [ -n "$INSTALL_TOKEN" ]; then
  log_info "Redeeming install token..."
  REDEEM_URL="$API_BASE/api/public/install/redeem"
  RESP=$(curl -sS -X GET "$REDEEM_URL?token=$INSTALL_TOKEN" 2>/dev/null || true)
  if [ -z "$RESP" ] || ! echo "$RESP" | grep -q '"agent_api_key"'; then
    log_error "Token redemption failed. Token may be expired or already used."
    exit 1
  fi
  API_KEY=$(echo "$RESP" | sed -n 's/.*"agent_api_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  SERVER_URL=$(echo "$RESP" | sed -n 's/.*"api_base_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
  [ -z "$SERVER_URL" ] && SERVER_URL="$API_BASE"
  log_info "Token redeemed successfully."
fi

# Validation
if [ -z "$API_KEY" ]; then
  log_error "API_KEY is required. Use --token <token> or set API_KEY=... when running."
  exit 1
fi
[ -z "$SERVER_URL" ] && SERVER_URL="$API_BASE"

log_info "Starting Patcherly Connector Installer..."
log_info "Server URL: $SERVER_URL"

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
  log_warn "Could not auto-detect environment. Defaulting to system checks."
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

install_nodejs() {
  log_info "Installing Node.js Agent..."
  mkdir -p "$INSTALL_DIR"
  TMP_ARCHIVE="/tmp/patcherly-node-agent.$$.tar.gz"
  if curl -sSLf -o "$TMP_ARCHIVE" "$ARTIFACT_BASE/node-agent.tar.gz" 2>/dev/null; then
    tar xzf "$TMP_ARCHIVE" -C "$INSTALL_DIR"
    rm -f "$TMP_ARCHIVE"
    log_info "Downloaded Node.js agent package."
  else
    log_warn "Could not download node-agent.tar.gz; creating minimal layout (run npm install in $INSTALL_DIR)."
  fi
  if [ ! -f "$INSTALL_DIR/package.json" ]; then
    echo '{"name":"patcherly-agent","private":true,"dependencies":{"dotenv":"^16.0.0"}}' > "$INSTALL_DIR/package.json"
  fi
  cat > "$INSTALL_DIR/start.sh" <<EOF
#!/bin/bash
cd "$INSTALL_DIR"
export AGENT_API_KEY="$API_KEY"
export SERVER_URL="$SERVER_URL"
[ ! -d "node_modules" ] && npm install --production
exec node node_agent.js
EOF
  chmod +x "$INSTALL_DIR/start.sh"
  printf 'AGENT_API_KEY=%s\nSERVER_URL=%s\n' "$API_KEY" "$SERVER_URL" > "$INSTALL_DIR/.env"
  log_info "Node.js Agent installed to $INSTALL_DIR"
}

install_python() {
  log_info "Installing Python Agent..."
  mkdir -p "$INSTALL_DIR"
  TMP_ARCHIVE="/tmp/patcherly-python-agent.$$.tar.gz"
  if curl -sSLf -o "$TMP_ARCHIVE" "$ARTIFACT_BASE/python-agent.tar.gz" 2>/dev/null; then
    tar xzf "$TMP_ARCHIVE" -C "$INSTALL_DIR"
    rm -f "$TMP_ARCHIVE"
    log_info "Downloaded Python agent package."
  else
    log_warn "Could not download python-agent.tar.gz; creating minimal layout."
  fi
  [ ! -d "$INSTALL_DIR/venv" ] && python3 -m venv "$INSTALL_DIR/venv"
  "$INSTALL_DIR/venv/bin/pip" install -q httpx python-dotenv 2>/dev/null || true
  cat > "$INSTALL_DIR/start.sh" <<EOF
#!/bin/bash
cd "$INSTALL_DIR"
export AGENT_API_KEY="$API_KEY"
export SERVER_URL="$SERVER_URL"
exec ./venv/bin/python python_agent.py
EOF
  chmod +x "$INSTALL_DIR/start.sh"
  printf 'AGENT_API_KEY=%s\nSERVER_URL=%s\n' "$API_KEY" "$SERVER_URL" > "$INSTALL_DIR/.env"
  log_info "Python Agent installed to $INSTALL_DIR"
}

install_php() {
  log_info "Installing PHP Agent..."
  mkdir -p "$INSTALL_DIR"
  TMP_ARCHIVE="/tmp/patcherly-php-agent.$$.zip"
  if curl -sSLf -o "$TMP_ARCHIVE" "$ARTIFACT_BASE/php-agent.zip" 2>/dev/null; then
    (cd "$INSTALL_DIR" && unzip -o -q "$TMP_ARCHIVE" 2>/dev/null) || true
    rm -f "$TMP_ARCHIVE"
    log_info "Downloaded PHP agent package."
  else
    log_warn "Could not download php-agent.zip; creating minimal layout."
  fi
  cat > "$INSTALL_DIR/start.sh" <<EOF
#!/bin/bash
cd "$INSTALL_DIR"
export AGENT_API_KEY="$API_KEY"
export SERVER_URL="$SERVER_URL"
exec php php_agent.php
EOF
  chmod +x "$INSTALL_DIR/start.sh"
  printf 'AGENT_API_KEY=%s\nSERVER_URL=%s\n' "$API_KEY" "$SERVER_URL" > "$INSTALL_DIR/.env"
  log_info "PHP Agent installed to $INSTALL_DIR"
}

detect_environment
log_info "Selected Agent Type: $AGENT_TYPE"
case "$AGENT_TYPE" in
  nodejs) install_nodejs ;;
  python) install_python ;;
  php)    install_php ;;
  *)      log_error "Unknown agent type: $AGENT_TYPE"; exit 1 ;;
esac

log_info "Installation complete. To start: $INSTALL_DIR/start.sh"
if command -v systemctl >/dev/null 2>&1; then
  log_info "Setting up systemd service..."
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
  systemctl start patcherly-agent
  log_info "Systemd service 'patcherly-agent' started and enabled."
fi
