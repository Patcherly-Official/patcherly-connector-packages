# Universal Connector Installer for Patcherly (PowerShell)
# Usage (prompt for token): irm https://api.patcherly.com/api/public/install.ps1 | iex
# Usage (with token):      irm ... | iex; <paste token when prompted>
# Or download and run:     .\install.ps1 -Token YOUR_TOKEN
# API_BASE and ARTIFACT_BASE are injected when served.
param([string]$Token)
$ErrorActionPreference = 'Stop'
$PATCHERLY_API_BASE = if ($env:PATCHERLY_API_BASE -and $env:PATCHERLY_API_BASE -ne '__PATCHERLY_API_BASE__') { $env:PATCHERLY_API_BASE.TrimEnd('/') } else { if ($env:API_BASE) { $env:API_BASE.TrimEnd('/') } else { 'https://api.patcherly.com' } }
$ARTIFACT_BASE = if ($env:PATCHERLY_ARTIFACT_BASE -and $env:PATCHERLY_ARTIFACT_BASE -ne '__PATCHERLY_ARTIFACT_BASE__') { $env:PATCHERLY_ARTIFACT_BASE.TrimEnd('/') } else { if ($env:CONNECTOR_ARTIFACT_BASE_URL) { $env:CONNECTOR_ARTIFACT_BASE_URL.TrimEnd('/') } else { 'https://github.com/Patcherly-Official/patcherly-connector-packages/releases/download/connector-packages' } }

function Log-Info { Write-Host "[INFO] $args" -ForegroundColor Green }
function Log-Warn { Write-Host "[WARN] $args" -ForegroundColor Yellow }
function Log-Err  { Write-Host "[ERROR] $args" -ForegroundColor Red }

$token = $Token
if (-not $token) { $token = Read-Host 'Paste your install token (from dashboard Connect > Generate install command)' }
$token = ($token -as [string]).Trim()
if (-not $token) { Log-Err 'Token is required.'; exit 1 }

Log-Info 'Redeeming install token...'
try {
  $redeem = Invoke-RestMethod -Uri "$PATCHERLY_API_BASE/api/public/install/redeem?token=$([uri]::EscapeDataString($token))" -Method Get
} catch {
  Log-Err "Token redemption failed. Token may be expired or already used. $($_.Exception.Message)"
  exit 1
}
$apiKey = $redeem.agent_api_key
$serverUrl = if ($redeem.api_base_url) { $redeem.api_base_url.TrimEnd('/') } else { $PATCHERLY_API_BASE }
if (-not $apiKey) { Log-Err 'No API key in response.'; exit 1 }
Log-Info 'Token redeemed successfully.'

$installDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { Join-Path $env:USERPROFILE 'patcherly-connector' }
$agentType = if ($env:AGENT_TYPE) { $env:AGENT_TYPE } else { 'nodejs' }
if (-not (Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }

Log-Info "Server URL: $serverUrl"
Log-Info "Install directory: $installDir"
Log-Info "Agent type: $agentType"

if ($agentType -eq 'nodejs') {
  Log-Info 'Installing Node.js Agent...'
  $archive = Join-Path $env:TEMP "patcherly-node-agent-$([guid]::NewGuid().ToString('n')).tar.gz"
  try {
    Invoke-WebRequest -Uri "$ARTIFACT_BASE/node-agent.tar.gz" -OutFile $archive -UseBasicParsing
    tar -xzf $archive -C $installDir 2>$null
    if (Test-Path $archive) { Remove-Item $archive -Force }
  } catch { Log-Warn "Could not download node-agent.tar.gz: $($_.Exception.Message)" }
  if (-not (Test-Path (Join-Path $installDir 'package.json'))) {
    @{ name = 'patcherly-agent'; private = $true; dependencies = @{ dotenv = '^16.0.0' } } | ConvertTo-Json | Set-Content (Join-Path $installDir 'package.json') -Encoding utf8
  }
  @"
AGENT_API_KEY=$apiKey
SERVER_URL=$serverUrl
"@ | Set-Content (Join-Path $installDir '.env') -Encoding utf8 -NoNewline
  Log-Info "Node.js Agent installed to $installDir. Run: cd $installDir; npm install; node node_agent.js"
} elseif ($agentType -eq 'python') {
  Log-Info 'Installing Python Agent...'
  $archive = Join-Path $env:TEMP "patcherly-python-agent-$([guid]::NewGuid().ToString('n')).tar.gz"
  try {
    Invoke-WebRequest -Uri "$ARTIFACT_BASE/python-agent.tar.gz" -OutFile $archive -UseBasicParsing
    tar -xzf $archive -C $installDir 2>$null
    if (Test-Path $archive) { Remove-Item $archive -Force }
  } catch { Log-Warn "Could not download python-agent.tar.gz: $($_.Exception.Message)" }
  @"
AGENT_API_KEY=$apiKey
SERVER_URL=$serverUrl
"@ | Set-Content (Join-Path $installDir '.env') -Encoding utf8 -NoNewline
  Log-Info "Python Agent installed to $installDir. Run: cd $installDir; pip install httpx python-dotenv; python python_agent.py"
} else {
  Log-Info 'Installing PHP Agent...'
  $archive = Join-Path $env:TEMP "patcherly-php-agent-$([guid]::NewGuid().ToString('n')).zip"
  try {
    Invoke-WebRequest -Uri "$ARTIFACT_BASE/php-agent.zip" -OutFile $archive -UseBasicParsing
    Expand-Archive -Path $archive -DestinationPath $installDir -Force
    if (Test-Path $archive) { Remove-Item $archive -Force }
  } catch { Log-Warn "Could not download php-agent.zip: $($_.Exception.Message)" }
  @"
AGENT_API_KEY=$apiKey
SERVER_URL=$serverUrl
"@ | Set-Content (Join-Path $installDir '.env') -Encoding utf8 -NoNewline
  Log-Info "PHP Agent installed to $installDir. Run: cd $installDir; php php_agent.php"
}

Log-Info "Installation complete. .env written to $installDir\.env"
