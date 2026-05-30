# Universal Connector Installer for Patcherly (PowerShell, OAuth pairing)
#
# Usage:
#   irm https://api.patcherly.com/api/public/install.ps1 | iex
#
# After install, pair the connector with a target via OAuth Device Authorization Grant:
#   cd <install dir>; .\start.ps1 login
#
# Environment overrides:
#   API_BASE             override the API host (default https://api.patcherly.com)
#   ARTIFACT_BASE        override the GitHub release for connector packages
#   AGENT_TYPE           force connector type (nodejs|python|php) — default nodejs
#   INSTALL_DIR          install path (default %USERPROFILE%\patcherly-connector)
$ErrorActionPreference = 'Stop'

$PATCHERLY_API_BASE = if ($env:PATCHERLY_API_BASE -and $env:PATCHERLY_API_BASE -ne '__PATCHERLY_API_BASE__') { $env:PATCHERLY_API_BASE.TrimEnd('/') } else { if ($env:API_BASE) { $env:API_BASE.TrimEnd('/') } else { 'https://api.patcherly.com' } }
$ARTIFACT_BASE = if ($env:PATCHERLY_ARTIFACT_BASE -and $env:PATCHERLY_ARTIFACT_BASE -ne '__PATCHERLY_ARTIFACT_BASE__') { $env:PATCHERLY_ARTIFACT_BASE.TrimEnd('/') } else { if ($env:CONNECTOR_ARTIFACT_BASE_URL) { $env:CONNECTOR_ARTIFACT_BASE_URL.TrimEnd('/') } else { 'https://github.com/Patcherly-Official/patcherly-connector-packages/releases/download/connector-packages' } }
$PATCHERLY_CONNECTOR_RELEASE = if ($env:PATCHERLY_CONNECTOR_RELEASE) { $env:PATCHERLY_CONNECTOR_RELEASE } else { '1.46.0' }

function Log-Info { Write-Host "[INFO] $args" -ForegroundColor Green }
function Log-Warn { Write-Host "[WARN] $args" -ForegroundColor Yellow }
function Log-Err  { Write-Host "[ERROR] $args" -ForegroundColor Red }

$installDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { Join-Path $env:USERPROFILE 'patcherly-connector' }
$agentType = if ($env:AGENT_TYPE) { $env:AGENT_TYPE } else { 'nodejs' }
if (-not (Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }

Log-Info "API base: $PATCHERLY_API_BASE"
Log-Info "Connector release track: $PATCHERLY_CONNECTOR_RELEASE"
Log-Info "Install directory: $installDir"
Log-Info "Connector type: $agentType"

function Write-EnvFile {
  param([string]$Dir, [string]$Server)
  Set-Content -Path (Join-Path $Dir '.env') -Encoding utf8 -NoNewline -Value "SERVER_URL=$Server`n"
}

function Write-StartScript {
  param([string]$Dir, [string]$Type, [string]$ApiBase)
  $startPath = Join-Path $Dir 'start.ps1'
  switch ($Type) {
    'nodejs' {
      $script = @"
param([string]`$Action = 'run')
Set-Location -Path `$PSScriptRoot
if (-not (Test-Path 'node_modules')) { npm install --production | Out-Null }
switch (`$Action) {
  'login' { node .\node_modules\.bin\patcherly login --api-base $ApiBase }
  default { node node_agent.js }
}
"@
    }
    'python' {
      $script = @"
param([string]`$Action = 'run')
Set-Location -Path `$PSScriptRoot
switch (`$Action) {
  'login' { .\venv\Scripts\python.exe patcherly_cli.py login --api-base $ApiBase }
  default { .\venv\Scripts\python.exe python_agent.py }
}
"@
    }
    default {
      $script = @"
param([string]`$Action = 'run')
Set-Location -Path `$PSScriptRoot
switch (`$Action) {
  'login' { php patcherly_cli.php login --api-base $ApiBase }
  default { php php_agent.php }
}
"@
    }
  }
  Set-Content -Path $startPath -Value $script -Encoding utf8
}

if ($agentType -eq 'nodejs') {
  Log-Info 'Installing Node.js connector...'
  $archive = Join-Path $env:TEMP "patcherly-node-agent-$([guid]::NewGuid().ToString('n')).tar.gz"
  try {
    Invoke-WebRequest -Uri "$ARTIFACT_BASE/node-agent.tar.gz" -OutFile $archive -UseBasicParsing
    tar -xzf $archive -C $installDir 2>$null
    if (Test-Path $archive) { Remove-Item $archive -Force }
  } catch { Log-Warn "Could not download node-agent.tar.gz: $($_.Exception.Message)" }
  if (-not (Test-Path (Join-Path $installDir 'package.json'))) {
    @{ name = 'patcherly-agent'; private = $true; dependencies = @{ dotenv = '^16.0.0' } } | ConvertTo-Json | Set-Content (Join-Path $installDir 'package.json') -Encoding utf8
  }
  Write-EnvFile -Dir $installDir -Server $PATCHERLY_API_BASE
  Write-StartScript -Dir $installDir -Type 'nodejs' -ApiBase $PATCHERLY_API_BASE
  Log-Info "Node.js connector installed to $installDir"
} elseif ($agentType -eq 'python') {
  Log-Info 'Installing Python connector...'
  $archive = Join-Path $env:TEMP "patcherly-python-agent-$([guid]::NewGuid().ToString('n')).tar.gz"
  try {
    Invoke-WebRequest -Uri "$ARTIFACT_BASE/python-agent.tar.gz" -OutFile $archive -UseBasicParsing
    tar -xzf $archive -C $installDir 2>$null
    if (Test-Path $archive) { Remove-Item $archive -Force }
  } catch { Log-Warn "Could not download python-agent.tar.gz: $($_.Exception.Message)" }
  Write-EnvFile -Dir $installDir -Server $PATCHERLY_API_BASE
  Write-StartScript -Dir $installDir -Type 'python' -ApiBase $PATCHERLY_API_BASE
  Log-Info "Python connector installed to $installDir"
} else {
  Log-Info 'Installing PHP connector...'
  $archive = Join-Path $env:TEMP "patcherly-php-agent-$([guid]::NewGuid().ToString('n')).zip"
  try {
    Invoke-WebRequest -Uri "$ARTIFACT_BASE/php-agent.zip" -OutFile $archive -UseBasicParsing
    Expand-Archive -Path $archive -DestinationPath $installDir -Force
    if (Test-Path $archive) { Remove-Item $archive -Force }
  } catch { Log-Warn "Could not download php-agent.zip: $($_.Exception.Message)" }
  Write-EnvFile -Dir $installDir -Server $PATCHERLY_API_BASE
  Write-StartScript -Dir $installDir -Type 'php' -ApiBase $PATCHERLY_API_BASE
  Log-Info "PHP connector installed to $installDir"
}

Log-Info "Installation complete."
Log-Info "Next step: pair this connector with a target via OAuth:"
Log-Info "  cd $installDir; .\start.ps1 login"
Log-Info "Then start the connector with: cd $installDir; .\start.ps1"
