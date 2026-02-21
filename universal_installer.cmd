@echo off
REM Universal Connector Installer for Patcherly (Windows CMD)
REM Usage: install.cmd YOUR_TOKEN
REM Or download first: curl -sS "https://api.patcherly.com/api/public/install.cmd" -o install.cmd && install.cmd YOUR_TOKEN
REM API_BASE is injected when served.
setlocal
set "API_BASE=__PATCHERLY_API_BASE__"
set "PS1_URL=%API_BASE%/api/public/install.ps1"
set "TMP_PS1=%TEMP%\patcherly-install.ps1"
echo [INFO] Downloading installer...
curl -sS "%PS1_URL%" -o "%TMP_PS1%"
if errorlevel 1 (
  echo [ERROR] Failed to download installer. Check your connection and API URL.
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%TMP_PS1%" -Token %1
endlocal
