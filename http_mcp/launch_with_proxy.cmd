@echo off
setlocal
set "HTTPS_PROXY=http://127.0.0.1:8080"
set "HTTP_PROXY=http://127.0.0.1:8080"
set "ALL_PROXY=http://127.0.0.1:8080"
if "%~1"=="" (
  echo usage: launch_with_proxy.cmd ^<exe^> [args...]
  exit /b 1
)
start "" %*
