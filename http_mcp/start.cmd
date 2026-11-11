@echo off
setlocal
cd /d "%~dp0.."
python -u "http_mcp\server.py" %*
