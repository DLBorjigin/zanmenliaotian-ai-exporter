@echo off
chcp 65001 >nul
title 卸载微信聊天导出工具
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0卸载工具.ps1"
set "result=%errorlevel%"
echo.
pause
exit /b %result%
