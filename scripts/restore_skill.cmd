@echo off
chcp 65001 >nul
title 恢复上一版微信聊天导出工具
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0恢复上一版本.ps1"
set "result=%errorlevel%"
echo.
pause
exit /b %result%
