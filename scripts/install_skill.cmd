@echo off
chcp 65001 >nul
title 安装微信聊天导出工具
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0安装工具.ps1"
set "result=%errorlevel%"
echo.
if not "%result%"=="0" echo 安装没有完成，请把上方错误信息发给提供工具的人。
pause
exit /b %result%
