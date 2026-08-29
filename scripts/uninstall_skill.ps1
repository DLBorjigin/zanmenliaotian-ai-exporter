param([switch]$Quiet)

$ErrorActionPreference = "Stop"
$codexRoot = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE ".codex" }
$destination = Join-Path (Join-Path $codexRoot "skills") "wechat-chat-export"
if (-not (Test-Path -LiteralPath $destination)) {
    Write-Host "没有检测到已安装的微信聊天导出工具。"
    exit 0
}
$removed = $destination + ".removed-" + (Get-Date -Format "yyyyMMdd-HHmmss")
Move-Item -LiteralPath $destination -Destination $removed
Write-Host "工具已停用。原文件保存在可恢复位置：$removed" -ForegroundColor Green
Write-Host "重新打开 Codex 后生效。"
