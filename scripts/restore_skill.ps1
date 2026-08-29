param([switch]$Quiet)

$ErrorActionPreference = "Stop"
$codexRoot = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE ".codex" }
$skillsRoot = Join-Path $codexRoot "skills"
$destination = Join-Path $skillsRoot "wechat-chat-export"
$backup = Get-ChildItem -LiteralPath $skillsRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "wechat-chat-export.backup-*" } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $backup) {
    throw "没有找到可以恢复的旧版本。"
}
$current = $null
if (Test-Path -LiteralPath $destination) {
    $current = $destination + ".replaced-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    Move-Item -LiteralPath $destination -Destination $current
}
try {
    Move-Item -LiteralPath $backup.FullName -Destination $destination
}
catch {
    if ($current -and (Test-Path -LiteralPath $current) -and -not (Test-Path -LiteralPath $destination)) {
        Move-Item -LiteralPath $current -Destination $destination
    }
    throw
}
Write-Host "已恢复上一版本。重新打开 Codex 后生效。" -ForegroundColor Green
