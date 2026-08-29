param(
    [string]$Package = "",
    [string]$ChecksumFile = "",
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$releaseRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($Package)) {
    $Package = Join-Path $releaseRoot "wechat-chat-export.zip"
}
if ([string]::IsNullOrWhiteSpace($ChecksumFile)) {
    $ChecksumFile = Join-Path $releaseRoot "SHA256SUMS.txt"
}

$archive = (Resolve-Path -LiteralPath $Package).Path
$checksums = (Resolve-Path -LiteralPath $ChecksumFile).Path
$archiveName = Split-Path -Leaf $archive
$line = Get-Content -LiteralPath $checksums -Encoding UTF8 |
    Where-Object { $_ -match ("^[0-9a-fA-F]{64}\s+" + [regex]::Escape($archiveName) + "$") } |
    Select-Object -First 1
if (-not $line) {
    throw "校验清单中没有找到安装包：$archiveName"
}
$expectedHash = ($line -split "\s+")[0].ToUpperInvariant()
$stream = [System.IO.File]::OpenRead($archive)
try {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $actualHash = ([System.BitConverter]::ToString($sha256.ComputeHash($stream))).Replace("-", "")
    }
    finally {
        $sha256.Dispose()
    }
}
finally {
    $stream.Dispose()
}
if ($actualHash -ne $expectedHash) {
    throw "安装包校验失败。文件可能下载不完整或已被改动，请重新获取发行包。"
}

$codexRoot = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE ".codex" }
$skillsRoot = Join-Path $codexRoot "skills"
$destination = Join-Path $skillsRoot "wechat-chat-export"
$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("wechat-chat-export-" + [guid]::NewGuid().ToString("N"))
$backup = $null
$installed = $false

New-Item -ItemType Directory -Path $staging | Out-Null
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
    try {
        foreach ($entry in $zip.Entries) {
            $normalized = $entry.FullName.Replace("\", "/")
            $segments = $normalized.Split("/", [System.StringSplitOptions]::RemoveEmptyEntries)
            if ($normalized.StartsWith("/") -or $segments -contains ".." -or
                ($segments.Count -gt 0 -and $segments[0] -ne "wechat-chat-export")) {
                throw "安装包包含不安全的文件路径，安装已停止。"
            }
        }
    }
    finally {
        $zip.Dispose()
    }

    Expand-Archive -LiteralPath $archive -DestinationPath $staging
    $source = Join-Path $staging "wechat-chat-export"
    $required = @(
        (Join-Path $source "SKILL.md"),
        (Join-Path $source "agents\openai.yaml"),
        (Join-Path $source "scripts\wechat_export.py"),
        (Join-Path $source "runtime\src\wechat_ai_exporter\cli.py")
    )
    foreach ($path in $required) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "安装包不完整，缺少：$(Split-Path -Leaf $path)"
        }
    }

    New-Item -ItemType Directory -Force -Path $skillsRoot | Out-Null
    if (Test-Path -LiteralPath $destination) {
        $backup = $destination + ".backup-" + (Get-Date -Format "yyyyMMdd-HHmmss")
        Move-Item -LiteralPath $destination -Destination $backup
    }
    try {
        Move-Item -LiteralPath $source -Destination $destination
        $installed = $true
    }
    catch {
        if ($backup -and (Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $destination)) {
            Move-Item -LiteralPath $backup -Destination $destination
        }
        throw
    }

    Write-Host ""
    Write-Host "微信聊天导出工具安装成功。" -ForegroundColor Green
    if ($backup) {
        Write-Host "旧版本已安全备份，可使用发行包中的恢复工具还原。"
    }
    Write-Host "请重新打开 Codex，然后直接说：导出我的一段微信聊天。"
}
finally {
    if (Test-Path -LiteralPath $staging) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}

if (-not $installed) {
    exit 1
}
