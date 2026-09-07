# GitHub v1.0.7 上传指南

仓库：<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter>

这次请严格按“先源码、再 tag、最后 Release 附件”的顺序。`v1.0.7` 安装包较大，
因为已经内置离线语音模型；上传时等待进度完成，不要刷新页面。

## 先认清三个位置

- `01-仓库源码`：上传到 GitHub 仓库的 **Code** 页面；
- `02-Release附件`：其中的 Windows ZIP 上传到 **Release** 页面；
- 外层 `GitHub上传材料-v1.0.7.zip`：只是给你保存和搬运整套材料，不上传。

不要把 Windows 安装包放进 Code 页面。模型只存在于 Release 附件中，仓库源码用
`vendor/voice-runtime.json` 和 `scripts/prepare_voice_runtime.py` 记录可复现方法。

## 第一步：上传 v1.0.7 源码

1. 打开仓库首页，点上方 `Code`。
2. 确认左上分支是 `main`。
3. 点文件列表上方的 `Add file` → `Upload files`。
4. 在电脑中打开本材料的 `01-仓库源码`。
5. 进入该文件夹后按 `Ctrl+A`，把里面的所有内容拖到网页上传区域。
6. 不要拖 `01-仓库源码` 文件夹本身，否则仓库会多一层目录。
7. 等所有小文件上传完，提交说明填：`Release v1.0.7 source`。
8. 选择直接提交到 `main`，点 `Commit changes`。

提交后在仓库根目录点开 `pyproject.toml`，必须看到：

`version = "1.0.7"`

如果仓库根目录仍有旧的 `*Windows.zip`，请先在 Code 页面删除它；历史 Release
不需要删除。

## 第二步：创建 v1.0.7 Release

1. 打开 <https://github.com/DLBorjigin/zanmenliaotian-ai-exporter/releases/new>。
2. 点 `Choose a tag`，输入 `v1.0.7`。
3. 选择 `Create new tag: v1.0.7 on publish`。
4. `Target` 选择刚上传完源码的 `main`。
5. `Release title` 填：`微信聊天导出工具 v1.0.7`。
6. 把本材料根目录的 `发布说明-v1.0.7.md` 全文复制到说明框。
7. 在附件框只拖入：
   `02-Release附件/微信聊天导出工具-v1.0.7-Windows.zip`。
8. 大文件上传会花一段时间。必须等文件名、大小和上传完成状态都出现。
9. 可再上传同文件夹中的 `发行包SHA256.txt`，供高级用户校验。
10. 勾选 `Set as the latest release`，不要勾选预发布，然后点 `Publish release`。

## 第三步：发布后验收

- 标题和 tag 都是 `v1.0.7`；
- 页面有绿色 `Latest`；
- Assets 中有 `微信聊天导出工具-v1.0.7-Windows.zip`；
- 安装包大小应明显大于旧版本，因为包含约 141 MiB 的模型；
- 点进 `v1.0.7` tag 后，`pyproject.toml` 显示 `1.0.7`；
- 普通朋友下载 Windows ZIP，不下载 GitHub 自动生成的 Source code ZIP。

朋友的固定下载页：
<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter/releases/latest>

如果错误地先建了 tag，请删除错误 Release 和 `v1.0.7` tag，然后从第一步重新按顺序做。
