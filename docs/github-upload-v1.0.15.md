# GitHub v1.0.15 上传指南

仓库：<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter>

严格按“先源码、再 tag、最后 Release 附件”的顺序操作。安装包内置离线语音模型，上传时请等待进度完成，不要刷新页面。

## 先认清三个位置

- `01-仓库源码`：上传到 GitHub 仓库的 **Code** 页面；
- `02-Release附件`：其中的 Windows ZIP 上传到 **Release** 页面；
- 外层 `GitHub上传材料-v1.0.15.zip`：只用于保存整套材料，不上传。

## 第一步：上传 v1.0.15 源码

1. 打开仓库首页，进入 `Code`，确认分支为 `main`。
2. 点 `Add file` → `Upload files`。
3. 打开本材料的 `01-仓库源码`，先拖入根目录的单独文件并提交。
4. 回到仓库根目录，依次拖入 `.github`、`docs`、`licenses`、`scripts`、`skill`、`src`、`tests`、`vendor` 文件夹，每批提交一次。
5. 不要拖入 `01-仓库源码` 文件夹本身，提交说明填 `Release v1.0.15 source`。
6. 全部提交后，打开仓库根目录的 `pyproject.toml`，确认显示 `version = "1.0.15"`。

## 第二步：创建 v1.0.15 Release

1. 打开 <https://github.com/DLBorjigin/zanmenliaotian-ai-exporter/releases/new>。
2. `Choose a tag` 输入 `v1.0.15`，选择在当前 `main` 上创建新 tag。
3. 标题填 `微信聊天导出工具 v1.0.15`。
4. 把材料根目录的 `发布说明-v1.0.15.md` 复制到说明框。
5. 附件框只拖入 `02-Release附件/微信聊天导出工具-v1.0.15-Windows.zip`。
6. 等待文件名、大小和上传完成状态出现，设为 Latest，然后发布。

不要上传 `发行包SHA256.txt`；它仅留在本地材料中供你自己核验。

## 第三步：发布后验收

- 标题和 tag 都是 `v1.0.15`，页面有绿色 `Latest`；
- Assets 中有 `微信聊天导出工具-v1.0.15-Windows.zip`；
- tag 内 `pyproject.toml` 显示 `1.0.15`；
- 普通朋友下载 Windows ZIP，不下载 GitHub 自动生成的 Source code ZIP。

朋友固定下载页：<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter/releases/latest>

GitHub 网页一次最多上传 100 个文件，因此源码需按上述方式分批上传。如果已经创建 tag 却发现源码未传完整，请先停止发布，不要把新安装包挂在旧源码 tag 下。
