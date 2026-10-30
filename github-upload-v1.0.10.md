# GitHub v1.0.10 上传指南

仓库：<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter>

这次请严格按“先源码、再 tag、最后 Release 附件”的顺序。`v1.0.10` 安装包较大，
因为已经内置离线语音模型；上传时等待进度完成，不要刷新页面。

## 先认清三个位置

- `01-仓库源码`：上传到 GitHub 仓库的 **Code** 页面；
- `02-Release附件`：其中的 Windows ZIP 上传到 **Release** 页面；
- 外层 `GitHub上传材料-v1.0.10.zip`：只是给你保存和搬运整套材料，不上传。

不要把 Windows 安装包放进 Code 页面。模型只存在于 Release 附件中，仓库源码用
`vendor/voice-runtime.json` 和 `scripts/prepare_voice_runtime.py` 记录可复现方法。

## 第一步：上传 v1.0.10 源码

1. 打开仓库首页，点上方 `Code`。
2. 确认左上分支是 `main`。
3. 点文件列表上方的 `Add file` → `Upload files`。
4. 在电脑中打开本材料的 `01-仓库源码`。
5. 分批上传：先拖入根目录的单独文件并提交，然后回到仓库根目录，依次拖入 `.github`、`docs`、`licenses`、`scripts`、`skill`、`src`、`tests`、`vendor` 文件夹，每批上传并提交一次。每批始终从仓库根目录开始，保留文件夹本身，这样内部目录不会错位。
6. 不要拖 `01-仓库源码` 文件夹本身，否则仓库会多一层目录。
7. 每批上传完成后，提交说明填：`Release v1.0.10 source`。
8. 选择直接提交到 `main`，点 `Commit changes`。

全部批次都提交后，再创建 Release。先在仓库根目录点开 `pyproject.toml`，必须看到：

`version = "1.0.10"`

如果仓库根目录仍有旧的 `*Windows.zip`，不要继续把新安装包放在那里；历史 Release
不需要删除。先检查旧 ZIP 是否还有用途，再决定是否移除。

## 第二步：创建 v1.0.10 Release

1. 打开 <https://github.com/DLBorjigin/zanmenliaotian-ai-exporter/releases/new>。
2. 点 `Choose a tag`，输入 `v1.0.10`。
3. 选择 `Create new tag: v1.0.10 on publish`。
4. `Target` 选择刚上传完源码的 `main`。
5. `Release title` 填：`微信聊天导出工具 v1.0.10`。
6. 把本材料根目录的 `发布说明-v1.0.10.md` 全文复制到说明框。
7. 在附件框只拖入：
   `02-Release附件/微信聊天导出工具-v1.0.10-Windows.zip`。
8. 大文件上传会花一段时间。必须等文件名、大小和上传完成状态都出现。
9. 可再上传同文件夹中的 `发行包SHA256.txt`，供高级用户校验。
10. 勾选 `Set as the latest release`，不要勾选预发布，然后点 `Publish release`。

## 第三步：发布后验收

- 标题和 tag 都是 `v1.0.10`；
- 页面有绿色 `Latest`；
- Assets 中有 `微信聊天导出工具-v1.0.10-Windows.zip`；
- 安装包包含约 141 MiB 的模型，具体文件大小见本材料的 `材料清单.json`；
- 点进 `v1.0.10` tag 后，`pyproject.toml` 显示 `1.0.10`；
- 普通朋友下载 Windows ZIP，不下载 GitHub 自动生成的 Source code ZIP。

朋友的固定下载页：
<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter/releases/latest>

如果已经创建了 v1.0.10 tag 却尚未上传完源码，请先暂停发布并让维护者检查 tag 指向；不要把新安装包挂在旧源码 tag 下。

GitHub 网页一次最多上传 100 个文件，上面的分批方法避免超过此限制。
官方说明：[上传文件](https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository)。

如果界面显示 `Propose changes` 而非直接提交，请按界面创建分支和合并请求，
合并到 main 后再创建 tag。若启用了不可变 Release，先保存草稿并上传全部附件，
确认完成后再发布。官方说明：[管理 Release](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)。
