# GitHub v1.0.6 上传指南

仓库：<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter>

必须先上传源码，再创建 `v1.0.6` tag 和 Release。tag 会固定指向创建时的
源码提交；顺序反过来会再次造成发行包与 tag 源码不一致。

## 你只会用到两个文件夹

- `01-仓库源码`：上传到 GitHub 的 Code 页面；
- `02-Release附件`：只把其中的 Windows 安装包上传到 Release 页面。

不要把整个“GitHub上传材料”ZIP 上传到仓库，也不要把安装包放在 Code 页面。

## 第一步：检查并清理 Code 页面

回到仓库首页，确认分支是 `main`。如果根目录仍有旧的 Windows 安装 ZIP，
先点击该文件并使用右上角删除按钮提交删除；历史 Release 不需要删除。

## 第二步：上传完整 v1.0.6 源码

1. 在仓库 `Code` 页面点击 `Add file`，再点 `Upload files`。
2. 在电脑中打开 `01-仓库源码` 文件夹。
3. 进入文件夹后按 `Ctrl+A`，将里面的全部内容拖进 GitHub 上传区域。
4. 不要拖动 `01-仓库源码` 文件夹本身，避免仓库多出一层目录。
5. 等待全部文件显示完成。
6. 提交说明填写：`Release v1.0.6 source`。
7. 选择直接提交到 `main`，点击 `Commit changes`。

提交后打开仓库根目录的 `pyproject.toml`，确认显示：

`version = "1.0.6"`

## 第三步：创建 v1.0.6 Release

1. 打开：<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter/releases/new>
2. 点击 `Choose a tag`，输入 `v1.0.6`。
3. 选择 `Create new tag: v1.0.6 on publish`。
4. `Target` 选择刚刚上传源码的 `main`。
5. `Release title` 填写：`微信聊天导出工具 v1.0.6`。
6. 把本材料根目录的 `发布说明-v1.0.6.md` 全文复制到说明框。
7. 附件区域只上传：`02-Release附件/微信聊天导出工具-v1.0.6-Windows.zip`。
8. 等待附件名称和大小完整出现。
9. 勾选 `Set as the latest release`，不要勾选预发布。
10. 点击 `Publish release`。

`发行包SHA256.txt` 可以作为第二个附件上传，但不是普通用户安装所必需。

## 第四步：发布后核对

- 标题和 tag 都是 `v1.0.6`；
- 页面显示绿色 `Latest`；
- Assets 中存在 `微信聊天导出工具-v1.0.6-Windows.zip`；
- 点击 tag 后，`pyproject.toml` 仍显示 `1.0.6`；
- 普通用户下载 Windows ZIP，不下载 GitHub 自动生成的 Source code ZIP。

朋友的固定下载页面：
<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter/releases/latest>

若 tag 指向了上传源码之前的提交，先删除错误 Release 和错误 tag，再按
“先源码、后 tag、最后附件”的顺序重新创建。
