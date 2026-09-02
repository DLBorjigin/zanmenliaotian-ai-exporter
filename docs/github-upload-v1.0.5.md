# GitHub v1.0.5 上传指南

仓库：<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter>

这次必须先上传源码，再创建 `v1.0.5` tag 和 Release。tag 会固定指向创建时的
源码提交；顺序反过来会再次造成“发行包与 tag 源码不一致”。

## 你只会用到两个文件夹

- `01-仓库源码`：上传到 GitHub 的 Code 页面；
- `02-Release附件`：只把其中的 Windows 安装包上传到 Release 页面。

不要把整个“GitHub上传材料”ZIP 上传到仓库，也不要把安装包继续放在 Code 页面。

## 第一步：清理 Code 页面中的旧安装包

仓库首页目前有一个 `微信聊天导出工具-v1.0.6-Windows.zip`。它是安装包，不是源码，
而且会造成版本号混乱。点击这个文件，使用右上角的删除文件按钮，提交说明填写：

`Remove misplaced old release archive`

确认提交到 `main`。已有的 `v1.0.4` Release 不必删除。

## 第二步：上传完整 v1.0.5 源码

1. 回到仓库的 `Code` 页面，确认当前分支为 `main`。
2. 点击 `Add file`，再点 `Upload files`。
3. 在电脑上打开 `01-仓库源码` 文件夹。
4. 进入该文件夹后按 `Ctrl+A` 选择里面的全部内容，再拖进 GitHub 上传区域。
   不要拖动 `01-仓库源码` 文件夹本身，否则可能多出一层目录。
5. 等待所有文件显示完成。该目录少于 100 个文件，适合网页一次上传。
6. 提交说明填写：`Release v1.0.5 source`。
7. 选择直接提交到 `main`，点击 `Commit changes` 或 `Propose changes`。
   如果页面只允许创建新分支，则按页面提示创建 Pull Request 并合并。

提交完成后，在仓库首页点开 `pyproject.toml`，确认能看到：

`version = "1.0.5"`

同时确认仓库根目录已经没有任何 `v1.0.6` 或 `v1.0.7` 安装 ZIP。

## 第三步：创建 v1.0.5 Release

1. 打开：<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter/releases/new>
2. 点击 `Choose a tag`，输入 `v1.0.5`。
3. 选择 `Create new tag: v1.0.5 on publish`。
4. `Target` 必须选择刚刚上传源码的 `main`。
5. `Release title` 填写：`微信聊天导出工具 v1.0.5`。
6. 将本材料根目录的 `发布说明-v1.0.5.md` 全文复制到说明框。
7. 在附件区域只上传：
   `02-Release附件/微信聊天导出工具-v1.0.5-Windows.zip`
8. 等待附件名称和大小完整出现。
9. 勾选 `Set as the latest release`，不要勾选 `This is a pre-release`。
10. 点击 `Publish release`。

`发行包SHA256.txt` 可以作为第二个附件上传，方便进阶用户核验，但不是安装所必需。

## 第四步：发布后核对

发布页应同时满足：

- 标题和 tag 都是 `v1.0.5`；
- 页面显示绿色 `Latest`；
- Assets 中存在 `微信聊天导出工具-v1.0.5-Windows.zip`；
- 点击 tag 后，`pyproject.toml` 仍显示 `1.0.5`；
- 普通用户只下载上述 Windows ZIP，不下载 GitHub 自动生成的 `Source code (zip)`。

朋友的固定下载页面是：
<https://github.com/DLBorjigin/zanmenliaotian-ai-exporter/releases/latest>

## 如果传错了

在真正公开分享前，如果 tag、标题或附件选错，先不要让朋友下载。进入 Release 页面，
点击铅笔修改标题或说明；若 tag 指向了上传源码之前的提交，最稳妥的方法是删除这条
错误 Release 和错误 tag，然后按“先源码、后 tag、最后附件”的顺序重新创建。

GitHub 官方说明：

- 网页上传文件：<https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository>
- 创建 Release：<https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository>
