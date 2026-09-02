from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import tomllib
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _zip_tree(root: Path, destination: Path, prefix: str = "") -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            relative = path.relative_to(root)
            archive.write(path, Path(prefix) / relative)


def build(output: Path) -> list[Path]:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    project_metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = project_metadata["project"]["version"]
    with tempfile.TemporaryDirectory(prefix="wechat-export-release-") as temp:
        staging = Path(temp)
        skill_stage = staging / "wechat-chat-export"
        shutil.copytree(PROJECT_ROOT / "skill" / "wechat-chat-export", skill_stage)
        runtime = skill_stage / "runtime"
        shutil.copytree(PROJECT_ROOT / "src", runtime / "src")
        shutil.copy2(PROJECT_ROOT / "pyproject.toml", runtime / "pyproject.toml")
        shutil.copy2(PROJECT_ROOT / "THIRD_PARTY_NOTICES.md", runtime / "THIRD_PARTY_NOTICES.md")
        shutil.copytree(PROJECT_ROOT / "licenses", runtime / "licenses")
        skill_zip = output / "wechat-chat-export.zip"
        _zip_tree(skill_stage, skill_zip, "wechat-chat-export")

        source_stage = staging / "wechat-ai-exporter"
        for directory in (
            ".github", "src", "skill", "scripts", "tests", "docs", "licenses"
        ):
            shutil.copytree(PROJECT_ROOT / directory, source_stage / directory)
        for filename in (
            ".gitignore", "CONTRIBUTING.md", "LICENSE", "PRIVACY.md", "README.md",
            "README.zh-CN.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "pyproject.toml",
        ):
            shutil.copy2(PROJECT_ROOT / filename, source_stage / filename)
        source_zip = output / "wechat-ai-exporter-source.zip"
        _zip_tree(source_stage, source_zip, "wechat-ai-exporter")

    readme = output / "开始使用.md"
    shutil.copy2(PROJECT_ROOT / "README.zh-CN.md", readme)
    release_notes = output / f"发布说明-v{version}.md"
    shutil.copy2(PROJECT_ROOT / "docs" / f"release-notes-v{version}.md", release_notes)
    script_names = {
        "install_skill.ps1": "安装工具.ps1",
        "install_skill.cmd": "双击安装.cmd",
        "uninstall_skill.ps1": "卸载工具.ps1",
        "uninstall_skill.cmd": "双击卸载.cmd",
        "restore_skill.ps1": "恢复上一版本.ps1",
        "restore_skill.cmd": "双击恢复上一版本.cmd",
    }
    copied_scripts = []
    for source_name, release_name in script_names.items():
        destination = output / release_name
        shutil.copy2(PROJECT_ROOT / "scripts" / source_name, destination)
        copied_scripts.append(destination)
    release_info = output / "版本信息.json"
    release_info.write_text(json.dumps({
        "product": "wechat-ai-exporter",
        "version": version,
        "channel": "stable",
        "platform": "Windows 10/11 x64",
        "skill_name": "wechat-chat-export",
        "network_required": False,
        "optional_network_media_download": True,
        "wechat_process_modified": False,
        "native_hook_bundled": False,
        "live_validated_weixin_versions": ["4.1.12.55", "4.1.13.12"],
        "additional_read_only_adapters": ["4.1.10"],
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    primary = [skill_zip, source_zip, readme, release_notes, release_info, *copied_scripts]
    checksum = output / "SHA256SUMS.txt"
    checksum.write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in primary
        ),
        encoding="utf-8",
    )
    bundle = output / f"微信聊天导出工具-v{version}-Windows.zip"
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in [*primary, checksum]:
            archive.write(path, Path(f"微信聊天导出工具-v{version}") / path.name)
    bundle_checksum = output / "发行包SHA256.txt"
    bundle_checksum.write_text(
        f"{hashlib.sha256(bundle.read_bytes()).hexdigest()}  {bundle.name}\n",
        encoding="utf-8",
    )
    return [bundle, bundle_checksum, *primary, checksum]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    for artifact in build(args.output):
        print(artifact)
