from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import tomllib
import zipfile

from build_release import build as build_release


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_DIRECTORIES = (
    ".github", "docs", "licenses", "scripts", "skill", "src", "tests",
)
REPOSITORY_FILES = (
    ".gitignore", "CONTRIBUTING.md", "LICENSE", "PRIVACY.md", "README.md",
    "README.zh-CN.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "pyproject.toml",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ignored(path: Path) -> bool:
    return "__pycache__" in path.parts or path.suffix == ".pyc"


def _copy_repository(destination: Path) -> None:
    destination.mkdir(parents=True)
    for name in REPOSITORY_DIRECTORIES:
        shutil.copytree(
            PROJECT_ROOT / name,
            destination / name,
            ignore=lambda _root, names: [
                name for name in names if name == "__pycache__" or name.endswith(".pyc")
            ],
        )
    for name in REPOSITORY_FILES:
        shutil.copy2(PROJECT_ROOT / name, destination / name)


def _zip_tree(root: Path, destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file() and not _ignored(path):
                archive.write(path, (Path(root.name) / path.relative_to(root)).as_posix())


def build(output_parent: Path) -> tuple[Path, Path]:
    metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = metadata["project"]["version"]
    kit = output_parent.resolve() / f"GitHub上传材料-v{version}"
    if kit.exists():
        raise FileExistsError(f"Output already exists: {kit}")
    repository = kit / "01-仓库源码"
    release_assets = kit / "02-Release附件"
    _copy_repository(repository)
    release_assets.mkdir(parents=True)

    with tempfile.TemporaryDirectory(prefix="wechat-publish-kit-") as temp:
        built = build_release(Path(temp))
        bundle = next(path for path in built if path.name == f"微信聊天导出工具-v{version}-Windows.zip")
        checksum = next(path for path in built if path.name == "发行包SHA256.txt")
        shutil.copy2(bundle, release_assets / bundle.name)
        shutil.copy2(checksum, release_assets / checksum.name)

    shutil.copy2(
        PROJECT_ROOT / "docs" / f"release-notes-v{version}.md",
        kit / f"发布说明-v{version}.md",
    )
    shutil.copy2(
        PROJECT_ROOT / "docs" / f"github-upload-v{version}.md",
        kit / "上传指南.md",
    )
    source_hashes = {
        path.relative_to(repository).as_posix(): _sha256(path)
        for path in sorted(repository.rglob("*"))
        if path.is_file() and not _ignored(path)
    }
    manifest = {
        "version": version,
        "release_asset": {
            "file": bundle.name,
            "size": (release_assets / bundle.name).stat().st_size,
            "sha256": _sha256(release_assets / bundle.name),
        },
        "repository_file_count": len(source_hashes),
        "repository_files_sha256": source_hashes,
        "publish_order": ["upload_source", f"create_v{version}_tag", "publish_release"],
    }
    (kit / "材料清单.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    archive = output_parent.resolve() / f"GitHub上传材料-v{version}.zip"
    if archive.exists():
        raise FileExistsError(f"Output already exists: {archive}")
    _zip_tree(kit, archive)
    return kit, archive


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-parent", required=True, type=Path)
    args = parser.parse_args()
    for artifact in build(args.output_parent):
        print(artifact)
