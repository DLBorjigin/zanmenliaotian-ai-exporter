import json
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


class ReleaseTests(unittest.TestCase):
    def test_publish_kit_matches_release_embedded_source(self) -> None:
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            output_parent = Path(temp) / "publish"
            output_parent.mkdir()
            built = subprocess.run(
                [sys.executable, str(project / "scripts" / "build_publish_kit.py"),
                 "--output-parent", str(output_parent)],
                cwd=project, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            kit = output_parent / "GitHub上传材料-v1.0.6"
            repository = kit / "01-仓库源码"
            bundle = kit / "02-Release附件" / "微信聊天导出工具-v1.0.6-Windows.zip"
            self.assertTrue((kit / "上传指南.md").is_file())
            self.assertTrue(bundle.is_file())
            self.assertFalse(any(repository.glob("*Windows.zip")))
            manifest = json.loads((kit / "材料清单.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["version"], "1.0.6")

            with zipfile.ZipFile(bundle) as outer:
                source_name = next(
                    name for name in outer.namelist()
                    if name.endswith("/wechat-ai-exporter-source.zip")
                )
                source_bytes = outer.read(source_name)
            with zipfile.ZipFile(io.BytesIO(source_bytes)) as source:
                archived = {
                    name.removeprefix("wechat-ai-exporter/"): hashlib.sha256(
                        source.read(name)
                    ).hexdigest()
                    for name in source.namelist()
                    if not name.endswith("/")
                }
            local = {
                path.relative_to(repository).as_posix(): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in repository.rglob("*") if path.is_file()
            }
            self.assertEqual(archived, local)

    def test_self_contained_skill_release_starts_and_is_clean(self) -> None:
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "release"
            built = subprocess.run(
                [sys.executable, str(project / "scripts" / "build_release.py"),
                 "--output", str(output)],
                cwd=project, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            skill_zip = output / "wechat-chat-export.zip"
            source_zip = output / "wechat-ai-exporter-source.zip"
            self.assertTrue(skill_zip.is_file())
            self.assertTrue(source_zip.is_file())
            self.assertTrue((output / "安装工具.ps1").is_file())
            self.assertTrue((output / "双击安装.cmd").is_file())
            self.assertTrue((output / "双击卸载.cmd").is_file())
            self.assertTrue((output / "双击恢复上一版本.cmd").is_file())
            self.assertTrue((output / "版本信息.json").is_file())
            self.assertTrue((output / "发布说明-v1.0.6.md").is_file())
            self.assertTrue((output / "微信聊天导出工具-v1.0.6-Windows.zip").is_file())
            self.assertTrue((output / "发行包SHA256.txt").is_file())
            with zipfile.ZipFile(skill_zip) as archive:
                names = archive.namelist()
                self.assertIn("wechat-chat-export/SKILL.md", names)
                self.assertIn(
                    "wechat-chat-export/runtime/src/wechat_ai_exporter/cli.py", names
                )
                self.assertFalse(any("VisualPrefetch" in name for name in names))
                self.assertFalse(any("__pycache__" in name or name.endswith(".pyc") for name in names))
                self.assertFalse(any("third_party_reference" in name for name in names))
                archive.extractall(Path(temp) / "unpacked")
            wrapper = Path(temp) / "unpacked" / "wechat-chat-export" / "scripts" / "wechat_export.py"
            run = subprocess.run(
                [sys.executable, str(wrapper), "doctor", "--json"],
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            payload = json.loads(run.stdout)
            self.assertEqual(payload["status"], "runtime_ready")
            self.assertEqual(payload["version"], "1.0.6")
            info = json.loads((output / "版本信息.json").read_text(encoding="utf-8"))
            self.assertIn("4.1.13.12", info["live_validated_weixin_versions"])
            self.assertFalse(payload["network_required"])
            with zipfile.ZipFile(source_zip) as archive:
                license_name = "wechat-ai-exporter/licenses/Apache-2.0.txt"
                self.assertIn("wechat-ai-exporter/README.md", archive.namelist())
                self.assertIn("wechat-ai-exporter/PRIVACY.md", archive.namelist())
                self.assertIn(
                    "wechat-ai-exporter/.github/ISSUE_TEMPLATE/bug_report.yml",
                    archive.namelist(),
                )
                self.assertIn(license_name, archive.namelist())
                self.assertGreater(len(archive.read(license_name)), 10_000)

    @unittest.skipUnless(os.name == "nt", "PowerShell installer test requires Windows")
    def test_one_click_installer_update_restore_and_uninstall(self) -> None:
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "release"
            built = subprocess.run(
                [sys.executable, str(project / "scripts" / "build_release.py"),
                 "--output", str(output)],
                cwd=project, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            env = dict(os.environ)
            env["CODEX_HOME"] = str(root / "codex-home")
            install = output / "安装工具.ps1"
            for _ in range(2):
                run = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                     "-File", str(install), "-Quiet"],
                    env=env, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
            skills = root / "codex-home" / "skills"
            current = skills / "wechat-chat-export"
            self.assertTrue((current / "SKILL.md").is_file())
            self.assertTrue(list(skills.glob("wechat-chat-export.backup-*")))

            restore = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", str(output / "恢复上一版本.ps1"), "-Quiet"],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(restore.returncode, 0, restore.stderr)
            self.assertTrue((current / "SKILL.md").is_file())

            tampered = root / "tampered" / "wechat-chat-export.zip"
            tampered.parent.mkdir()
            tampered.write_bytes((output / "wechat-chat-export.zip").read_bytes() + b"tampered")
            rejected = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", str(install), "-Package", str(tampered),
                 "-ChecksumFile", str(output / "SHA256SUMS.txt"), "-Quiet"],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertTrue((current / "SKILL.md").is_file())

            uninstall = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", str(output / "卸载工具.ps1"), "-Quiet"],
                env=env, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
            self.assertFalse(current.exists())
            self.assertTrue(list(skills.glob("wechat-chat-export.removed-*")))


if __name__ == "__main__":
    unittest.main()
