import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

from wechat_ai_exporter import __version__, key_probe as kp
from wechat_ai_exporter.key_validation import wipe_key
from test_key_probe import encrypted_page_for_master


class CurrentRuntimeTests(unittest.TestCase):
    def test_exact_current_build_validates_before_legacy_scan(self):
        page, expected = encrypted_page_for_master(bytes(range(32)))
        candidate = bytearray(expected)
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "synthetic.db"
            database.write_bytes(page)
            with mock.patch.object(kp, "_process_ids", return_value=[123]), \
                    mock.patch.object(kp, "_weixin_module", return_value=(
                        1, 2, Path("C:/Weixin/4.2.0.13/Weixin.dll"))), \
                    mock.patch.object(kp, "_candidate_wcdb_config_keys", return_value=iter([candidate])), \
                    mock.patch.object(kp, "_candidate_master_keys") as legacy:
                result = kp.probe_database_key(database, authorized=True)
                self.assertEqual(result.adapter, "weixin-4.2.0.13-exact-salt-config")
                self.assertEqual(bytes(result.key), expected)
                legacy.assert_not_called()
                wipe_key(result.key)
        self.assertEqual(candidate, bytearray(32))

    def test_unvalidated_neighbor_build_does_not_open_memory(self):
        with mock.patch.object(kp, "_weixin_module", return_value=(
                1, 2, Path("C:/Weixin/4.2.0.14/Weixin.dll"))), \
                mock.patch.object(kp, "_open_reader") as reader, \
                mock.patch.object(kp, "_process_memory_hits") as scan:
            self.assertEqual(list(kp._candidate_wcdb_config_keys(123, b"x" * 4096, 10**12)), [])
            reader.assert_not_called()
            scan.assert_not_called()

    def test_valid_candidate_is_wiped_if_reporting_module_fails(self):
        page, expected = encrypted_page_for_master(bytes(range(32)))
        candidate = bytearray(expected)
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "synthetic.db"
            database.write_bytes(page)
            with mock.patch.object(kp, "_process_ids", return_value=[123]), \
                    mock.patch.object(kp, "_candidate_wcdb_config_keys", return_value=iter([candidate])), \
                    mock.patch.object(kp, "_weixin_module", side_effect=RuntimeError("synthetic")):
                with self.assertRaises(RuntimeError):
                    kp.probe_database_key(database, authorized=True)
        self.assertEqual(candidate, bytearray(32))

    def test_skill_entrypoint_and_package_metadata_agree(self):
        repo = Path(__file__).resolve().parents[1]
        metadata = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(metadata["project"]["version"], __version__)
        script = repo / "skill/wechat-chat-export/scripts/wechat_export.py"
        run = subprocess.run([sys.executable, "-B", "-X", "utf8", str(script), "doctor", "--json"],
                             capture_output=True, text=True, encoding="utf-8", timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)
        info = json.loads(run.stdout)
        self.assertEqual(info["version"], __version__)
        self.assertIn("weixin-4.2.0.13-exact-salt-config", info["read_only_probe_adapters"])


if __name__ == "__main__":
    unittest.main()
