import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wechat_ai_exporter import key_probe as kp
from test_key_probe import encrypted_page_for_master


class Build42053Tests(unittest.TestCase):
    def test_exact_build_validates_target(self):
        page, key = encrypted_page_for_master(bytes(range(32)))
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "test.db"
            database.write_bytes(page)
            with (
                mock.patch.object(kp, "_process_ids", return_value=[123]),
                mock.patch.object(kp, "_candidate_master_keys", return_value=iter(())),
                mock.patch.object(
                    kp, "_candidate_wcdb_config_keys",
                    return_value=iter([bytearray(key)]),
                ),
                mock.patch.object(
                    kp, "_weixin_module",
                    return_value=(1, 2, Path("C:/Weixin/4.2.0.53/Weixin.dll")),
                ),
            ):
                result = kp.probe_database_key(
                    database, authorized=True, time_budget_seconds=20
                )
        self.assertEqual(result.adapter, "weixin-4.2.0.53-exact-salt-config")
        self.assertEqual(bytes(result.key), key)
        kp.wipe_key(result.key)

    def test_bad_key_is_rejected(self):
        page, _ = encrypted_page_for_master(bytes(range(32)))
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "test.db"
            database.write_bytes(page)
            with (
                mock.patch.object(kp, "_process_ids", return_value=[123]),
                mock.patch.object(kp, "_candidate_master_keys", return_value=iter(())),
                mock.patch.object(
                    kp, "_candidate_wcdb_config_keys",
                    return_value=iter([bytearray(32)]),
                ),
                mock.patch.object(
                    kp, "_weixin_module",
                    return_value=(1, 2, Path("C:/Weixin/4.2.0.53/Weixin.dll")),
                ),
            ):
                with self.assertRaises(kp.ProbeError):
                    kp.probe_database_key(
                        database, authorized=True, time_budget_seconds=20
                    )

    def test_unknown_neighbor_build_is_rejected(self):
        with (
            mock.patch.object(
                kp, "_weixin_module",
                return_value=(1, 2, Path("C:/Weixin/4.2.0.54/Weixin.dll")),
            ),
            mock.patch.object(kp, "_process_memory_hits") as scan,
        ):
            self.assertEqual(
                list(kp._candidate_wcdb_config_keys(123, b"x" * 4096, 10**12)),
                [],
            )
            scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
