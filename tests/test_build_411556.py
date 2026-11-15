import tempfile
import unittest
from pathlib import Path
from unittest import mock
from wechat_ai_exporter import key_probe as kp
from test_key_probe import encrypted_page_for_master

class Build411556Tests(unittest.TestCase):
    def test_exact_build_validates_target(self):
        page,key=encrypted_page_for_master(bytes(range(32)))
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'test.db';p.write_bytes(page)
            with mock.patch.object(kp,'_process_ids',return_value=[123]), mock.patch.object(kp,'_candidate_master_keys',return_value=iter(())), mock.patch.object(kp,'_candidate_wcdb_config_keys',return_value=iter([bytearray(key)])), mock.patch.object(kp,'_weixin_module',return_value=(1,2,Path('C:/Weixin/4.1.15.56/Weixin.dll'))):
                result=kp.probe_database_key(p,authorized=True,time_budget_seconds=20)
        self.assertEqual(result.adapter,'weixin-4.1.15.56-exact-salt-config')
        self.assertEqual(bytes(result.key),key)
        kp.wipe_key(result.key)

    def test_bad_key_is_rejected(self):
        page,_=encrypted_page_for_master(bytes(range(32)))
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'test.db';p.write_bytes(page)
            with mock.patch.object(kp,'_process_ids',return_value=[123]), mock.patch.object(kp,'_candidate_master_keys',return_value=iter(())), mock.patch.object(kp,'_candidate_wcdb_config_keys',return_value=iter([bytearray(32)])):
                with self.assertRaises(kp.ProbeError):
                    kp.probe_database_key(p,authorized=True,time_budget_seconds=20)
