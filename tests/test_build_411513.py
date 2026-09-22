import tempfile
import unittest
from pathlib import Path
from unittest import mock
from wechat_ai_exporter import key_probe as kp
from test_key_probe import encrypted_page_for_master

class Build411513Tests(unittest.TestCase):
    def test_exact_build_label_and_validated_key(self):
        page,key=encrypted_page_for_master(bytes(range(32)))
        candidate=bytearray(key)
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'test.db';db.write_bytes(page)
            with mock.patch.object(kp,'_process_ids',return_value=[123]), mock.patch.object(kp,'_candidate_master_keys',return_value=iter(())), mock.patch.object(kp,'_candidate_wcdb_config_keys',return_value=iter([candidate])), mock.patch.object(kp,'_weixin_module',return_value=(1,2,Path('C:/Weixin/4.1.15.13/Weixin.dll'))):
                result=kp.probe_database_key(db,authorized=True,time_budget_seconds=20)
        self.assertEqual(result.adapter,'weixin-4.1.15.13-exact-salt-config')
        self.assertEqual(bytes(result.key),key)
        kp.wipe_key(result.key)

    def test_unverified_neighbor_never_scans_config(self):
        with mock.patch.object(kp,'_weixin_module',return_value=(1,2,Path('C:/Weixin/4.1.15.14/Weixin.dll'))), mock.patch.object(kp,'_process_memory_hits') as scan:
            self.assertEqual(list(kp._candidate_wcdb_config_keys(123,b'x'*4096,10**12)),[])
            scan.assert_not_called()
