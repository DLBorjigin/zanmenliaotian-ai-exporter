import hashlib
import hmac
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from wechat_ai_exporter.cli import main
from wechat_ai_exporter.key_probe import (
    MASTER_DLL_PATTERN, MASTER_DLL_VERIFY, ProbeError, ProbeResult,
    derive_database_key, derive_image_key, extract_xor_material,
    probe_database_key, _candidate_wcdb_config_keys, _exact_salt_keys_from_bytes,
    _landmark_offsets,
    _owner_pointer_address, _version_from_module_path, EXACT_SALT_ADAPTER,
    MasterKeyAdapter, wait_for_manual_weixin_exit,
)
from wechat_ai_exporter.key_validation import PAGE_SIZE, SALT_SIZE, WEIXIN4, verify_first_page


def encrypted_page_for_master(master: bytes) -> tuple[bytes, bytes]:
    salt = bytes(range(1, SALT_SIZE + 1))
    key = derive_database_key(master, salt)
    page = bytearray((index * 13 + 7) % 256 for index in range(PAGE_SIZE))
    page[:SALT_SIZE] = salt
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", bytes(key), mac_salt, 2, dklen=32)
    authenticated_end = PAGE_SIZE - WEIXIN4.reserve_size + 16
    digest = hmac.new(
        mac_key,
        bytes(page[SALT_SIZE:authenticated_end]) + (1).to_bytes(4, "little"),
        "sha512",
    ).digest()
    page[authenticated_end:authenticated_end + 64] = digest
    return bytes(page), bytes(key)


class KeyProbeTests(unittest.TestCase):
    def test_master_derives_key_for_exact_database_salt(self) -> None:
        master = bytes(range(32))
        page, expected = encrypted_page_for_master(master)
        derived = derive_database_key(master, page[:16])
        self.assertEqual(bytes(derived), expected)
        self.assertTrue(verify_first_page(derived, page, WEIXIN4))
        wrong_salt = bytes(reversed(page[:16]))
        self.assertFalse(verify_first_page(derive_database_key(master, wrong_salt), page, WEIXIN4))

    def test_dll_signature_extraction_fails_closed(self) -> None:
        chunks = []
        expected = bytearray()
        for index in range(4):
            immediate = bytes([0x31 + index]) * 8
            expected.extend(immediate)
            chunks.append(immediate)
            if index < 3:
                chunks.append(MASTER_DLL_VERIFY[index])
        image = b"prefix" + MASTER_DLL_PATTERN + b"".join(chunks) + b"suffix"
        self.assertEqual(extract_xor_material(image), bytes(expected))
        self.assertEqual(MASTER_DLL_VERIFY[0], bytes.fromhex("488944242048b8"))
        corrupted = image.replace(MASTER_DLL_VERIFY[1], b"\x90" * len(MASTER_DLL_VERIFY[1]))
        self.assertIsNone(extract_xor_material(corrupted))
        self.assertIsNone(extract_xor_material(b"unknown-version"))

    def test_cfg_pointer_back_is_relative_to_string_size_field(self) -> None:
        sso = b"global_config" + b"\x00" * 3 + (13).to_bytes(8, "little") + (15).to_bytes(8, "little")
        self.assertEqual(list(_landmark_offsets(sso)), [0])
        adapter = MasterKeyAdapter("synthetic", pointer_back=0x138)
        self.assertEqual(_owner_pointer_address(0x100000, 0x500, adapter), 0x100000 + 0x500 + 16 - 0x138)

    def test_image_key_derivation_is_deterministic(self) -> None:
        key, xor_key = derive_image_key(0x12345678, "wxid_test")
        self.assertEqual(len(key), 16)
        self.assertEqual(xor_key, 0x78)
        self.assertEqual((key, xor_key), derive_image_key(0x12345678, "wxid_test"))

    def test_exact_salt_config_parser_is_database_specific(self) -> None:
        salt = bytes(range(16))
        key = bytes(range(32))
        serialized = b'prefix x\'' + key.hex().encode() + salt.hex().encode() + b"' suffix"
        found = list(_exact_salt_keys_from_bytes(serialized, salt))
        self.assertEqual([bytes(item) for item in found], [key])
        self.assertEqual(list(_exact_salt_keys_from_bytes(serialized, bytes(reversed(salt)))), [])

        utf16 = ("x'" + key.hex() + salt.hex() + "'").encode("utf-16le")
        self.assertEqual(list(_exact_salt_keys_from_bytes(utf16, salt)), [])
        raw = b"prefix" + key + salt + b"suffix"
        self.assertEqual(list(_exact_salt_keys_from_bytes(raw, salt)), [])

    def test_exact_salt_adapter_is_gated_to_verified_build(self) -> None:
        self.assertEqual(
            _version_from_module_path(Path(r"C:\\Weixin\\4.1.13.12\\Weixin.dll")),
            (4, 1, 13, 12),
        )
        self.assertNotEqual(
            _version_from_module_path(Path(r"C:\\Weixin\\4.1.14.1\\Weixin.dll")),
            (4, 1, 13, 12),
        )
        with mock.patch(
            "wechat_ai_exporter.key_probe._weixin_module",
            return_value=(0x100000, 1024, Path(r"C:\\Weixin\\4.1.14.1\\Weixin.dll")),
        ), mock.patch("wechat_ai_exporter.key_probe._process_memory_hits") as scan:
            self.assertEqual(
                list(_candidate_wcdb_config_keys(123, b"x" * PAGE_SIZE, 10**12)), []
            )
            scan.assert_not_called()

    def test_probe_accepts_only_validated_wcdb_config_candidate(self) -> None:
        master = bytes(range(32))
        page, database_key = encrypted_page_for_master(master)
        captured = bytearray(database_key)
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "message.db"
            database.write_bytes(page)
            with mock.patch("wechat_ai_exporter.key_probe._process_ids", return_value=[123]), \
                    mock.patch("wechat_ai_exporter.key_probe._candidate_master_keys", return_value=iter(())), \
                    mock.patch(
                        "wechat_ai_exporter.key_probe._candidate_wcdb_config_keys",
                        return_value=iter((captured,)),
                    ):
                result = probe_database_key(database, authorized=True)
        self.assertEqual(result.adapter, EXACT_SALT_ADAPTER)
        self.assertEqual(bytes(result.key), database_key)

    def test_exact_salt_adapter_can_pair_separately_authorized_media_key(self) -> None:
        master = bytes(range(32))
        page, database_key = encrypted_page_for_master(master)
        captured = bytearray(database_key)
        media_key = bytearray(b"0123456789abcdef")
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "message.db"
            database.write_bytes(page)
            with mock.patch("wechat_ai_exporter.key_probe._process_ids", return_value=[123]), \
                    mock.patch("wechat_ai_exporter.key_probe._candidate_master_keys", return_value=iter(())), \
                    mock.patch(
                        "wechat_ai_exporter.key_probe._candidate_wcdb_config_keys",
                        return_value=iter((captured,)),
                    ), mock.patch(
                        "wechat_ai_exporter.key_probe._candidate_image_keys_from_global_config",
                        return_value=iter(((7, media_key, 7),)),
                    ):
                result = probe_database_key(
                    database, authorized=True, derive_media_key=True
                )
        self.assertEqual(result.adapter, EXACT_SALT_ADAPTER)
        self.assertEqual(bytes(result.key), database_key)
        self.assertIs(result.image_key, media_key)
        self.assertEqual(result.image_xor_key, 7)

    def test_exact_salt_adapter_can_find_media_config_in_another_weixin_process(self) -> None:
        master = bytes(range(32))
        page, database_key = encrypted_page_for_master(master)
        captured = bytearray(database_key)
        media_key = bytearray(b"fedcba9876543210")

        def database_candidates(pid, _page, _deadline):
            return iter((captured,)) if pid == 123 else iter(())

        def media_candidates(pid, _deadline):
            return iter(((9, media_key, 9),)) if pid == 456 else iter(())

        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "message.db"
            database.write_bytes(page)
            with mock.patch("wechat_ai_exporter.key_probe._process_ids", return_value=[123, 456]), \
                    mock.patch("wechat_ai_exporter.key_probe._candidate_master_keys", return_value=iter(())), \
                    mock.patch(
                        "wechat_ai_exporter.key_probe._candidate_wcdb_config_keys",
                        side_effect=database_candidates,
                    ), mock.patch(
                        "wechat_ai_exporter.key_probe._candidate_image_keys_from_global_config",
                        side_effect=media_candidates,
                    ):
                result = probe_database_key(
                    database, authorized=True, derive_media_key=True
                )
        self.assertEqual(bytes(result.key), database_key)
        self.assertIs(result.image_key, media_key)
        self.assertEqual(result.image_xor_key, 9)

    def test_probe_requires_authorization_before_process_access(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "message.db"
            database.write_bytes(b"x" * PAGE_SIZE)
            with mock.patch("wechat_ai_exporter.key_probe._process_ids") as process_ids:
                with self.assertRaises(ProbeError):
                    probe_database_key(database, authorized=False)
                process_ids.assert_not_called()

    def test_manual_exit_wait_only_polls_and_never_terminates(self) -> None:
        with mock.patch(
            "wechat_ai_exporter.key_probe._process_ids", side_effect=[[11, 22], [22], []]
        ) as process_ids, mock.patch("wechat_ai_exporter.key_probe.time.sleep") as sleeper:
            elapsed = wait_for_manual_weixin_exit(30, 0.1)
        self.assertGreaterEqual(elapsed, 0)
        self.assertEqual(process_ids.call_count, 3)
        self.assertEqual(sleeper.call_count, 2)

    def test_manual_close_flow_requires_separate_confirmation(self) -> None:
        with mock.patch("wechat_ai_exporter.cli.probe_database_key") as probe:
            code = main([
                "prepare-auto-key", "--database", "message.db",
                "--snapshot-dir", "snapshots", "--confirm-read-process-memory",
                "--wait-for-manual-exit",
            ])
        self.assertEqual(code, 4)
        probe.assert_not_called()

    def test_auto_cli_does_not_print_or_persist_key(self) -> None:
        master = bytes(range(32))
        page, db_key = encrypted_page_for_master(master)
        captured = bytearray(db_key)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / "message.db"
            database.write_bytes(page)
            fake = ProbeResult(captured, "synthetic-adapter", 123, 7)
            with mock.patch("wechat_ai_exporter.cli.probe_database_key", return_value=fake):
                with mock.patch("builtins.print") as output:
                    code = main([
                        "prepare-auto-key", "--database", str(database),
                        "--snapshot-dir", str(root / "snapshots"),
                        "--confirm-read-process-memory", "--json",
                    ])
            self.assertEqual(code, 0)
            rendered = " ".join(str(call) for call in output.call_args_list)
            self.assertNotIn(db_key.hex(), rendered)
            self.assertEqual(captured, bytearray(32))

    def test_auto_image_key_path_needs_separate_authorization(self) -> None:
        with mock.patch("wechat_ai_exporter.cli.probe_database_key") as probe:
            code = main([
                "export-plaintext", "--message-database", "plain.db",
                "--layout", "weixin-4", "--conversation-id", "conversation-x",
                "--output-dir", "out", "--include-assets", "--account-root", "account",
                "--confirm-authorized", "--confirm-selection", "--confirm-copy-attachments",
                "--auto-image-key-database", "encrypted.db",
            ])
        self.assertEqual(code, 4)
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
