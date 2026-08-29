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
    probe_database_key, _landmark_offsets, _owner_pointer_address,
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
