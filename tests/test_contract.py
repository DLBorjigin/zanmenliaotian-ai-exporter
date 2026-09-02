import unittest
from pathlib import Path
import re
import tempfile
import hashlib
import hmac
import json
import io
import sqlite3
import struct
import zipfile
from contextlib import contextmanager, redirect_stdout
from unittest import mock

from wechat_ai_exporter.cli import _auto_plaintext_bundle, _doctor_payload, build_parser, main
from wechat_ai_exporter.discovery import _account_candidates, _bounded_scan, DiscoveryReport, report_to_dict
from wechat_ai_exporter.decrypt import DecryptionError, SQLITE_HEADER, decrypt_database
from wechat_ai_exporter.key_validation import (
    PAGE_SIZE, SALT_SIZE, WECHAT3, WEIXIN4, cipher_keys, page_hmac, parse_hex_key,
    verify_first_page, wipe_key,
)
from wechat_ai_exporter.models import AccessMode
from wechat_ai_exporter.security import AUTHORIZATION_MATRIX
from wechat_ai_exporter.snapshot import SnapshotError, create_verified_snapshot
from wechat_ai_exporter.schema_inspector import inspect_schema


def synthetic_encrypted_page(key: bytes, profile) -> bytes:
    page = bytearray((index * 17 + 11) % 256 for index in range(PAGE_SIZE))
    salt = bytes(range(1, SALT_SIZE + 1))
    page[:SALT_SIZE] = salt
    encryption_key = key
    if profile.derive_encryption_key:
        encryption_key = hashlib.pbkdf2_hmac(
            profile.kdf_hash, key, salt, profile.kdf_iterations, dklen=32
        )
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac(
        profile.hmac_hash, encryption_key, mac_salt, profile.hmac_iterations, dklen=32
    )
    authenticated_end = PAGE_SIZE - profile.reserve_size + 16
    digest = hmac.new(
        mac_key,
        bytes(page[SALT_SIZE:authenticated_end]) + (1).to_bytes(4, "little"),
        profile.hmac_hash,
    ).digest()
    page[authenticated_end:authenticated_end + profile.hmac_size] = digest
    return bytes(page)


def encrypt_test_page(plaintext: bytes, key: bytes, profile, page_number: int,
                      salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    aes_key, mac_key = cipher_keys(key, salt, profile)
    if len(plaintext) != PAGE_SIZE:
        raise ValueError("test page must be 4096 bytes")
    offset = SALT_SIZE if page_number == 1 else 0
    iv = bytes([page_number % 251 + 1]) * 16
    payload = plaintext[offset:PAGE_SIZE - profile.reserve_size]
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(payload) + encryptor.finalize()
    prefix = salt if page_number == 1 else b""
    authenticated = ciphertext + iv
    digest = page_hmac(mac_key, authenticated, page_number, profile)
    padding = bytes(profile.reserve_size - 16 - profile.hmac_size)
    return prefix + ciphertext + iv + digest + padding


def encrypt_test_pages(plaintext_pages: list[bytes], key: bytes, profile) -> bytes:
    salt = bytes(range(1, SALT_SIZE + 1))
    return b"".join(
        encrypt_test_page(plaintext, key, profile, page_number, salt)
        for page_number, plaintext in enumerate(plaintext_pages, start=1)
    )


class ContractTests(unittest.TestCase):
    def test_sensitive_modes_require_confirmation(self) -> None:
        for mode in (AccessMode.SUPPLIED_KEY, AccessMode.READ_ONLY_PROBE, AccessMode.NATIVE_HOOK):
            self.assertTrue(AUTHORIZATION_MATRIX[mode].requires_explicit_confirmation)

    def test_only_native_hook_mutates_process(self) -> None:
        mutating = [mode for mode, item in AUTHORIZATION_MATRIX.items() if item.mutates_wechat_process]
        self.assertEqual(mutating, [AccessMode.NATIVE_HOOK])

    def test_doctor_is_offline_and_content_free(self) -> None:
        payload = _doctor_payload()
        self.assertFalse(payload["network_required"])
        self.assertEqual(payload["status"], "runtime_ready")
        self.assertFalse(
            payload["authorization"][AccessMode.METADATA_ONLY.value]["reads_message_bodies"]
        )

    def test_skill_structure_and_ui_metadata(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        skill_root = project_root / "skill" / "wechat-chat-export"
        skill_text = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        frontmatter = re.match(r"^---\n(.*?)\n---", skill_text, re.DOTALL)
        self.assertIsNotNone(frontmatter)
        assert frontmatter is not None
        self.assertRegex(frontmatter.group(1), r"(?m)^name: wechat-chat-export$")
        self.assertRegex(frontmatter.group(1), r"(?m)^description: .+")
        self.assertNotIn("[TODO:", skill_text)

        ui_text = (skill_root / "agents" / "openai.yaml").read_text(encoding="utf-8")
        match = re.search(r'short_description: "([^"]+)"', ui_text)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertGreaterEqual(len(match.group(1)), 25)
        self.assertLessEqual(len(match.group(1)), 64)
        self.assertIn("$wechat-chat-export", ui_text)

    def test_discovery_redacts_account_directory_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "xwechat_files"
            account = root / "wxid_private_identifier_ab12"
            database = account / "db_storage" / "message" / "message_0.db"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"metadata-test")
            found = _account_candidates(root, "test")
            self.assertEqual(len(found), 1)
            payload = report_to_dict(DiscoveryReport((), tuple(found), {"enabled": False}))
            rendered = str(payload)
            self.assertNotIn("wxid_private_identifier", rendered)
            self.assertFalse(payload["privacy"]["absolute_paths_included"])
            self.assertEqual(payload["accounts"][0]["layout"], "weixin-4")

    def test_discovery_exact_plan_is_opt_in_and_classified(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "xwechat_files"
            account = root / "wxid_private"
            paths = [
                account / "db_storage" / "message" / "message_0.db",
                account / "db_storage" / "message" / "message_1.db",
                account / "db_storage" / "message" / "media_0.db",
                account / "db_storage" / "session" / "session.db",
                account / "db_storage" / "contact" / "contact.db",
            ]
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"metadata-test")
            found = _account_candidates(root, "test")
            hidden = report_to_dict(DiscoveryReport((), tuple(found), {"enabled": False}))
            self.assertNotIn("database_plan", hidden["accounts"][0])
            shown = report_to_dict(
                DiscoveryReport((), tuple(found), {"enabled": False}), show_paths=True
            )
            plan = shown["accounts"][0]["database_plan"]
            self.assertEqual(len(plan["message"]), 2)
            self.assertEqual(len(plan["voice_media"]), 1)
            self.assertEqual(len(plan["session"]), 1)
            self.assertEqual(len(plan["contact"]), 1)

    def test_auto_commands_accept_multiple_message_databases(self) -> None:
        args = build_parser().parse_args([
            "selection-preview-auto-key",
            "--message-database", "message_0.db",
            "--message-database", "message_1.db",
            "--session-database", "session.db",
            "--contact-database", "contact.db",
            "--snapshot-dir", "snapshots",
            "--work-dir", "work",
            "--conversation-id", "conversation-test",
        ])
        self.assertEqual(args.message_database, ["message_0.db", "message_1.db"])

    def test_video_asset_defaults_to_original_and_thumbnail_is_explicit(self) -> None:
        base = [
            "export-auto-key", "--message-database", "message.db",
            "--session-database", "session.db", "--contact-database", "contact.db",
            "--snapshot-dir", "snapshots", "--work-dir", "work",
            "--conversation-id", "conversation-test", "--output-dir", "out",
        ]
        self.assertEqual(build_parser().parse_args(base).video_asset, "original")
        self.assertEqual(
            build_parser().parse_args(base + ["--video-asset", "thumbnail"]).video_asset,
            "thumbnail",
        )

    def test_onboard_reports_one_safe_next_action_without_content_access(self) -> None:
        discovery_payload = {
            "installations": [{"running": True, "version": "4.1.12.55"}],
            "accounts": [],
            "privacy": {"absolute_paths_included": False},
            "scan": {"enabled": False},
        }
        stdout = io.StringIO()
        with mock.patch("wechat_ai_exporter.cli.discover"), mock.patch(
            "wechat_ai_exporter.cli.report_to_dict", return_value=discovery_payload
        ), mock.patch(
            "wechat_ai_exporter.cli._doctor_payload",
            return_value={"aes_backend_available": True, "status": "runtime_ready"},
        ), redirect_stdout(stdout):
            exit_code = main(["onboard", "--json"])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["status"], "needs_fixed_drive_scan")
        self.assertEqual(payload["message_bodies_read"], 0)
        self.assertFalse(payload["process_memory_read"])
        self.assertFalse(payload["network_used"])

    def test_onboard_ready_requires_exact_primary_database_roles(self) -> None:
        discovery_payload = {
            "installations": [{"running": True, "version": "4.1.12.55"}],
            "accounts": [{
                "id": "account-test", "freshness": "active",
                "database_role_counts": {
                    "message": 2, "session": 1, "contact": 1,
                    "voice_media": 0, "other": 3,
                },
            }],
            "privacy": {"absolute_paths_included": True},
            "scan": {"enabled": True},
        }
        stdout = io.StringIO()
        with mock.patch("wechat_ai_exporter.cli.discover"), mock.patch(
            "wechat_ai_exporter.cli.report_to_dict", return_value=discovery_payload
        ), mock.patch(
            "wechat_ai_exporter.cli._doctor_payload",
            return_value={"aes_backend_available": True, "status": "runtime_ready"},
        ), redirect_stdout(stdout):
            exit_code = main(["onboard", "--scan-fixed-drives", "--show-paths", "--json"])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["usable_account_ids"], ["account-test"])

    def test_bounded_scan_finds_custom_layout_and_install(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data_root = root / "custom" / "nested" / "xwechat_files"
            data_root.mkdir(parents=True)
            executable = root / "apps" / "Weixin" / "Weixin.exe"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"")
            exes, roots, status = _bounded_scan([root], max_depth=4, seconds=2.0)
            self.assertIn(executable, exes)
            self.assertIn(data_root, roots)
            self.assertFalse(status["timed_out"])

    def test_weixin4_and_wechat3_key_profiles(self) -> None:
        key = bytes(range(32))
        wrong = bytes(reversed(range(32)))
        for profile in (WEIXIN4, WECHAT3):
            page = synthetic_encrypted_page(key, profile)
            self.assertTrue(verify_first_page(key, page, profile))
            self.assertFalse(verify_first_page(wrong, page, profile))

    def test_key_parser_and_best_effort_wipe(self) -> None:
        key = parse_hex_key("hex:" + bytes(range(32)).hex())
        self.assertEqual(len(key), 32)
        wipe_key(key)
        self.assertEqual(key, bytearray(32))

    def test_verified_snapshot_contains_no_key(self) -> None:
        key = bytearray(range(32))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / "message_0.db"
            database.write_bytes(synthetic_encrypted_page(bytes(key), WEIXIN4))
            result = create_verified_snapshot(database, root / "snapshots", key, WEIXIN4)
            manifest_path = result.directory / "snapshot-manifest.json"
            manifest_text = manifest_path.read_text(encoding="utf-8")
            manifest = json.loads(manifest_text)
            self.assertTrue(result.database.is_file())
            self.assertFalse(manifest["contains_key"])
            self.assertNotIn(bytes(key).hex(), manifest_text)

    def test_wrong_key_publishes_no_snapshot(self) -> None:
        key = bytearray(range(32))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / "message_0.db"
            database.write_bytes(synthetic_encrypted_page(bytes(key), WEIXIN4))
            destination = root / "snapshots"
            with self.assertRaises(SnapshotError):
                create_verified_snapshot(database, destination, bytearray(32), WEIXIN4)
            self.assertEqual(list(destination.iterdir()), [])

    def test_stable_snapshot_flow_captures_residual_wal(self) -> None:
        key = bytearray(range(32))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / "message_0.db"
            database.write_bytes(synthetic_encrypted_page(bytes(key), WEIXIN4))
            Path(str(database) + "-wal").write_bytes(b"still-active")
            destination = root / "snapshots"
            result = create_verified_snapshot(
                database, destination, key, WEIXIN4,
                manual_process_exit_confirmed=True,
            )
            manifest = json.loads(
                (result.directory / "snapshot-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["wal_state"], "captured_stable")
            self.assertTrue(manifest["manual_process_exit_confirmed"])
            self.assertTrue((result.directory / "message_0.db-wal").is_file())
            self.assertTrue(all("sha256" in item for item in manifest["files"]))

    def test_cli_known_key_is_not_printed_and_buffer_is_wiped(self) -> None:
        supplied = bytearray(range(32))
        secret_hex = bytes(supplied).hex()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / "message_0.db"
            database.write_bytes(synthetic_encrypted_page(bytes(supplied), WEIXIN4))
            output = io.StringIO()
            with mock.patch("wechat_ai_exporter.cli.prompt_key", return_value=supplied):
                with redirect_stdout(output):
                    exit_code = main([
                        "prepare-known-key", "--database", str(database),
                        "--layout", "weixin-4", "--snapshot-dir", str(root / "snapshots"),
                        "--confirm-authorized", "--json",
                    ])
            self.assertEqual(exit_code, 0)
            self.assertNotIn(secret_hex, output.getvalue())
            self.assertEqual(supplied, bytearray(32))

    def test_page_decryption_and_integrity_failure_cleanup(self) -> None:
        key = bytes(range(32))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for profile in (WEIXIN4, WECHAT3):
                first = bytearray((index * 5 + 3) % 256 for index in range(PAGE_SIZE))
                first[:16] = SQLITE_HEADER
                second = bytes((index * 7 + 1) % 256 for index in range(PAGE_SIZE))
                encrypted = encrypt_test_pages([bytes(first), second], key, profile)
                source = root / f"encrypted-{profile.name}.db"
                output = root / f"plain-{profile.name}.sqlite"
                source.write_bytes(encrypted)
                decrypt_database(source, output, key, profile)
                decrypted = output.read_bytes()
                usable = PAGE_SIZE - profile.reserve_size
                self.assertEqual(decrypted[:usable], bytes(first)[:usable])
                self.assertEqual(decrypted[PAGE_SIZE:PAGE_SIZE + usable], second[:usable])

            corrupted = bytearray(encrypt_test_pages([bytes(first), second], key, WEIXIN4))
            corrupted[100] ^= 0xFF
            bad_source = root / "corrupt.db"
            bad_output = root / "must-not-exist.sqlite"
            bad_source.write_bytes(corrupted)
            with self.assertRaises(DecryptionError):
                decrypt_database(bad_source, bad_output, key, WEIXIN4)
            self.assertFalse(bad_output.exists())

    def test_committed_wal_is_merged_and_uncommitted_tail_is_ignored(self) -> None:
        key = bytes(range(32))
        salt = bytes(range(1, SALT_SIZE + 1))
        first = bytearray(PAGE_SIZE)
        first[:16] = SQLITE_HEADER
        first[16:18] = b"\x10\x00"
        first[20] = WEIXIN4.reserve_size
        first[28:32] = (2).to_bytes(4, "big")
        original = bytes([0x11]) * PAGE_SIZE
        committed = bytes([0x22]) * PAGE_SIZE
        uncommitted = bytes([0x33]) * PAGE_SIZE
        wal_salt = b"WALSALT1"
        wal_header = (
            struct.pack(">IIII", 0x377F0682, 3007000, PAGE_SIZE, 0)
            + wal_salt + bytes(8)
        )
        committed_header = struct.pack(">II", 2, 2) + wal_salt + bytes(8)
        tail_header = struct.pack(">II", 2, 0) + wal_salt + bytes(8)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "message_0.db"
            output = root / "merged.sqlite"
            source.write_bytes(encrypt_test_pages([bytes(first), original], key, WEIXIN4))
            Path(str(source) + "-wal").write_bytes(
                wal_header
                + committed_header + encrypt_test_page(committed, key, WEIXIN4, 2, salt)
                + tail_header + encrypt_test_page(uncommitted, key, WEIXIN4, 2, salt)
            )
            decrypt_database(source, output, key, WEIXIN4)
            merged = output.read_bytes()
            usable = PAGE_SIZE - WEIXIN4.reserve_size
            self.assertEqual(merged[PAGE_SIZE:PAGE_SIZE + usable], committed[:usable])
            self.assertNotEqual(merged[PAGE_SIZE:PAGE_SIZE + usable], uncommitted[:usable])

    def test_committed_wal_integrity_failure_leaves_no_plaintext(self) -> None:
        key = bytes(range(32))
        first = bytearray(PAGE_SIZE)
        first[:16] = SQLITE_HEADER
        first[28:32] = (1).to_bytes(4, "big")
        wal_salt = b"WALSALT2"
        wal_header = (
            struct.pack(">IIII", 0x377F0682, 3007000, PAGE_SIZE, 0)
            + wal_salt + bytes(8)
        )
        frame_header = struct.pack(">II", 1, 1) + wal_salt + bytes(8)
        damaged = bytearray(encrypt_test_page(bytes(first), key, WEIXIN4, 1, bytes(range(1, 17))))
        damaged[100] ^= 0xFF
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "message_0.db"
            output = root / "must-not-exist.sqlite"
            source.write_bytes(encrypt_test_pages([bytes(first)], key, WEIXIN4))
            Path(str(source) + "-wal").write_bytes(wal_header + frame_header + damaged)
            with self.assertRaises(DecryptionError):
                decrypt_database(source, output, key, WEIXIN4)
            self.assertFalse(output.exists())

    def test_schema_report_reads_no_message_rows_and_redacts_table_name(self) -> None:
        sensitive_text = "PRIVATE-MESSAGE-MUST-NOT-APPEAR"
        shard_name = "Msg_0123456789abcdef0123456789abcdef"
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "plain.sqlite"
            connection = sqlite3.connect(database)
            connection.execute(
                f'CREATE TABLE "{shard_name}" ('
                "local_id INTEGER, local_type INTEGER, create_time INTEGER, "
                "message_content TEXT)"
            )
            connection.execute("CREATE TABLE Name2Id (rowid INTEGER PRIMARY KEY, user_name TEXT)")
            connection.execute(
                f'INSERT INTO "{shard_name}" VALUES (1, 1, 1, ?)', (sensitive_text,)
            )
            connection.commit()
            connection.close()
            report = inspect_schema(database)
            rendered = json.dumps(report, ensure_ascii=False)
            self.assertEqual(report["status"], "compatible")
            self.assertEqual(report["detected_layout"], "weixin-4")
            self.assertEqual(report["message_rows_read"], 0)
            self.assertNotIn(sensitive_text, rendered)
            self.assertNotIn(shard_name, rendered)

    def test_cli_inspection_deletes_plaintext_by_default(self) -> None:
        supplied = bytearray(range(32))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            encrypted = root / "snapshot.db"
            encrypted.write_bytes(b"placeholder")

            def fake_decrypt(_source, output, _key, _profile):
                connection = sqlite3.connect(output)
                connection.execute(
                    "CREATE TABLE MSG (StrTalker TEXT, StrContent TEXT, CreateTime INTEGER)"
                )
                connection.commit()
                connection.close()
                return output

            stdout = io.StringIO()
            with mock.patch("wechat_ai_exporter.cli.prompt_key", return_value=supplied), \
                 mock.patch("wechat_ai_exporter.cli.decrypt_database", side_effect=fake_decrypt):
                with redirect_stdout(stdout):
                    exit_code = main([
                        "inspect-known-key", "--snapshot-database", str(encrypted),
                        "--layout", "wechat-3", "--work-dir", str(root / "work"),
                        "--confirm-authorized", "--json",
                    ])
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertFalse(payload["decrypted_database_retained"])
            self.assertFalse(any((root / "work").glob("decrypted-*.sqlite")))
            self.assertTrue(Path(payload["report"]).is_file())
            self.assertEqual(supplied, bytearray(32))

    def test_cli_reports_processed_encrypted_wal(self) -> None:
        supplied = bytearray(range(32))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            encrypted = root / "snapshot.db"
            encrypted.write_bytes(b"placeholder")
            Path(str(encrypted) + "-wal").write_bytes(b"unmerged")

            def fake_decrypt(_source, output, _key, _profile):
                connection = sqlite3.connect(output)
                connection.execute(
                    "CREATE TABLE MSG (StrTalker TEXT, StrContent TEXT, CreateTime INTEGER)"
                )
                connection.commit()
                connection.close()
                return output

            stdout = io.StringIO()
            with mock.patch("wechat_ai_exporter.cli.prompt_key", return_value=supplied), \
                 mock.patch("wechat_ai_exporter.cli.decrypt_database", side_effect=fake_decrypt):
                with redirect_stdout(stdout):
                    exit_code = main([
                        "inspect-known-key", "--snapshot-database", str(encrypted),
                        "--layout", "wechat-3", "--work-dir", str(root / "work"),
                        "--confirm-authorized", "--json",
                    ])
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["status"], "compatible")
            self.assertTrue(payload["encrypted_wal_processed"])
            self.assertTrue(payload["safe_for_message_export"])

    def test_auto_schema_inspection_requires_both_confirmations(self) -> None:
        with mock.patch("wechat_ai_exporter.cli.probe_database_key") as probe:
            exit_code = main([
                "inspect-auto-key", "--snapshot-database", "snapshot.db",
                "--key-database", "live.db", "--work-dir", "work",
                "--confirm-read-process-memory",
            ])
        self.assertEqual(exit_code, 4)
        probe.assert_not_called()

    def test_auto_schema_inspection_wipes_key_and_plaintext(self) -> None:
        supplied = bytearray(range(32))
        fake_probe = mock.Mock(key=supplied, adapter="synthetic-adapter")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            snapshot = root / "snapshot.db"
            snapshot.write_bytes(b"placeholder")

            def fake_decrypt(_source, output, _key, _profile):
                connection = sqlite3.connect(output)
                connection.execute(
                    "CREATE TABLE MSG (StrTalker TEXT, StrContent TEXT, CreateTime INTEGER)"
                )
                connection.commit()
                connection.close()
                return output

            stdout = io.StringIO()
            with mock.patch(
                "wechat_ai_exporter.cli.probe_database_key", return_value=fake_probe
            ), mock.patch(
                "wechat_ai_exporter.cli.decrypt_database", side_effect=fake_decrypt
            ), redirect_stdout(stdout):
                exit_code = main([
                    "inspect-auto-key", "--snapshot-database", str(snapshot),
                    "--key-database", str(root / "live.db"),
                    "--work-dir", str(root / "work"),
                    "--confirm-read-process-memory", "--confirm-schema-inspection", "--json",
                ])
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["message_rows_read"], 0)
            self.assertFalse(payload["decrypted_database_retained"])
            self.assertFalse(any((root / "work").glob("decrypted-*.sqlite")))
            self.assertEqual(supplied, bytearray(32))

    def test_combined_snapshot_inspection_requires_both_confirmations(self) -> None:
        with mock.patch("wechat_ai_exporter.cli.probe_database_key") as probe:
            exit_code = main([
                "snapshot-inspect-auto-key", "--database", "session.db",
                "--snapshot-dir", "snapshots", "--work-dir", "work",
                "--confirm-schema-inspection",
            ])
        self.assertEqual(exit_code, 4)
        probe.assert_not_called()

    def test_combined_snapshot_inspection_scans_once_and_cleans_secrets(self) -> None:
        supplied = bytearray(range(32))
        fake_probe = mock.Mock(key=supplied, adapter="synthetic-adapter")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "session.db"
            source.write_bytes(b"placeholder")
            snapshot_dir = root / "published-snapshot"
            snapshot_dir.mkdir()
            snapshot_database = snapshot_dir / "session.db"
            snapshot_database.write_bytes(b"encrypted-placeholder")
            fake_snapshot = mock.Mock(
                directory=snapshot_dir,
                database=snapshot_database,
                copied_files=(snapshot_database,),
            )

            def fake_decrypt(_source, output, _key, _profile):
                connection = sqlite3.connect(output)
                connection.execute("CREATE TABLE SessionTable (username TEXT)")
                connection.commit()
                connection.close()
                return output

            stdout = io.StringIO()
            with mock.patch(
                "wechat_ai_exporter.cli.probe_database_key", return_value=fake_probe
            ) as probe, mock.patch(
                "wechat_ai_exporter.cli.create_verified_snapshot", return_value=fake_snapshot
            ), mock.patch(
                "wechat_ai_exporter.cli.decrypt_database", side_effect=fake_decrypt
            ), redirect_stdout(stdout):
                exit_code = main([
                    "snapshot-inspect-auto-key", "--database", str(source),
                    "--snapshot-dir", str(root / "snapshots"),
                    "--work-dir", str(root / "work"),
                    "--confirm-read-process-memory", "--confirm-schema-inspection", "--json",
                ])
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(probe.call_count, 1)
            self.assertEqual(payload["process_memory_scan_count"], 1)
            self.assertEqual(payload["message_rows_read"], 0)
            self.assertFalse(any((root / "work").glob("decrypted-*.sqlite")))
            self.assertEqual(supplied, bytearray(32))

    def test_catalog_preview_requires_all_three_confirmations(self) -> None:
        with mock.patch("wechat_ai_exporter.cli.probe_database_key") as probe:
            exit_code = main([
                "catalog-preview-auto-key", "--message-database", "message.db",
                "--session-database", "session.db", "--contact-database", "contact.db",
                "--snapshot-dir", "snapshots", "--work-dir", "work",
                "--confirm-read-process-memory", "--confirm-private-metadata",
            ])
        self.assertEqual(exit_code, 4)
        probe.assert_not_called()

    def test_catalog_preview_scans_three_times_without_bodies_or_plaintext(self) -> None:
        keys = [bytearray([value]) * 32 for value in (1, 2, 3)]
        probes = [
            mock.Mock(
                key=key, adapter="synthetic-adapter",
                image_key=None, image_xor_key=None,
            )
            for key in keys
        ]
        hidden_message = "PRIVATE-MESSAGE-MUST-NOT-APPEAR"
        hidden_summary = "PRIVATE-SUMMARY-MUST-NOT-APPEAR"
        selector = "wxid_friend"
        shard = "Msg_" + hashlib.md5(selector.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sources = {
                "message": root / "message.db",
                "session": root / "session.db",
                "contact": root / "contact.db",
            }
            for path in sources.values():
                path.write_bytes(b"encrypted-placeholder")

            def fake_snapshot(database, destination_parent, **_kwargs):
                role = database.stem
                directory = Path(destination_parent) / f"snapshot-{role}"
                directory.mkdir(parents=True, exist_ok=True)
                copied = directory / database.name
                copied.write_bytes(b"encrypted-copy")
                return mock.Mock(directory=directory, database=copied, copied_files=(copied,))

            def fake_decrypt(_source, output, _key, _profile):
                connection = sqlite3.connect(output)
                name = output.name
                if "message" in name:
                    connection.execute(
                        f'CREATE TABLE "{shard}" ('
                        "local_type INTEGER, create_time INTEGER, message_content TEXT)"
                    )
                    connection.executemany(
                        f'INSERT INTO "{shard}" VALUES (?, ?, ?)',
                        [(1, 100, hidden_message), (3, 200, hidden_message),
                         (47, 300, hidden_message), (49, 400, hidden_message)],
                    )
                elif "session" in name:
                    connection.execute(
                        "CREATE TABLE SessionTable (username TEXT, last_timestamp INTEGER, summary TEXT)"
                    )
                    connection.execute(
                        "INSERT INTO SessionTable VALUES (?, ?, ?)",
                        (selector, 400, hidden_summary),
                    )
                else:
                    connection.execute(
                        "CREATE TABLE contact (username TEXT, remark TEXT, nick_name TEXT, alias TEXT)"
                    )
                    connection.execute(
                        "INSERT INTO contact VALUES (?, ?, ?, ?)",
                        (selector, "Project Partner", "Nick", "alias"),
                    )
                connection.commit()
                connection.close()
                return output

            stdout = io.StringIO()
            with mock.patch(
                "wechat_ai_exporter.cli.probe_database_key", side_effect=probes
            ) as probe, mock.patch(
                "wechat_ai_exporter.cli.create_verified_snapshot", side_effect=fake_snapshot
            ), mock.patch(
                "wechat_ai_exporter.cli.decrypt_database", side_effect=fake_decrypt
            ), redirect_stdout(stdout):
                exit_code = main([
                    "catalog-preview-auto-key",
                    "--message-database", str(sources["message"]),
                    "--session-database", str(sources["session"]),
                    "--contact-database", str(sources["contact"]),
                    "--snapshot-dir", str(root / "snapshots"),
                    "--work-dir", str(root / "work"),
                    "--confirm-read-process-memory", "--confirm-private-metadata",
                    "--confirm-count-query", "--json",
                ])
            rendered = stdout.getvalue()
            payload = json.loads(rendered)
            self.assertEqual(exit_code, 0)
            self.assertEqual(probe.call_count, 3)
            self.assertEqual(payload["process_memory_scan_count"], 3)
            self.assertEqual(payload["message_bodies_read"], 0)
            self.assertEqual(payload["summaries_or_drafts_read"], 0)
            self.assertEqual(payload["conversations"][0]["display_name"], "Project Partner")
            self.assertEqual(
                payload["conversations"][0]["counts_by_kind"],
                {"image": 1, "link": 1, "text": 1},
            )
            self.assertNotIn(hidden_message, rendered)
            self.assertNotIn(hidden_summary, rendered)
            self.assertFalse(any((root / "work").glob("decrypted-*.sqlite")))
            self.assertTrue(all(key == bytearray(32) for key in keys))

    def test_auto_export_requires_body_and_attachment_confirmations_before_scan(self) -> None:
        base = [
            "export-auto-key", "--message-database", "message.db",
            "--session-database", "session.db", "--contact-database", "contact.db",
            "--snapshot-dir", "snapshots", "--work-dir", "work",
            "--conversation-id", "conversation-test", "--output-dir", "out",
            "--confirm-read-process-memory", "--confirm-private-metadata",
            "--confirm-selection",
        ]
        with mock.patch("wechat_ai_exporter.cli.probe_database_key") as probe:
            self.assertEqual(main(base), 4)
            self.assertEqual(main(base + ["--confirm-read-message-bodies", "--include-assets"]), 4)
        probe.assert_not_called()

    def test_auto_export_scans_once_per_database_and_cleans_plaintext(self) -> None:
        keys = [bytearray([value]) * 32 for value in (4, 5, 6)]
        probes = [
            mock.Mock(
                key=key, adapter="synthetic-adapter",
                image_key=None, image_xor_key=None,
            )
            for key in keys
        ]
        selector = "wxid_export_friend"
        conversation_id = "conversation-" + hashlib.sha256(selector.encode()).hexdigest()[:12]
        shard = "Msg_" + hashlib.md5(selector.encode()).hexdigest()
        private_body = "# private test body\nhello"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sources = {
                "message": root / "message.db",
                "session": root / "session.db",
                "contact": root / "contact.db",
            }
            for path in sources.values():
                path.write_bytes(b"encrypted-placeholder")

            def fake_snapshot(database, destination_parent, **_kwargs):
                directory = Path(destination_parent) / f"snapshot-{database.stem}"
                directory.mkdir(parents=True, exist_ok=True)
                copied = directory / database.name
                copied.write_bytes(b"encrypted-copy")
                return mock.Mock(directory=directory, database=copied, copied_files=(copied,))

            def fake_decrypt(_source, output, _key, _profile):
                connection = sqlite3.connect(output)
                if "message" in output.name:
                    connection.execute(
                        f'CREATE TABLE "{shard}" ('
                        "local_id INTEGER, server_id INTEGER, local_type INTEGER, "
                        "sort_seq INTEGER, real_sender_id INTEGER, create_time INTEGER, "
                        "status INTEGER, message_content TEXT)"
                    )
                    connection.executemany(
                        f'INSERT INTO "{shard}" VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        [(1, 11, 1, 1, 0, 100, 4, private_body),
                         (2, 12, 47, 2, 0, 200, 4, "excluded-emoticon")],
                    )
                elif "session" in output.name:
                    connection.execute(
                        "CREATE TABLE SessionTable (username TEXT, last_timestamp INTEGER)"
                    )
                    connection.execute("INSERT INTO SessionTable VALUES (?, ?)", (selector, 200))
                else:
                    connection.execute(
                        "CREATE TABLE contact (username TEXT, remark TEXT, nick_name TEXT, alias TEXT)"
                    )
                    connection.execute(
                        "INSERT INTO contact VALUES (?, ?, ?, ?)",
                        (selector, "Export Partner", "Nick", "alias"),
                    )
                connection.commit()
                connection.close()
                return output

            stdout = io.StringIO()
            with mock.patch(
                "wechat_ai_exporter.cli.probe_database_key", side_effect=probes
            ) as probe, mock.patch(
                "wechat_ai_exporter.cli.create_verified_snapshot", side_effect=fake_snapshot
            ), mock.patch(
                "wechat_ai_exporter.cli.decrypt_database", side_effect=fake_decrypt
            ), redirect_stdout(stdout):
                exit_code = main([
                    "export-auto-key",
                    "--message-database", str(sources["message"]),
                    "--session-database", str(sources["session"]),
                    "--contact-database", str(sources["contact"]),
                    "--snapshot-dir", str(root / "snapshots"),
                    "--work-dir", str(root / "work"),
                    "--conversation-id", conversation_id,
                    "--include", "text", "--output-dir", str(root / "exports"),
                    "--confirm-read-process-memory", "--confirm-private-metadata",
                    "--confirm-selection", "--confirm-read-message-bodies", "--json",
                ])
            payload = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(probe.call_count, 3)
            self.assertEqual(payload["message_count"], 1)
            self.assertNotIn(private_body, stdout.getvalue())
            archive = Path(payload["archive"])
            with zipfile.ZipFile(archive) as bundle:
                transcript = bundle.read("transcript.md").decode("utf-8")
                manifest = json.loads(bundle.read("manifest.json"))
            self.assertIn("> # private test body", transcript)
            self.assertEqual(manifest["message_count"], 1)
            self.assertFalse(any((root / "work").glob("decrypted-*.sqlite")))
            self.assertTrue(all(key == bytearray(32) for key in keys))

    def test_auto_bundle_failure_wipes_used_keys_and_prior_plaintext(self) -> None:
        keys = [bytearray([7]) * 32, bytearray([8]) * 32]
        probes = [
            mock.Mock(key=key, image_key=None, image_xor_key=None)
            for key in keys
        ]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sources = {
                "message": root / "message.db",
                "session": root / "session.db",
            }
            for path in sources.values():
                path.write_bytes(b"encrypted")

            def fake_snapshot(database, destination_parent, **_kwargs):
                directory = Path(destination_parent) / database.stem
                directory.mkdir(parents=True, exist_ok=True)
                copied = directory / database.name
                copied.write_bytes(b"copy")
                return mock.Mock(directory=directory, database=copied, copied_files=(copied,))

            def fake_decrypt(_source, output, _key, _profile):
                if "session" in output.name:
                    raise DecryptionError("synthetic decrypt failure")
                output.write_bytes(b"temporary plaintext")
                return output

            with mock.patch(
                "wechat_ai_exporter.cli.probe_database_key", side_effect=probes
            ), mock.patch(
                "wechat_ai_exporter.cli.create_verified_snapshot", side_effect=fake_snapshot
            ), mock.patch(
                "wechat_ai_exporter.cli.decrypt_database", side_effect=fake_decrypt
            ):
                with self.assertRaises(DecryptionError):
                    with _auto_plaintext_bundle(
                        sources, root / "snapshots", root / "work", 20
                    ):
                        pass
            self.assertFalse(any((root / "work").glob("decrypted-*.sqlite")))
            self.assertTrue(all(key == bytearray(32) for key in keys))

    def test_auto_selection_preview_requires_count_confirmation_before_scan(self) -> None:
        with mock.patch("wechat_ai_exporter.cli.probe_database_key") as probe:
            exit_code = main([
                "selection-preview-auto-key",
                "--message-database", "message.db", "--session-database", "session.db",
                "--contact-database", "contact.db", "--snapshot-dir", "snapshots",
                "--work-dir", "work", "--conversation-id", "conversation-test",
                "--confirm-read-process-memory", "--confirm-private-metadata",
            ])
        self.assertEqual(exit_code, 4)
        probe.assert_not_called()

    def test_auto_selection_preview_filters_types_without_reading_bodies(self) -> None:
        selector = "wxid_preview_friend"
        conversation_id = "conversation-" + hashlib.sha256(selector.encode()).hexdigest()[:12]
        shard = "Msg_" + hashlib.md5(selector.encode()).hexdigest()
        private_body = "PREVIEW-MUST-NOT-READ-THIS-BODY"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            message_db = root / "message.sqlite"
            session_db = root / "session.sqlite"
            contact_db = root / "contact.sqlite"
            connection = sqlite3.connect(message_db)
            connection.execute(
                f'CREATE TABLE "{shard}" (local_type INTEGER, create_time INTEGER, message_content TEXT)'
            )
            connection.executemany(
                f'INSERT INTO "{shard}" VALUES (?, ?, ?)',
                [(1, 100, private_body), (3, 200, private_body)],
            )
            connection.commit()
            connection.close()
            connection = sqlite3.connect(session_db)
            connection.execute("CREATE TABLE SessionTable (username TEXT, last_timestamp INTEGER)")
            connection.execute("INSERT INTO SessionTable VALUES (?, ?)", (selector, 200))
            connection.commit()
            connection.close()
            connection = sqlite3.connect(contact_db)
            connection.execute(
                "CREATE TABLE contact (username TEXT, remark TEXT, nick_name TEXT, alias TEXT)"
            )
            connection.execute(
                "INSERT INTO contact VALUES (?, ?, ?, ?)",
                (selector, "Preview Partner", "Nick", "alias"),
            )
            connection.commit()
            connection.close()

            @contextmanager
            def fake_bundle(*_args, **_kwargs):
                snapshots = {
                    role: mock.Mock(directory=root / f"snapshot-{role}")
                    for role in ("message", "session", "contact")
                }
                yield {
                    "message": message_db, "session": session_db, "contact": contact_db,
                }, snapshots, bytearray(), None

            stdout = io.StringIO()
            with mock.patch(
                "wechat_ai_exporter.cli._auto_plaintext_bundle", side_effect=fake_bundle
            ), redirect_stdout(stdout):
                exit_code = main([
                    "selection-preview-auto-key",
                    "--message-database", "encrypted-message.db",
                    "--session-database", "encrypted-session.db",
                    "--contact-database", "encrypted-contact.db",
                    "--snapshot-dir", str(root / "snapshots"),
                    "--work-dir", str(root / "work"),
                    "--conversation-id", conversation_id, "--include", "text",
                    "--confirm-read-process-memory", "--confirm-private-metadata",
                    "--confirm-count-query", "--json",
                ])
            rendered = stdout.getvalue()
            payload = json.loads(rendered)
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["selected_count"], 1)
            self.assertEqual(payload["counts_by_kind"], {"image": 1, "text": 1})
            self.assertEqual(payload["message_bodies_read"], 0)
            self.assertNotIn(private_body, rendered)


if __name__ == "__main__":
    unittest.main()
