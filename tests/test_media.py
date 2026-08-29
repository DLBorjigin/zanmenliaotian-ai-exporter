from pathlib import Path
import sqlite3
import tempfile
import unittest
import json
import zipfile

from wechat_ai_exporter.exporter import export_chat
from wechat_ai_exporter.media import MediaResolver, V2_MAGIC, decode_legacy_xor
from wechat_ai_exporter.models import Conversation, ExportScope, MessageKind, NormalizedMessage


def message(kind: MessageKind, content: str = "", packed_info=None,
            local_id: int = 10, server_id: int = 20) -> NormalizedMessage:
    return NormalizedMessage(
        id=f"message-{kind.value}", conversation_id="conversation-test",
        timestamp=1_700_000_000, sender_name="Alice", is_self=False,
        kind=kind, type_code=1, subtype_code=None, content=content,
        sequence=1,
        metadata={
            "local_id": local_id, "server_id": server_id,
            "table": "Msg_test", "packed_info": packed_info,
        },
    )


class MediaTests(unittest.TestCase):
    def test_legacy_xor_image_is_decoded_and_packaged(self) -> None:
        plaintext = b"\xff\xd8\xff\xe0" + b"test-jpeg" + b"\xff\xd9"
        key = 0x5A
        encrypted = bytes(value ^ key for value in plaintext)
        token = "0123456789abcdef0123456789abcdef"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "msg" / "attach" / "chat" / "2026-08" / "Img" / f"{token}.dat"
            source.parent.mkdir(parents=True)
            source.write_bytes(encrypted)
            resolver = MediaResolver(root)
            assets = resolver.resolve(message(MessageKind.IMAGE, f"<img md5='{token}'/>"), root / "out" / "assets")
            self.assertEqual(assets[0].status, "packaged")
            output = root / "out" / assets[0].relative_path
            self.assertEqual(output.read_bytes(), plaintext)
            self.assertTrue(output.name.endswith(".jpg"))

    def test_v2_image_requires_separate_image_key(self) -> None:
        token = "abcdefabcdefabcdefabcdefabcdefab"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "msg" / "attach" / "x" / "Img" / f"{token}.dat"
            source.parent.mkdir(parents=True)
            source.write_bytes(V2_MAGIC + bytes(64))
            result = MediaResolver(root).resolve(
                message(MessageKind.IMAGE, token), root / "out" / "assets"
            )[0]
            self.assertEqual(result.status, "image_v2_key_required")
            self.assertIsNone(result.relative_path)

    def test_v2_image_with_supplied_key_is_decrypted_and_packaged(self) -> None:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        token = "fedcbafedcbafedcbafedcbafedcbafe"
        key = bytearray(b"0123456789abcdef")
        xor_key = 0x5C
        first = b"\xff\xd8\xffsynthetic"
        raw = b"-raw-"
        tail = b"tail\xff\xd9"
        pad = 16 - len(first) % 16
        padded = first + bytes([pad]) * pad
        encryptor = Cipher(algorithms.AES(bytes(key)), modes.ECB()).encryptor()
        encrypted_first = encryptor.update(padded) + encryptor.finalize()
        encrypted_tail = bytes(value ^ xor_key for value in tail)
        data = (
            V2_MAGIC + len(first).to_bytes(4, "little")
            + len(tail).to_bytes(4, "little") + b"\x00"
            + encrypted_first + raw + encrypted_tail
        )
        plaintext = first + raw + tail
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "msg" / "attach" / "x" / "Img" / f"{token}.dat"
            source.parent.mkdir(parents=True)
            source.write_bytes(data)
            source.with_name(source.stem + "_t.dat").write_bytes(
                b"thumbnail" + bytes([0xFF ^ xor_key, 0xD9 ^ xor_key])
            )
            result = MediaResolver(root, image_aes_key=key).resolve(
                message(MessageKind.IMAGE, token), root / "out" / "assets"
            )[0]
            self.assertEqual(result.status, "packaged")
            self.assertEqual((root / "out" / result.relative_path).read_bytes(), plaintext)

    def test_v2_wrong_key_fails_without_writing_asset(self) -> None:
        token = "99999999999999999999999999999999"
        data = V2_MAGIC + (1).to_bytes(4, "little") + (0).to_bytes(4, "little") + b"\x00" + bytes(32)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "msg" / "attach" / "x" / "Img" / f"{token}.dat"
            source.parent.mkdir(parents=True)
            source.write_bytes(data)
            result = MediaResolver(root, image_aes_key=bytearray(b"badbadbadbadbad1")).resolve(
                message(MessageKind.IMAGE, token), root / "out" / "assets"
            )[0]
            self.assertEqual(result.status, "image_v2_key_invalid_or_xor_unavailable")
            self.assertIsNone(result.relative_path)

    def test_file_is_matched_by_exact_xml_title(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "msg" / "file" / "2026-08" / "project plan.pdf"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"PDF-test")
            result = MediaResolver(root).resolve(
                message(
                    MessageKind.FILE,
                    "<msg><appmsg><type>6</type><title>project plan.pdf</title></appmsg></msg>",
                ),
                root / "out" / "assets",
            )[0]
            self.assertEqual(result.status, "packaged")
            self.assertEqual((root / "out" / result.relative_path).read_bytes(), b"PDF-test")

    def test_voice_blob_is_normalized_to_silk(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / "media_0.db"
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE VoiceInfo (local_id INTEGER, svr_id INTEGER, voice_data BLOB)"
            )
            connection.execute(
                "INSERT INTO VoiceInfo VALUES (10, 20, ?)",
                (b"\x02#!SILK_V3synthetic-audio",),
            )
            connection.commit()
            connection.close()
            result = MediaResolver(media_databases=[database]).resolve(
                message(MessageKind.AUDIO), root / "out" / "assets"
            )[0]
            self.assertEqual(result.status, "packaged_requires_conversion")
            self.assertEqual(result.media_type, "audio/silk")
            self.assertEqual(
                (root / "out" / result.relative_path).read_bytes(),
                b"#!SILK_V3synthetic-audio",
            )

    def test_ambiguous_file_match_is_not_copied(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for folder in ("a", "b"):
                path = root / "msg" / "file" / folder / "duplicate.bin"
                path.parent.mkdir(parents=True)
                path.write_bytes(folder.encode())
            result = MediaResolver(root).resolve(
                message(MessageKind.FILE, "<title>duplicate.bin</title>"),
                root / "out" / "assets",
            )[0]
            self.assertEqual(result.status, "ambiguous_match")
            self.assertIsNone(result.relative_path)

    def test_business_emoticon_tree_is_indexed_only_when_explicitly_included(self) -> None:
        token = "abababababababababababababababab"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "business" / "emoticon" / "Persist" / "ab" / f"{token}.gif"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"GIF89a" + b"synthetic-emoticon")
            normalized = message(MessageKind.EMOTICON, token)
            excluded = MediaResolver(root).resolve(
                normalized, root / "excluded" / "assets"
            )[0]
            included = MediaResolver(root, include_emoticons=True).resolve(
                normalized, root / "included" / "assets"
            )[0]
            self.assertEqual(excluded.status, "not_found")
            self.assertEqual(included.status, "packaged")
            self.assertEqual(
                (root / "included" / included.relative_path).read_bytes(),
                source.read_bytes(),
            )

    def test_xor_decoder_rejects_unknown_data(self) -> None:
        self.assertIsNone(decode_legacy_xor(b"not-an-image-format"))

    def test_export_archive_contains_resolved_asset_and_manifest_mapping(self) -> None:
        token = "11111111111111111111111111111111"
        plaintext = b"\x89PNG\r\n\x1a\n" + b"synthetic-png"
        encrypted = bytes(value ^ 0x33 for value in plaintext)
        normalized = message(MessageKind.IMAGE, token)
        conversation = Conversation(
            id=normalized.conversation_id, display_name="Test", conversation_type="direct",
            last_timestamp=normalized.timestamp, layout="weixin-4", database=Path("unused"),
            table="Msg_test", selector="test",
        )

        class Dataset:
            def resolve(self, _conversation_id):
                return conversation

            def iter_messages(self, _scope, limit):
                yield normalized

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "account" / "msg" / "attach" / "x" / "Img" / f"{token}.dat"
            source.parent.mkdir(parents=True)
            source.write_bytes(encrypted)
            result = export_chat(
                Dataset(), ExportScope(normalized.conversation_id, include=frozenset({MessageKind.IMAGE})),
                root / "exports", media_resolver=MediaResolver(root / "account"),
            )
            with zipfile.ZipFile(result.archive) as archive:
                assets = [name for name in archive.namelist() if name.startswith("assets/")]
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(len(assets), 1)
                self.assertEqual(archive.read(assets[0]), plaintext)
                self.assertEqual(manifest["assets"][0]["status"], "packaged")


if __name__ == "__main__":
    unittest.main()
