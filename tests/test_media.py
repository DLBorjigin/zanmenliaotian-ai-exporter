from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock
import json
import zipfile

from wechat_ai_exporter.exporter import export_chat
from wechat_ai_exporter.media import (
    MediaResolver, V2_MAGIC, _allowed_remote_media_host, decode_legacy_xor,
)
from wechat_ai_exporter.models import Conversation, ExportScope, MessageKind, NormalizedMessage


def message(kind: MessageKind, content: str = "", packed_info=None,
            local_id: int = 10, server_id: int = 20,
            table: str = "Msg_test") -> NormalizedMessage:
    return NormalizedMessage(
        id=f"message-{kind.value}", conversation_id="conversation-test",
        timestamp=1_700_000_000, sender_name="Alice", is_self=False,
        kind=kind, type_code=1, subtype_code=None, content=content,
        sequence=1,
        metadata={
            "local_id": local_id, "server_id": server_id,
            "table": table, "packed_info": packed_info,
        },
    )


class MediaTests(unittest.TestCase):
    def test_large_unrelated_tree_is_bypassed_by_conversation_shard(self) -> None:
        token = "90909090909090909090909090909090"
        shard = "1234567890abcdef1234567890abcdef"
        plaintext = b"\x89PNG\r\n\x1a\n" + b"target"
        encrypted = bytes(value ^ 0x44 for value in plaintext)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            unrelated = root / "msg" / "attach" / "unrelated"
            unrelated.mkdir(parents=True)
            for index in range(250):
                (unrelated / f"irrelevant-{index}.dat").write_bytes(b"x")
            source = root / "msg" / "attach" / shard / "2026-08" / "Img" / f"{token}.dat"
            source.parent.mkdir(parents=True)
            source.write_bytes(encrypted)
            resolver = MediaResolver(root)
            result = resolver.resolve(
                message(MessageKind.IMAGE, token, table="Msg_" + shard),
                root / "out" / "assets",
            )[0]
            self.assertEqual(result.status, "packaged")
            self.assertIsNotNone(resolver._index)
            self.assertEqual(resolver._index.files_scanned, 1)

    def test_remote_media_host_allowlist_is_exact(self) -> None:
        self.assertTrue(_allowed_remote_media_host("wxapp.tc.qq.com"))
        self.assertTrue(_allowed_remote_media_host("emoji.qpic.cn"))
        self.assertFalse(_allowed_remote_media_host("evilqq.com"))
        self.assertFalse(_allowed_remote_media_host("wxapp.tc.qq.com.attacker.invalid"))

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

    def test_v2_wxgf_packages_opaque_original_and_viewable_preview(self) -> None:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        def encode(plaintext: bytes, key: bytearray, xor_key: int) -> bytes:
            first = plaintext
            pad = 16 - len(first) % 16
            padded = first + bytes([pad]) * pad
            encryptor = Cipher(algorithms.AES(bytes(key)), modes.ECB()).encryptor()
            encrypted = encryptor.update(padded) + encryptor.finalize()
            return (
                V2_MAGIC + len(first).to_bytes(4, "little")
                + (0).to_bytes(4, "little") + b"\x00" + encrypted
            )

        token = "ababcdcdababcdcdababcdcdababcdcd"
        key = bytearray(b"0123456789abcdef")
        xor_key = 0x31
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "msg" / "attach" / "x" / "Img" / f"{token}.dat"
            source.parent.mkdir(parents=True)
            source.write_bytes(encode(b"wxgf" + b"opaque-original", key, xor_key))
            preview = source.with_name(source.stem + "_t.dat")
            preview.write_bytes(encode(b"\xff\xd8\xffpreview\xff\xd9", key, xor_key))
            results = MediaResolver(
                root, image_aes_key=key, image_xor_key=xor_key
            ).resolve(message(MessageKind.IMAGE, token), root / "out" / "assets")
            self.assertEqual(
                [item.status for item in results],
                ["packaged_opaque", "packaged_preview"],
            )
            self.assertTrue(
                (root / "out" / results[1].relative_path).read_bytes().startswith(b"\xff\xd8\xff")
            )

    def test_video_jpeg_is_labeled_thumbnail_only(self) -> None:
        token = "12341234123412341234123412341234"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "msg" / "attach" / "x" / "Video" / f"{token}.jpg"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"\xff\xd8\xffvideo-thumb\xff\xd9")
            original = MediaResolver(root).resolve(
                message(MessageKind.VIDEO, token), root / "out" / "assets"
            )[0]
            self.assertEqual(original.status, "video_original_not_found")
            self.assertIsNone(original.relative_path)
            result = MediaResolver(root, video_asset="thumbnail").resolve(
                message(MessageKind.VIDEO, token), root / "thumb" / "assets"
            )[0]
            self.assertEqual(result.status, "packaged_thumbnail_only")
            self.assertEqual(result.media_type, "image/jpeg")
            self.assertTrue(result.relative_path.startswith("assets/videos/"))

    def test_video_original_does_not_include_thumbnail(self) -> None:
        token = "34343434343434343434343434343434"
        video = b"\x00\x00\x00\x18ftypisom" + b"synthetic-video"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "msg" / "attach" / "x" / "Video"
            folder.mkdir(parents=True)
            (folder / f"{token}.mp4").write_bytes(video)
            (folder / f"{token}.jpg").write_bytes(b"\xff\xd8\xffthumb")
            results = MediaResolver(root, video_asset="original").resolve(
                message(MessageKind.VIDEO, token), root / "out" / "assets"
            )
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].status, "packaged")
            self.assertEqual(results[0].media_type, "video/mp4")
            self.assertTrue(results[0].relative_path.endswith(".mp4"))

    def test_remote_video_original_is_signature_validated(self) -> None:
        video = b"\x00\x00\x00\x18ftypisom" + b"remote-video"
        xml = '<videomsg cdnvideourl="https://wxapp.tc.qq.com/video/example" />'

        class Response:
            headers = {"Content-Length": str(len(video))}

            def __enter__(self): return self
            def __exit__(self, *_args): return None
            def geturl(self): return "https://wxapp.tc.qq.com/video/example"
            def read(self, _limit): return video

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch("urllib.request.urlopen", return_value=Response()):
                result = MediaResolver(
                    root, allow_remote_media_download=True, video_asset="original"
                ).resolve(message(MessageKind.VIDEO, xml), root / "out" / "assets")[0]
            self.assertEqual(result.status, "packaged_remote")
            self.assertEqual(result.media_type, "video/mp4")
            self.assertTrue(result.relative_path.startswith("assets/videos/"))

    def test_remote_video_can_use_message_aes_ecb_key(self) -> None:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key = b"0123456789abcdef"
        video = b"\x00\x00\x00\x18ftypisom" + b"encrypted-video"
        pad = 16 - len(video) % 16
        encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        encrypted = encryptor.update(video + bytes([pad]) * pad) + encryptor.finalize()
        xml = (
            '<videomsg cdnvideourl="https://wxapp.tc.qq.com/video/encrypted" '
            f'aeskey="{key.hex()}" />'
        )

        class Response:
            headers = {"Content-Length": str(len(encrypted))}

            def __enter__(self): return self
            def __exit__(self, *_args): return None
            def geturl(self): return "https://wxapp.tc.qq.com/video/encrypted"
            def read(self, _limit): return encrypted

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch("urllib.request.urlopen", return_value=Response()):
                result = MediaResolver(
                    root, allow_remote_media_download=True, video_asset="original"
                ).resolve(message(MessageKind.VIDEO, xml), root / "out" / "assets")[0]
            self.assertEqual(result.status, "packaged_remote")
            self.assertEqual((root / "out" / result.relative_path).read_bytes(), video)

    def test_legacy_hex_video_token_requires_wechat_client(self) -> None:
        xml = (
            '<videomsg cdnvideourl="3057020100044b304902010002043904" '
            'aeskey="00112233445566778899aabbccddeeff" />'
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            offline = MediaResolver(root).resolve(
                message(MessageKind.VIDEO, xml), root / "offline" / "assets"
            )[0]
            self.assertEqual(offline.status, "video_remote_download_not_authorized")
            online = MediaResolver(
                root, allow_remote_media_download=True
            ).resolve(message(MessageKind.VIDEO, xml), root / "online" / "assets")[0]
            self.assertEqual(online.status, "video_cdn_requires_wechat_client")
            self.assertIsNone(online.relative_path)

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

    def test_identical_duplicate_candidates_are_deduplicated(self) -> None:
        token = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for folder in (root / "business" / "emoticon", root / "cache" / "emoji"):
                folder.mkdir(parents=True)
                (folder / f"{token}.gif").write_bytes(b"GIF89a" + b"same")
            result = MediaResolver(root, include_emoticons=True).resolve(
                message(MessageKind.EMOTICON, token), root / "out" / "assets"
            )[0]
            self.assertEqual(result.status, "packaged")

    def test_unknown_local_emoticon_is_not_packaged_as_viewable_media(self) -> None:
        token = "efefefefefefefefefefefefefefefef"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "business" / "emoticon" / token
            source.parent.mkdir(parents=True)
            source.write_bytes(b"private-wechat-emoticon")
            result = MediaResolver(root, include_emoticons=True).resolve(
                message(MessageKind.EMOTICON, token), root / "out" / "assets"
            )[0]
            self.assertEqual(result.status, "unsupported_emoticon_format")
            self.assertIsNone(result.relative_path)

    def test_remote_emoticon_requires_opt_in_and_validates_image(self) -> None:
        token = "12121212121212121212121212121212"
        xml = f'<emoji md5="{token}" cdnurl="https://emoji.qpic.cn/wx_emoji/example/" />'

        class Response:
            headers = {"Content-Length": "17"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def geturl(self):
                return "https://emoji.qpic.cn/wx_emoji/example/"

            def read(self, _limit):
                return b"GIF89a" + b"remote-gif"

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "business" / "emoticon" / token
            source.parent.mkdir(parents=True)
            source.write_bytes(b"private-wechat-emoticon")
            with mock.patch("urllib.request.urlopen", return_value=Response()) as fetch:
                result = MediaResolver(
                    root, include_emoticons=True, allow_remote_media_download=True
                ).resolve(message(MessageKind.EMOTICON, xml), root / "out" / "assets")[0]
            self.assertEqual(result.status, "packaged_remote")
            self.assertEqual(result.media_type, "image/gif")
            self.assertTrue(result.relative_path.startswith("assets/emoticons/"))
            fetch.assert_called_once()

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
                split_asset_bundles=False,
            )
            with zipfile.ZipFile(result.archive) as archive:
                assets = [name for name in archive.namelist() if name.startswith("assets/")]
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(len(assets), 1)
                self.assertTrue(assets[0].startswith("assets/images/"))
                self.assertEqual(archive.read(assets[0]), plaintext)
                self.assertEqual(manifest["assets"][0]["status"], "packaged")

    def test_default_split_asset_bundle_keeps_image_message_in_core_records(self) -> None:
        token = "22222222222222222222222222222222"
        plaintext = b"\x89PNG\r\n\x1a\n" + b"separate-png"
        encrypted = bytes(value ^ 0x21 for value in plaintext)
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
            self.assertIn("images", result.asset_archives)
            with zipfile.ZipFile(result.archive) as core:
                self.assertFalse(any(name.startswith("assets/") for name in core.namelist()))
                payload = json.loads(core.read("messages.json"))
                self.assertEqual(payload["messages"][0]["kind"], "image")
                self.assertTrue(payload["messages"][0]["assets"][0]["relative_path"].startswith("assets/images/"))
                manifest = json.loads(core.read("manifest.json"))
                self.assertEqual(manifest["asset_delivery"]["mode"], "separate_archives")
            with zipfile.ZipFile(result.asset_archives["images"]) as media:
                asset_name = next(name for name in media.namelist() if name.startswith("assets/images/"))
                self.assertEqual(media.read(asset_name), plaintext)
            output_files = sorted(path.name for path in (root / "exports").iterdir())
            self.assertEqual(len(output_files), 2)
            self.assertTrue(any(name.endswith("-records.zip") for name in output_files))
            self.assertTrue(any(name.endswith("-images.zip") for name in output_files))


if __name__ == "__main__":
    unittest.main()
