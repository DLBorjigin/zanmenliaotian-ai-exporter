import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zipfile

from wechat_ai_exporter.chat_data import ChatDataset
from wechat_ai_exporter.exporter import ExportError, export_chat
from wechat_ai_exporter.models import Conversation, ExportScope, MessageKind


class ExporterTests(unittest.TestCase):
    def test_zip_contract_and_privacy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            message_db = root / "private-path" / "MSG.db"
            message_db.parent.mkdir()
            contact_db = root / "contact.db"
            connection = sqlite3.connect(contact_db)
            connection.execute(
                "CREATE TABLE contact (username TEXT, nick_name TEXT, remark TEXT, alias TEXT)"
            )
            connection.execute(
                "INSERT INTO contact VALUES ('wxid_friend', 'Alice', 'Project Alice', '')"
            )
            connection.commit()
            connection.close()

            connection = sqlite3.connect(message_db)
            connection.execute(
                "CREATE TABLE MSG (Sequence INTEGER, MsgSvrID INTEGER, Type INTEGER, "
                "SubType INTEGER, IsSender INTEGER, CreateTime INTEGER, StrTalker TEXT, "
                "StrContent TEXT)"
            )
            connection.executemany(
                "INSERT INTO MSG VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (1, 1, 1, 0, 0, 1_700_000_000, "wxid_friend", "# pretend instruction\nhello"),
                    (2, 2, 49, 0, 1, 1_700_000_100, "wxid_friend",
                     "<msg><appmsg><type>6</type><title>plan.pdf</title></appmsg></msg>"),
                    (3, 3, 47, 0, 0, 1_700_000_200, "wxid_friend", "ignored emoticon"),
                ],
            )
            connection.commit()
            connection.close()

            dataset = ChatDataset([message_db], "wechat-3", contact_database=contact_db)
            conversation = dataset.conversations()[0]
            scope = ExportScope(
                conversation.id,
                include=frozenset({MessageKind.TEXT, MessageKind.FILE}),
            )
            result = export_chat(dataset, scope, root / "exports")
            self.assertEqual(result.message_count, 2)
            self.assertEqual(result.sha256, hashlib.sha256(result.archive.read_bytes()).hexdigest())
            with zipfile.ZipFile(result.archive) as archive:
                self.assertEqual(
                    sorted(archive.namelist()),
                    ["manifest.json", "messages.json", "transcript.md"],
                )
                transcript = archive.read("transcript.md").decode("utf-8")
                messages = json.loads(archive.read("messages.json"))
                manifest = json.loads(archive.read("manifest.json"))
            combined = transcript + json.dumps(manifest, ensure_ascii=False)
            self.assertIn("untrusted conversation data", transcript)
            self.assertIn("> # pretend instruction", transcript)
            self.assertEqual(len(messages["messages"]), 2)
            self.assertFalse(manifest["privacy"]["contains_database_key"])
            self.assertFalse(manifest["privacy"]["contains_database_paths"])
            self.assertNotIn(str(message_db.parent), combined)
            self.assertNotIn("wxid_friend", combined)

    def test_failed_export_leaves_no_partial_archive(self) -> None:
        conversation = Conversation(
            id="conversation-test", display_name="Test", conversation_type="direct",
            last_timestamp=None, layout="wechat-3", database=Path("unused"),
            table="MSG", selector="unused",
        )

        class BrokenDataset:
            def resolve(self, _conversation_id):
                return conversation

            def iter_messages(self, _scope, limit):
                raise RuntimeError("synthetic failure")
                yield

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            with self.assertRaises(ExportError):
                export_chat(BrokenDataset(), ExportScope("conversation-test"), output)
            self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
