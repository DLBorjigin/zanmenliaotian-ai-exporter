import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from wechat_ai_exporter.chat_data import ChatDataset, message_kind
from wechat_ai_exporter.models import ExportScope, MessageKind


def create_contact_db(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE contact (id INTEGER, username TEXT, nick_name TEXT, remark TEXT, alias TEXT)"
    )
    connection.executemany(
        "INSERT INTO contact VALUES (?, ?, ?, ?, ?)",
        [
            (1, "wxid_friend", "Friend Nick", "Project Partner", "friend_alias"),
            (2, "wxid_sender", "Group Sender", "", "sender_alias"),
            (3, "room@chatroom", "Team Room", "Work Group", ""),
        ],
    )
    connection.commit()
    connection.close()


class ChatDataTests(unittest.TestCase):
    def test_v3_catalog_time_and_type_filters(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            message_db = root / "MSG.db"
            contact_db = root / "contact.db"
            create_contact_db(contact_db)
            connection = sqlite3.connect(message_db)
            connection.execute(
                "CREATE TABLE MSG (Sequence INTEGER, MsgSvrID INTEGER, Type INTEGER, "
                "SubType INTEGER, IsSender INTEGER, CreateTime INTEGER, StrTalker TEXT, "
                "StrContent TEXT)"
            )
            connection.executemany(
                "INSERT INTO MSG VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (1, 101, 1, 0, 0, 1_700_000_000_000, "wxid_friend", "hello"),
                    (2, 102, 3, 0, 1, 1_700_000_100_000, "wxid_friend", "image-ref"),
                    (3, 103, 47, 0, 0, 1_700_000_200_000, "wxid_friend", "emoticon"),
                    (4, 104, 1, 0, 0, 1_700_000_000_000, "other", "not selected"),
                ],
            )
            connection.commit()
            connection.close()

            dataset = ChatDataset([message_db], "wechat-3", contact_database=contact_db)
            conversation = next(item for item in dataset.conversations() if item.display_name == "Project Partner")
            scope = ExportScope(
                conversation.id, start_timestamp=1_700_000_050,
                end_timestamp=1_700_000_250,
                include=frozenset({MessageKind.IMAGE}),
            )
            preview = dataset.preview(scope)
            messages = list(dataset.iter_messages(scope))
            self.assertEqual(preview["message_bodies_read"], 0)
            self.assertEqual(preview["counts_by_kind"], {"emoticon": 1, "image": 1})
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].kind, MessageKind.IMAGE)
            self.assertTrue(messages[0].is_self)

    def test_v4_session_mapping_sender_and_file_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            message_db = root / "message_0.db"
            session_db = root / "session.db"
            contact_db = root / "contact.db"
            create_contact_db(contact_db)
            table = "Msg_" + hashlib.md5(b"room@chatroom").hexdigest()

            connection = sqlite3.connect(message_db)
            connection.execute("CREATE TABLE Name2Id (rowid INTEGER PRIMARY KEY, user_name TEXT)")
            connection.execute("INSERT INTO Name2Id VALUES (1, 'wxid_sender')")
            connection.execute(
                f'CREATE TABLE "{table}" (local_id INTEGER, server_id INTEGER, local_type INTEGER, '
                "sort_seq INTEGER, real_sender_id INTEGER, create_time INTEGER, status INTEGER, "
                "message_content TEXT)"
            )
            connection.executemany(
                f'INSERT INTO "{table}" VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    (1, 201, 1, 1, 1, 1_700_001_000, 4, "group hello"),
                    (2, 202, 49, 2, 1, 1_700_001_100, 2,
                     "<msg><appmsg><type>6</type><title>report.pdf</title></appmsg></msg>"),
                ],
            )
            connection.commit()
            connection.close()

            connection = sqlite3.connect(session_db)
            connection.execute("CREATE TABLE SessionTable (username TEXT, last_timestamp INTEGER, summary TEXT)")
            connection.execute(
                "INSERT INTO SessionTable VALUES ('room@chatroom', 1700001100, 'must not be read')"
            )
            connection.commit()
            connection.close()

            dataset = ChatDataset(
                [message_db], "weixin-4", session_database=session_db,
                contact_database=contact_db,
            )
            conversation = dataset.conversations()[0]
            self.assertEqual(conversation.display_name, "Work Group")
            self.assertEqual(conversation.conversation_type, "group")
            scope = ExportScope(
                conversation.id,
                include=frozenset({MessageKind.TEXT, MessageKind.FILE}),
            )
            preview = dataset.preview(scope)
            messages = list(dataset.iter_messages(scope))
            self.assertEqual(preview["ambiguous_link_or_file_count"], 1)
            self.assertEqual([item.kind for item in messages], [MessageKind.TEXT, MessageKind.FILE])
            self.assertEqual(messages[0].sender_name, "Group Sender")
            self.assertEqual(messages[1].sender_name, "Me")

    def test_message_type_mapping(self) -> None:
        self.assertEqual(message_kind(34), MessageKind.AUDIO)
        self.assertEqual(message_kind(47), MessageKind.EMOTICON)
        self.assertEqual(message_kind(10_000), MessageKind.SYSTEM)
        self.assertEqual(message_kind(49, "<msg><appmsg><type>6</type></appmsg></msg>"), MessageKind.FILE)

    def test_v4_compressed_content_can_classify_file_without_message_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            message_db = root / "message.db"
            session_db = root / "session.db"
            table = "Msg_" + hashlib.md5(b"room@chatroom").hexdigest()
            connection = sqlite3.connect(message_db)
            connection.execute(
                f'CREATE TABLE "{table}" (local_id INTEGER, server_id INTEGER, '
                "local_type INTEGER, sort_seq INTEGER, create_time INTEGER, status INTEGER, "
                "message_content TEXT, compress_content BLOB, source BLOB)"
            )
            connection.execute(
                f'INSERT INTO "{table}" VALUES (1, 2, 49, 3, 1700000000, 4, NULL, ?, ?)',
                (b"compressed-file", b"compressed-source"),
            )
            connection.commit()
            connection.close()
            connection = sqlite3.connect(session_db)
            connection.execute("CREATE TABLE SessionTable (username TEXT)")
            connection.execute("INSERT INTO SessionTable VALUES ('room@chatroom')")
            connection.commit()
            connection.close()
            xml = b"<msg><appmsg><type>6</type><title>report.pdf</title></appmsg></msg>"

            def decode(value):
                if value == b"compressed-file":
                    return xml
                return value

            with mock.patch(
                "wechat_ai_exporter.chat_data.decode_zstd_if_needed", side_effect=decode
            ):
                dataset = ChatDataset([message_db], "weixin-4", session_database=session_db)
                conversation = dataset.conversations()[0]
                scope = ExportScope(
                    conversation.id, include=frozenset({MessageKind.FILE})
                )
                messages = list(dataset.iter_messages(scope))
            self.assertEqual(len(messages), 1)
            self.assertEqual(messages[0].kind, MessageKind.FILE)
            self.assertIn("report.pdf", messages[0].content)


if __name__ == "__main__":
    unittest.main()
