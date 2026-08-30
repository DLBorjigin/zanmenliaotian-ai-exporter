from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
from pathlib import Path
import re
import sqlite3
from typing import Iterator
import xml.etree.ElementTree as ET

from .models import Conversation, ExportScope, MessageKind, NormalizedMessage
from .zstd_codec import decode_zstd_if_needed


class ChatDataError(RuntimeError):
    pass


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _connect(path: Path) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(path.resolve(strict=True).as_uri() + "?mode=ro&immutable=1", uri=True)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection
    except (OSError, sqlite3.DatabaseError) as exc:
        raise ChatDataError(f"Could not open plaintext database: {path.name}") from exc


def _tables(connection: sqlite3.Connection) -> dict[str, str]:
    return {
        str(name).casefold(): str(name)
        for (name,) in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def _columns(connection: sqlite3.Connection, table: str) -> dict[str, str]:
    return {
        str(row[1]).casefold(): str(row[1])
        for row in connection.execute(f"PRAGMA table_xinfo({_quote(table)})")
    }


def _column_expression(columns: dict[str, str], name: str, alias: str,
                       prefix: str = "") -> str:
    actual = columns.get(name.casefold())
    if actual is None:
        return f"NULL AS {_quote(alias)}"
    qualified = f"{prefix}." if prefix else ""
    return f"{qualified}{_quote(actual)} AS {_quote(alias)}"


def _stable_id(prefix: str, value: str) -> str:
    return f"{prefix}-{hashlib.sha256(value.encode('utf-8', 'surrogatepass')).hexdigest()[:12]}"


def _display_label(selector: str, candidate: str) -> str:
    if candidate != selector:
        return candidate
    if selector.startswith("wxid_") or selector.startswith("gh_") or selector.endswith("@chatroom"):
        kind = "group" if selector.endswith("@chatroom") else "contact"
        return f"Unknown {kind} {_stable_id('name', selector)[-6:]}"
    return candidate


def normalize_timestamp(value: object) -> int:
    try:
        timestamp = int(value or 0)
    except (TypeError, ValueError):
        return 0
    absolute = abs(timestamp)
    if absolute >= 10**15:
        return timestamp // 1_000_000
    if absolute >= 10**12:
        return timestamp // 1_000
    return timestamp


def parse_time_bound(value: str | None) -> int | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ChatDataError("Time must use ISO format, for example 2026-08-01 or 2026-08-01T09:30:00.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return int(parsed.timestamp())


def message_kind(type_code: int, content: str = "", inspect_content: bool = True) -> MessageKind:
    if type_code == 1:
        return MessageKind.TEXT
    if type_code == 3:
        return MessageKind.IMAGE
    if type_code == 34:
        return MessageKind.AUDIO
    if type_code in {43, 62}:
        return MessageKind.VIDEO
    if type_code == 47:
        return MessageKind.EMOTICON
    if type_code == 49:
        if inspect_content:
            try:
                root = ET.fromstring(content)
                app_type = root.findtext(".//appmsg/type")
                if app_type == "6":
                    return MessageKind.FILE
            except (ET.ParseError, TypeError):
                pass
        return MessageKind.LINK
    if type_code >= 10_000:
        return MessageKind.SYSTEM
    return MessageKind.UNKNOWN


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    return str(value)


def _decoded_text(value: object) -> str:
    if isinstance(value, bytes):
        decoded = decode_zstd_if_needed(value)
        if decoded is None:
            return ""
        value = decoded
    return _text(value)


class ChatDataset:
    def __init__(self, message_databases: list[Path], layout: str,
                 session_database: Path | None = None,
                 contact_database: Path | None = None) -> None:
        if not message_databases:
            raise ChatDataError("At least one plaintext message database is required.")
        self.message_databases = [Path(item) for item in message_databases]
        self.layout = layout
        self.session_database = Path(session_database) if session_database else None
        self.contact_database = Path(contact_database) if contact_database else None
        self._contacts = self._load_contacts()
        self._catalog: list[Conversation] | None = None

    def _load_contacts(self) -> dict[str, str]:
        if self.contact_database is None:
            return {}
        connection = _connect(self.contact_database)
        try:
            tables = _tables(connection)
            table = tables.get("contact") or tables.get("rcontact")
            if not table:
                return {}
            columns = _columns(connection, table)
            username = columns.get("username") or columns.get("username_")
            if not username:
                return {}
            display_fields = [
                columns.get("remark"), columns.get("remark_"),
                columns.get("nick_name"), columns.get("nickname"), columns.get("nickname_"),
                columns.get("alias"),
            ]
            selected = [_quote(username)] + [
                _quote(item) for item in display_fields if item is not None
            ]
            contacts: dict[str, str] = {}
            for row in connection.execute(f"SELECT {', '.join(selected)} FROM {_quote(table)}"):
                identifier = _text(row[0])
                if not identifier:
                    continue
                display = next((_text(value) for value in row[1:] if _text(value).strip()), identifier)
                contacts[identifier] = display
            return contacts
        finally:
            connection.close()

    def conversations(self) -> list[Conversation]:
        if self._catalog is None:
            self._catalog = self._v3_conversations() if self.layout == "wechat-3" else self._v4_conversations()
        return list(self._catalog)

    def _v3_conversations(self) -> list[Conversation]:
        database = self.message_databases[0]
        connection = _connect(database)
        try:
            table = _tables(connection).get("msg")
            if not table:
                raise ChatDataError("The WeChat 3.x MSG table was not found.")
            columns = _columns(connection, table)
            talker = columns.get("strtalker")
            created = columns.get("createtime")
            if not talker or not created:
                raise ChatDataError("The WeChat 3.x message schema is unsupported.")
            rows = connection.execute(
                f"SELECT {_quote(talker)}, MAX({_quote(created)}) FROM {_quote(table)} "
                f"WHERE {_quote(talker)} IS NOT NULL GROUP BY {_quote(talker)}"
            ).fetchall()
            result = []
            for selector, last_time in rows:
                selector_text = _text(selector)
                result.append(self._conversation(
                    selector_text, self._contacts.get(selector_text, selector_text), database,
                    table, normalize_timestamp(last_time), "wechat-3",
                ))
            return sorted(result, key=lambda item: item.last_timestamp or 0, reverse=True)
        finally:
            connection.close()

    def _v4_conversations(self) -> list[Conversation]:
        shards: dict[str, tuple[Path, str]] = {}
        for database in self.message_databases:
            connection = _connect(database)
            try:
                for actual in _tables(connection).values():
                    if re.fullmatch(r"Msg_[0-9a-fA-F]{32}", actual):
                        shards[actual.casefold()] = (database, actual)
            finally:
                connection.close()

        result: list[Conversation] = []
        claimed: set[str] = set()
        if self.session_database is not None:
            connection = _connect(self.session_database)
            try:
                table = _tables(connection).get("sessiontable")
                if table:
                    columns = _columns(connection, table)
                    username = columns.get("username")
                    time_column = next((columns.get(name) for name in (
                        "last_timestamp", "last_time", "update_time", "timestamp", "sort_timestamp"
                    ) if columns.get(name)), None)
                    if username:
                        time_expression = _quote(time_column) if time_column else "NULL"
                        for selector, last_time in connection.execute(
                            f"SELECT {_quote(username)}, {time_expression} FROM {_quote(table)}"
                        ):
                            selector_text = _text(selector)
                            shard_key = "msg_" + hashlib.md5(selector_text.encode("utf-8")).hexdigest()
                            shard = shards.get(shard_key)
                            if not shard:
                                continue
                            claimed.add(shard_key)
                            result.append(self._conversation(
                                selector_text, self._contacts.get(selector_text, selector_text),
                                shard[0], shard[1], normalize_timestamp(last_time), "weixin-4",
                            ))
            finally:
                connection.close()
        for shard_key, (database, table) in shards.items():
            if shard_key in claimed:
                continue
            token = shard_key.removeprefix("msg_")[:8]
            result.append(self._conversation(
                shard_key, f"Unknown conversation {token}", database, table,
                self._max_timestamp(database, table, "create_time"), "weixin-4",
            ))
        return sorted(result, key=lambda item: item.last_timestamp or 0, reverse=True)

    def _conversation(self, selector: str, display_name: str, database: Path,
                      table: str, last_timestamp: int | None, layout: str) -> Conversation:
        conversation_type = (
            "group" if selector.endswith("@chatroom") else
            "official" if selector.startswith("gh_") else "direct"
        )
        return Conversation(
            id=_stable_id("conversation", selector), display_name=_display_label(selector, display_name),
            conversation_type=conversation_type, last_timestamp=last_timestamp or None,
            layout=layout, database=database, table=table, selector=selector,
        )

    def _max_timestamp(self, database: Path, table: str, column: str) -> int | None:
        connection = _connect(database)
        try:
            columns = _columns(connection, table)
            actual = columns.get(column)
            if not actual:
                return None
            value = connection.execute(
                f"SELECT MAX({_quote(actual)}) FROM {_quote(table)}"
            ).fetchone()[0]
            return normalize_timestamp(value) or None
        finally:
            connection.close()

    def resolve(self, conversation_id: str) -> Conversation:
        matches = [item for item in self.conversations() if item.id == conversation_id]
        if len(matches) != 1:
            raise ChatDataError("The selected conversation ID is missing or ambiguous.")
        return matches[0]

    def preview(self, scope: ExportScope) -> dict[str, object]:
        conversation = self.resolve(scope.conversation_id)
        connection = _connect(conversation.database)
        try:
            columns = _columns(connection, conversation.table)
            type_name = columns.get("type") if conversation.layout == "wechat-3" else columns.get("local_type")
            time_name = columns.get("createtime") if conversation.layout == "wechat-3" else columns.get("create_time")
            talker_name = columns.get("strtalker") if conversation.layout == "wechat-3" else None
            if not type_name or not time_name:
                raise ChatDataError("The selected message table lacks type or time columns.")
            time_scale = self._time_scale(connection, conversation.table, time_name)
            where, parameters = self._where(
                scope, time_name, talker_name, conversation.selector, time_scale
            )
            rows = connection.execute(
                f"SELECT {_quote(type_name)}, COUNT(*) FROM {_quote(conversation.table)} "
                f"{where} GROUP BY {_quote(type_name)}", parameters,
            ).fetchall()
            counts = Counter()
            ambiguous = 0
            for raw_type, count in rows:
                kind = message_kind(int(raw_type or 0), inspect_content=False)
                if int(raw_type or 0) == 49:
                    ambiguous += int(count)
                counts[kind.value] += int(count)
            included = {kind.value: counts.get(kind.value, 0) for kind in scope.include}
            return {
                "conversation_id": conversation.id,
                "display_name": conversation.display_name,
                "start_timestamp": scope.start_timestamp,
                "end_timestamp": scope.end_timestamp,
                "counts_by_kind": dict(sorted(counts.items())),
                "selected_count": sum(included.values()),
                "included_kinds": sorted(kind.value for kind in scope.include),
                "ambiguous_link_or_file_count": ambiguous,
                "message_bodies_read": 0,
            }
        finally:
            connection.close()

    def _time_scale(self, connection: sqlite3.Connection, table: str, time_column: str) -> int:
        value = connection.execute(
            f"SELECT MAX(ABS({_quote(time_column)})) FROM {_quote(table)}"
        ).fetchone()[0]
        absolute = abs(int(value or 0))
        return 1_000_000 if absolute >= 10**15 else 1_000 if absolute >= 10**12 else 1

    def _where(self, scope: ExportScope, time_column: str,
               talker_column: str | None, selector: str,
               time_scale: int = 1) -> tuple[str, list[object]]:
        clauses: list[str] = []
        parameters: list[object] = []
        if talker_column:
            clauses.append(f"{_quote(talker_column)} = ?")
            parameters.append(selector)
        if scope.start_timestamp is not None:
            clauses.append(f"{_quote(time_column)} >= ?")
            parameters.append(scope.start_timestamp * time_scale)
        if scope.end_timestamp is not None:
            clauses.append(f"{_quote(time_column)} <= ?")
            parameters.append(scope.end_timestamp * time_scale)
        return ("WHERE " + " AND ".join(clauses) if clauses else "", parameters)

    def iter_messages(self, scope: ExportScope, limit: int = 100_000) -> Iterator[NormalizedMessage]:
        conversation = self.resolve(scope.conversation_id)
        if conversation.layout == "wechat-3":
            yield from self._iter_v3(conversation, scope, limit)
        else:
            yield from self._iter_v4(conversation, scope, limit)

    def _iter_v3(self, conversation: Conversation, scope: ExportScope,
                 limit: int) -> Iterator[NormalizedMessage]:
        connection = _connect(conversation.database)
        try:
            columns = _columns(connection, conversation.table)
            expressions = [
                _column_expression(columns, "localId", "local_id"),
                _column_expression(columns, "Sequence", "sequence"),
                _column_expression(columns, "MsgSvrID", "server_id"),
                _column_expression(columns, "Type", "type_code"),
                _column_expression(columns, "SubType", "subtype_code"),
                _column_expression(columns, "IsSender", "is_sender"),
                _column_expression(columns, "CreateTime", "created"),
                _column_expression(columns, "StrContent", "content"),
                _column_expression(columns, "BytesExtra", "packed_info"),
            ]
            time_name = columns.get("createtime")
            if not time_name:
                raise ChatDataError("The message time column is missing.")
            time_scale = self._time_scale(connection, conversation.table, time_name)
            where, parameters = self._where(
                scope, time_name, columns.get("strtalker"), conversation.selector, time_scale
            )
            parameters.append(max(1, min(limit, 1_000_000)))
            query = (
                f"SELECT {', '.join(expressions)} FROM {_quote(conversation.table)} {where} "
                f"ORDER BY {_quote(time_name)}, rowid LIMIT ?"
            )
            for row in connection.execute(query, parameters):
                message = self._normalize_row(
                    conversation, row[1:8], sender=conversation.display_name,
                    metadata={
                        "local_id": int(row[0] or 0), "server_id": int(row[2] or 0),
                        "table": conversation.table, "packed_info": row[8],
                    },
                )
                if message.kind in scope.include:
                    yield message
        finally:
            connection.close()

    def _iter_v4(self, conversation: Conversation, scope: ExportScope,
                 limit: int) -> Iterator[NormalizedMessage]:
        connection = _connect(conversation.database)
        try:
            columns = _columns(connection, conversation.table)
            tables = _tables(connection)
            name_table = tables.get("name2id")
            join = ""
            sender_expression = "NULL AS sender"
            if name_table:
                name_columns = _columns(connection, name_table)
                sender_id = columns.get("real_sender_id")
                username = name_columns.get("user_name")
                if sender_id and username:
                    join = (
                        f" LEFT JOIN {_quote(name_table)} n ON "
                        f"m.{_quote(sender_id)} = n.rowid"
                    )
                    sender_expression = f"n.{_quote(username)} AS sender"
            expressions = [
                _column_expression(columns, "local_id", "local_id", "m"),
                _column_expression(columns, "sort_seq", "sequence", "m"),
                _column_expression(columns, "server_id", "server_id", "m"),
                _column_expression(columns, "local_type", "type_code", "m"),
                "NULL AS subtype_code",
                _column_expression(columns, "status", "is_sender", "m"),
                _column_expression(columns, "create_time", "created", "m"),
                _column_expression(columns, "message_content", "content", "m"),
                _column_expression(columns, "packed_info_data", "packed_info", "m"),
                _column_expression(columns, "source", "source", "m"),
                _column_expression(columns, "compress_content", "compress_content", "m"),
                _column_expression(columns, "origin_source", "origin_source", "m"),
                sender_expression,
            ]
            time_name = columns.get("create_time")
            if not time_name:
                raise ChatDataError("The message time column is missing.")
            clauses = []
            parameters = []
            if scope.start_timestamp is not None:
                clauses.append(f"m.{_quote(time_name)} >= ?")
                parameters.append(scope.start_timestamp)
            if scope.end_timestamp is not None:
                clauses.append(f"m.{_quote(time_name)} <= ?")
                parameters.append(scope.end_timestamp)
            where = "WHERE " + " AND ".join(clauses) if clauses else ""
            parameters.append(max(1, min(limit, 1_000_000)))
            query = (
                f"SELECT {', '.join(expressions)} FROM {_quote(conversation.table)} m{join} "
                f"{where} ORDER BY m.{_quote(time_name)}, m.rowid LIMIT ?"
            )
            for row in connection.execute(query, parameters):
                sender_id = _text(row[12])
                sender = _display_label(
                    sender_id, self._contacts.get(sender_id, sender_id or conversation.display_name)
                )
                content = _decoded_text(row[7]) or _decoded_text(row[10])
                normalized_row = (*row[1:7], content)
                message = self._normalize_row(
                    conversation, normalized_row, sender=sender,
                    metadata={
                        "local_id": int(row[0] or 0), "server_id": int(row[2] or 0),
                        "table": conversation.table, "packed_info": row[8],
                        "source": _decoded_text(row[9]),
                        "compress_content": _decoded_text(row[10]),
                        "origin_source": _decoded_text(row[11]),
                    },
                )
                if message.kind in scope.include:
                    yield message
        finally:
            connection.close()

    def _normalize_row(self, conversation: Conversation, row: tuple[object, ...],
                       sender: str, metadata: dict[str, object]) -> NormalizedMessage:
        sequence, server_id, raw_type, subtype, sender_flag, created, raw_content = row
        content = _text(raw_content)
        type_code = int(raw_type or 0)
        kind = message_kind(type_code, content, inspect_content=True)
        if conversation.layout == "wechat-3":
            is_self = bool(sender_flag) if sender_flag is not None else None
        else:
            status = int(sender_flag or 0)
            is_self = True if status == 2 else False if status == 4 else None
        message_id_source = str(server_id or f"{conversation.selector}:{sequence}:{created}")
        return NormalizedMessage(
            id=_stable_id("message", message_id_source),
            conversation_id=conversation.id,
            timestamp=normalize_timestamp(created),
            sender_name="Me" if is_self else sender,
            is_self=is_self,
            kind=kind,
            type_code=type_code,
            subtype_code=int(subtype) if subtype is not None else None,
            content=content,
            sequence=int(sequence or 0),
            metadata=metadata,
        )
