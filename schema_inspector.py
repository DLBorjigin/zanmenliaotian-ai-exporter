from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3


class SchemaInspectionError(RuntimeError):
    pass


def _quoted_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _role(name: str, columns: set[str]) -> str:
    lowered = name.casefold()
    normalized_columns = {column.casefold() for column in columns}
    if lowered == "msg" and {"strtalker", "strcontent", "createtime"} <= normalized_columns:
        return "message-v3"
    if re.fullmatch(r"msg_[0-9a-f]{32}", lowered) and {
        "local_type", "create_time", "message_content"
    } <= normalized_columns:
        return "message-v4-shard"
    if lowered == "name2id" and "user_name" in normalized_columns:
        return "sender-map-v4"
    if "session" in lowered:
        return "session"
    if "contact" in lowered or lowered in {"rcontact", "contactlabel"}:
        return "contact"
    return "unclassified"


def inspect_schema(database: Path) -> dict[str, object]:
    database = database.resolve(strict=True)
    try:
        uri = database.as_uri() + "?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        objects = connection.execute(
            "SELECT type, name FROM sqlite_schema "
            "WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%' "
            "ORDER BY type, name"
        ).fetchall()
        tables = []
        canonical = []
        for object_type, name in objects:
            if object_type != "table":
                continue
            rows = connection.execute(f"PRAGMA table_xinfo({_quoted_identifier(name)})").fetchall()
            columns = [str(row[1]) for row in rows]
            role = _role(str(name), set(columns))
            identifier = hashlib.sha256(str(name).encode("utf-8")).hexdigest()[:12]
            tables.append({"id": f"table-{identifier}", "role": role, "columns": columns})
            canonical.append((str(name), tuple(columns)))
        index_count = sum(1 for item in objects if item[0] == "index")
        connection.close()
    except (OSError, sqlite3.DatabaseError, TypeError, ValueError) as exc:
        raise SchemaInspectionError("Decrypted output is not a readable SQLite database.") from exc

    roles = sorted({item["role"] for item in tables if item["role"] != "unclassified"})
    if "message-v4-shard" in roles:
        layout = "weixin-4"
    elif "message-v3" in roles:
        layout = "wechat-3"
    elif roles:
        layout = "auxiliary-database"
    else:
        layout = "unknown"
    fingerprint_source = json.dumps(canonical, ensure_ascii=False, separators=(",", ":"))
    return {
        "schema_version": 1,
        "status": "compatible" if layout != "unknown" else "unsupported_schema",
        "detected_layout": layout,
        "page_size": page_size,
        "user_version": user_version,
        "table_count": len(tables),
        "index_count": index_count,
        "roles": roles,
        "tables": tables,
        "schema_fingerprint": hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest(),
        "message_rows_read": 0,
        "identifiers_redacted": True,
    }
