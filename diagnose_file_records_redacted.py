from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from wechat_ai_exporter.chat_data import _columns, _connect, _quote, _tables
from wechat_ai_exporter.cli import _auto_plaintext_bundle
from diagnose_scope_types_redacted import _zstd_decompress


def _summary(value: object, zstd_library: Path | None) -> dict[str, object]:
    if value is None:
        raw = b""
    elif isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8", "surrogatepass")
    decoded = _zstd_decompress(raw, zstd_library)
    payload = decoded if decoded is not None else raw
    searchable = payload.lower() + payload.replace(b"\x00", b"").lower()
    return {
        "stored_length": len(raw),
        "decoded_length": len(payload),
        "zstd": decoded is not None,
        "sha256_prefix": hashlib.sha256(payload).hexdigest()[:12],
        "flags": {
            "appmsg": b"appmsg" in searchable,
            "filename": b"filename" in searchable or b"title" in searchable,
            "fileext": b"fileext" in searchable or b".pdf" in searchable,
            "url": b"url" in searchable,
        },
    }


def main(args: argparse.Namespace) -> dict[str, object]:
    sources = {
        "message": args.message_database,
        "session": args.session_database,
        "contact": args.contact_database,
    }
    with _auto_plaintext_bundle(
        sources, args.snapshot_dir, args.work_dir, args.time_budget,
        derive_image_key=False,
    ) as (plain, _snapshots, _image_key, _image_xor_key):
        connection = _connect(plain["message"])
        try:
            records = []
            total = 0
            for table in _tables(connection).values():
                if not table.casefold().startswith("msg_"):
                    continue
                columns = _columns(connection, table)
                type_column = columns.get("local_type")
                if not type_column:
                    continue
                count = int(connection.execute(
                    f"SELECT COUNT(*) FROM {_quote(table)} WHERE {_quote(type_column)} = 49"
                ).fetchone()[0])
                total += count
                if count <= 0 or len(records) >= args.sample_limit:
                    continue
                names = ["message_content", "compress_content", "source", "packed_info_data"]
                expressions = [_quote(columns[name]) if columns.get(name) else "NULL" for name in names]
                for row in connection.execute(
                    f"SELECT {', '.join(expressions)} FROM {_quote(table)} "
                    f"WHERE {_quote(type_column)} = 49 LIMIT ?",
                    (args.sample_limit - len(records),),
                ):
                    records.append({
                        name: _summary(value, args.zstd_library)
                        for name, value in zip(names, row)
                    })
            return {
                "status": "redacted_file_record_diagnostic",
                "type49_total": total,
                "samples": records,
                "message_content_printed": False,
                "source_paths_printed": False,
                "keys_printed": False,
                "plaintext_retained": False,
            }
        finally:
            connection.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--message-database", required=True, type=Path)
    parser.add_argument("--session-database", required=True, type=Path)
    parser.add_argument("--contact-database", required=True, type=Path)
    parser.add_argument("--snapshot-dir", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--zstd-library", type=Path)
    parser.add_argument("--time-budget", type=float, default=25.0)
    parser.add_argument("--sample-limit", type=int, default=5)
    parser.add_argument("--confirm-read-process-memory", action="store_true")
    parser.add_argument("--confirm-read-selected-message-metadata", action="store_true")
    args = parser.parse_args()
    if not (args.confirm_read_process_memory and args.confirm_read_selected_message_metadata):
        raise SystemExit("explicit read-only confirmations are required")
    print(json.dumps(main(args), ensure_ascii=False, indent=2))
