from __future__ import annotations

import argparse
import ctypes
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re

from wechat_ai_exporter.chat_data import ChatDataset, _columns, _connect, _quote
from wechat_ai_exporter.cli import _auto_plaintext_bundle
from wechat_ai_exporter.media import MediaResolver, V1_MAGIC, V2_MAGIC
from wechat_ai_exporter.models import ExportScope, MessageKind


def _header_kind(path: Path) -> str:
    try:
        data = path.read_bytes()[:32]
    except OSError:
        return "unreadable"
    if data.startswith(V2_MAGIC):
        return "wechat-v2"
    if data.startswith(V1_MAGIC):
        return "wechat-v1"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "mp4-family"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"wxgf"):
        return "wxgf"
    return "other"


def _header_hex(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(24).hex()
    except OSError:
        return ""


def _path_category(path: Path) -> str:
    text = "/".join(part.casefold() for part in path.parts)
    for label in ("video", "img", "emotion", "file"):
        if f"/{label}/" in f"/{text}/":
            return label
    return "other"


def _zstd_decompress(data: bytes, library: Path | None) -> bytes | None:
    if library is None or not data.startswith(b"\x28\xb5\x2f\xfd"):
        return None
    try:
        dll = ctypes.WinDLL(str(library))
        dll.ZSTD_getFrameContentSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        dll.ZSTD_getFrameContentSize.restype = ctypes.c_ulonglong
        dll.ZSTD_decompress.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t
        ]
        dll.ZSTD_decompress.restype = ctypes.c_size_t
        dll.ZSTD_isError.argtypes = [ctypes.c_size_t]
        dll.ZSTD_isError.restype = ctypes.c_uint
        source = ctypes.create_string_buffer(data)
        size = int(dll.ZSTD_getFrameContentSize(source, len(data)))
        if not 0 < size <= 16 * 1024 * 1024:
            return None
        target = ctypes.create_string_buffer(size)
        written = int(dll.ZSTD_decompress(target, size, source, len(data)))
        if dll.ZSTD_isError(written) or written != size:
            return None
        return target.raw[:written]
    except (OSError, AttributeError, ValueError):
        return None


def _field_summary(value: object, zstd_library: Path | None = None) -> dict[str, object]:
    if value is None:
        data = b""
    elif isinstance(value, bytes):
        data = value
    else:
        data = str(value).encode("utf-8", "surrogatepass")
    searchable = data.lower() + data.replace(b"\x00", b"").lower()
    summary = {
        "length": len(data),
        "sha256_prefix": hashlib.sha256(data).hexdigest()[:12],
        "header_hex": data[:32].hex(),
        "flags": {
            "video": b"video" in searchable,
            "mp4": b".mp4" in searchable,
            "image": b"image" in searchable or b"img" in searchable,
            "emotion": b"emotion" in searchable,
            "file": b"file" in searchable,
            "dat": b".dat" in searchable,
        },
    }
    decoded = _zstd_decompress(data, zstd_library)
    if decoded is not None:
        searchable_decoded = decoded.lower() + decoded.replace(b"\x00", b"").lower()
        summary["zstd_decoded"] = {
            "length": len(decoded),
            "sha256_prefix": hashlib.sha256(decoded).hexdigest()[:12],
            "tags": sorted(set(
                item.decode("ascii", "ignore").casefold()
                for item in re.findall(rb"<([A-Za-z][A-Za-z0-9_]*)", decoded)
            ))[:30],
            "flags": {
                "video": b"video" in searchable_decoded,
                "mp4": b".mp4" in searchable_decoded,
                "image": b"image" in searchable_decoded or b"img" in searchable_decoded,
                "emotion": b"emotion" in searchable_decoded or b"emoji" in searchable_decoded,
                "file": b"file" in searchable_decoded,
            },
        }
    return summary


def _xml_attribute_presence(text: str) -> dict[str, object]:
    names = sorted(set(
        match.casefold() for match in re.findall(r"\b([A-Za-z][A-Za-z0-9_]*)\s*=", text)
    ))
    sensitive_lengths = {}
    for name in ("md5", "androidmd5", "cdnurl", "encrypturl", "thumburl", "aeskey"):
        match = re.search(rf'(?is)\b{name}\s*=\s*["\']([^"\']*)["\']', text)
        sensitive_lengths[name] = len(match.group(1)) if match else 0
    return {
        "attribute_names": names,
        "sensitive_value_lengths": sensitive_lengths,
        "values_printed": False,
    }


def _emoticon_aes_probe(text: str, paths: list[Path]) -> dict[str, object]:
    match = re.search(r'(?is)\baeskey\s*=\s*["\']([0-9a-f]{32})["\']', text)
    result = {"key_present": bool(match), "ecb_image_matches": 0, "keys_printed": False}
    if not match:
        return result
    key = bytearray.fromhex(match.group(1))
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        seen = set()
        for path in paths:
            try:
                data = path.read_bytes()
            except OSError:
                continue
            digest = hashlib.sha256(data).digest()
            if digest in seen or not data or len(data) % 16:
                continue
            seen.add(digest)
            decryptor = Cipher(algorithms.AES(bytes(key)), modes.ECB()).decryptor()
            decoded = decryptor.update(data) + decryptor.finalize()
            pad = decoded[-1]
            if 1 <= pad <= 16 and decoded[-pad:] == bytes([pad]) * pad:
                decoded = decoded[:-pad]
            header = decoded[:16]
            if (
                header.startswith((b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF8", b"BM"))
                or (header.startswith(b"RIFF") and header[8:12] == b"WEBP")
            ):
                result["ecb_image_matches"] = int(result["ecb_image_matches"]) + 1
    finally:
        key[:] = b"\x00" * len(key)
    return result


def diagnose(args: argparse.Namespace) -> dict[str, object]:
    sources = {
        "message": args.message_database,
        "session": args.session_database,
        "contact": args.contact_database,
    }
    with _auto_plaintext_bundle(
        sources, args.snapshot_dir, args.work_dir, args.time_budget,
        derive_image_key=False,
    ) as (plain, _snapshots, _image_key, _image_xor_key):
        dataset = ChatDataset(
            [plain["message"]], "weixin-4",
            session_database=plain["session"], contact_database=plain["contact"],
        )
        scope = ExportScope(
            args.conversation_id, args.start, args.end,
            include=frozenset(MessageKind),
        )
        resolver = MediaResolver(args.account_root, include_emoticons=True)
        index = resolver._media_index()
        rows = []
        conversation = dataset.resolve(args.conversation_id)
        connection = _connect(plain["message"])
        try:
            columns = _columns(connection, conversation.table)
            local_id_column = columns.get("local_id")
            raw_fields = ["source", "compress_content", "origin_source"]
            for message in dataset.iter_messages(scope, limit=1000):
                if message.kind not in {
                    MessageKind.IMAGE, MessageKind.VIDEO, MessageKind.EMOTICON,
                    MessageKind.FILE, MessageKind.LINK,
                }:
                    continue
                packed = message.metadata.get("packed_info")
                packed_bytes = bytes(packed) if isinstance(packed, bytes) else b""
                searchable = packed_bytes.lower() + packed_bytes.replace(b"\x00", b"").lower()
                extra = {}
                local_id = int(message.metadata.get("local_id") or 0)
                selected_fields = [columns.get(name) for name in raw_fields]
                if local_id_column and local_id and any(selected_fields):
                    expressions = [
                        _quote(name) if name else "NULL" for name in selected_fields
                    ]
                    raw_row = connection.execute(
                        f"SELECT {', '.join(expressions)} FROM {_quote(conversation.table)} "
                        f"WHERE {_quote(local_id_column)} = ? LIMIT 1", (local_id,),
                    ).fetchone()
                    if raw_row:
                        extra = {
                            name: _field_summary(value, args.zstd_library)
                            for name, value in zip(raw_fields, raw_row)
                        }
                candidates = resolver._candidates(message, index) if index is not None else []
                top_score = candidates[0][0] if candidates else None
                top = [path for score, path in candidates if score == top_score]
                rows.append({
                "timestamp_local": datetime.fromtimestamp(message.timestamp).isoformat(),
                "raw_type": message.type_code,
                "normalized_kind": message.kind.value,
                "content_length": len(message.content),
                "content_sha256_prefix": hashlib.sha256(
                    message.content.encode("utf-8", "surrogatepass")
                ).hexdigest()[:12],
                "xml_attribute_presence": _xml_attribute_presence(message.content),
                "emoticon_aes_probe": (
                    _emoticon_aes_probe(message.content, top)
                    if message.kind == MessageKind.EMOTICON else None
                ),
                "packed_info_length": len(packed_bytes),
                "metadata_flags": {
                    "video": b"video" in searchable,
                    "mp4": b".mp4" in searchable,
                    "image": b"image" in searchable or b"img" in searchable,
                    "emotion": b"emotion" in searchable,
                    "dat": b".dat" in searchable,
                },
                "candidate_count": len(candidates),
                "top_candidate_count": len(top),
                    "extra_fields": extra,
                    "top_candidates": [
                    {
                        "category": _path_category(path),
                        "suffix": path.suffix.casefold(),
                        "size": path.stat().st_size,
                        "header_kind": _header_kind(path),
                        "header_hex": _header_hex(path),
                    }
                    for path in top[:5]
                ],
                })
        finally:
            connection.close()
        return {
            "status": "redacted_scope_type_diagnostic",
            "rows": rows,
            "message_content_printed": False,
            "source_paths_printed": False,
            "keys_printed": False,
            "plaintext_retained": False,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--message-database", required=True, type=Path)
    parser.add_argument("--session-database", required=True, type=Path)
    parser.add_argument("--contact-database", required=True, type=Path)
    parser.add_argument("--account-root", required=True, type=Path)
    parser.add_argument("--snapshot-dir", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--conversation-id", required=True)
    parser.add_argument("--start", required=True, type=int)
    parser.add_argument("--end", required=True, type=int)
    parser.add_argument("--time-budget", type=float, default=25.0)
    parser.add_argument("--zstd-library", type=Path)
    parser.add_argument("--confirm-read-process-memory", action="store_true")
    parser.add_argument("--confirm-read-selected-message-metadata", action="store_true")
    args = parser.parse_args()
    if not (
        args.confirm_read_process_memory
        and args.confirm_read_selected_message_metadata
    ):
        raise SystemExit("explicit read-only confirmations are required")
    print(json.dumps(diagnose(args), ensure_ascii=False, indent=2))
