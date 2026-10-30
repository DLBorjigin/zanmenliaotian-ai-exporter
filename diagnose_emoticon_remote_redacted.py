from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

from wechat_ai_exporter.chat_data import ChatDataset
from wechat_ai_exporter.cli import _auto_plaintext_bundle
from wechat_ai_exporter.media import _allowed_remote_media_host, _detect_image
from wechat_ai_exporter.models import ExportScope, MessageKind


def _probe_blob(data: bytes, key: bytearray | None) -> dict[str, object]:
    direct = _detect_image(data)
    result: dict[str, object] = {
        "size": len(data),
        "sha256_prefix": hashlib.sha256(data).hexdigest()[:12],
        "header_hex": data[:16].hex(),
        "direct_image": direct[1] if direct else None,
        "aes_ecb_image": None,
    }
    if key is None or not data or len(data) % 16:
        return result
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        decryptor = Cipher(algorithms.AES(bytes(key)), modes.ECB()).decryptor()
        decoded = decryptor.update(data) + decryptor.finalize()
        pad = decoded[-1]
        if 1 <= pad <= 16 and decoded[-pad:] == bytes([pad]) * pad:
            decoded = decoded[:-pad]
        detected = _detect_image(decoded)
        if detected:
            result["aes_ecb_image"] = detected[1]
            result["aes_ecb_size"] = len(decoded)
            result["aes_ecb_sha256_prefix"] = hashlib.sha256(decoded).hexdigest()[:12]
    except (ImportError, ValueError):
        pass
    return result


def diagnose(args: argparse.Namespace) -> dict[str, object]:
    sources = {
        "message": args.message_database,
        "session": args.session_database,
        "contact": args.contact_database,
    }
    rows = []
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
            include=frozenset({MessageKind.EMOTICON}),
        )
        for message in dataset.iter_messages(scope, limit=20):
            text = html.unescape(message.content)
            key_match = re.search(r'(?is)\baeskey\s*=\s*["\']([0-9a-f]{32})["\']', text)
            key = bytearray.fromhex(key_match.group(1)) if key_match else None
            try:
                for name in (
                    "cdnurl", "tpurl", "externurl", "thumburl", "cdnthumburl", "encrypturl"
                ):
                    match = re.search(rf'(?is)\b{name}\s*=\s*["\']([^"\']+)["\']', text)
                    if not match:
                        continue
                    raw_url = match.group(1).strip()
                    parsed = urllib.parse.urlsplit(raw_url)
                    hostname = (parsed.hostname or "").casefold()
                    item: dict[str, object] = {
                        "field": name,
                        "url_length": len(raw_url),
                        "hostname": hostname,
                        "host_allowed": _allowed_remote_media_host(hostname),
                        "url_printed": False,
                    }
                    if not item["host_allowed"] or parsed.scheme not in {"http", "https"}:
                        rows.append(item)
                        continue
                    if parsed.scheme == "http":
                        parsed = parsed._replace(scheme="https")
                    try:
                        request = urllib.request.Request(
                            urllib.parse.urlunsplit(parsed),
                            headers={"User-Agent": "wechat-ai-exporter/1"},
                        )
                        with urllib.request.urlopen(request, timeout=20) as response:
                            data = response.read(args.max_bytes + 1)
                            item["http_status"] = getattr(response, "status", None)
                            item["final_host_allowed"] = _allowed_remote_media_host(
                                (urllib.parse.urlsplit(response.geturl()).hostname or "").casefold()
                            )
                            item["content_type"] = response.headers.get("Content-Type", "")[:80]
                        item.update(_probe_blob(data, key))
                    except (OSError, ValueError, urllib.error.URLError) as exc:
                        item["error_type"] = type(exc).__name__
                    rows.append(item)
            finally:
                if key is not None:
                    key[:] = b"\x00" * len(key)
    return {
        "status": "redacted_emoticon_remote_diagnostic",
        "rows": rows,
        "urls_printed": False,
        "keys_printed": False,
        "message_content_printed": False,
        "plaintext_retained": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--message-database", required=True, type=Path)
    parser.add_argument("--session-database", required=True, type=Path)
    parser.add_argument("--contact-database", required=True, type=Path)
    parser.add_argument("--snapshot-dir", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--conversation-id", required=True)
    parser.add_argument("--start", required=True, type=int)
    parser.add_argument("--end", required=True, type=int)
    parser.add_argument("--time-budget", type=float, default=25.0)
    parser.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--confirm-read-process-memory", action="store_true")
    parser.add_argument("--confirm-read-selected-message-metadata", action="store_true")
    parser.add_argument("--confirm-remote-media-download", action="store_true")
    args = parser.parse_args()
    if not (
        args.confirm_read_process_memory
        and args.confirm_read_selected_message_metadata
        and args.confirm_remote_media_download
    ):
        raise SystemExit("all explicit confirmations are required")
    print(json.dumps(diagnose(args), ensure_ascii=False, indent=2))
