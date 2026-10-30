from __future__ import annotations

import argparse
import base64
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
from wechat_ai_exporter.media import (
    MediaResolver,
    _allowed_remote_media_host,
    _decrypt_aes_ecb_media,
    _detect_video,
)
from wechat_ai_exporter.models import ExportScope, MessageKind


def diagnose(args: argparse.Namespace) -> dict[str, object]:
    sources = {
        "message": args.message_database,
        "session": args.session_database,
        "contact": args.contact_database,
    }
    rows: list[dict[str, object]] = []
    message_count = 0
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
            include=frozenset({MessageKind.VIDEO}),
        )
        resolver = MediaResolver()
        for message in dataset.iter_messages(scope, limit=20):
            message_count += 1
            text = html.unescape(resolver._metadata_text(message))
            key_values: list[bytearray] = []
            key_fields: list[dict[str, object]] = []
            for name in ("aeskey", "cdnrawvideoaeskey"):
                match = re.search(rf'(?is)\b{name}\s*=\s*["\']([^"\']*)["\']', text)
                if not match:
                    continue
                value = match.group(1).strip()
                key_fields.append({
                    "field": name,
                    "length": len(value),
                    "hex": bool(re.fullmatch(r"[0-9a-fA-F]+", value)),
                })
                if len(value) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", value):
                    candidate = bytearray.fromhex(value)
                    if not any(candidate == prior for prior in key_values):
                        key_values.append(candidate)
            try:
                for name in ("cdnvideourl", "cdnrawvideourl"):
                    match = re.search(rf'(?is)\b{name}\s*=\s*["\']([^"\']+)["\']', text)
                    if not match:
                        continue
                    raw_url = match.group(1).strip()
                    parsed = urllib.parse.urlsplit(raw_url)
                    hostname = (parsed.hostname or "").casefold()
                    item: dict[str, object] = {
                        "field": name,
                        "url_length": len(raw_url),
                        "scheme": parsed.scheme,
                        "hostname": hostname,
                        "host_allowed": _allowed_remote_media_host(hostname),
                        "key_fields": key_fields,
                        "url_printed": False,
                        "looks_hex": bool(re.fullmatch(r"[0-9a-fA-F]+", raw_url)),
                        "looks_base64": False,
                        "contains_percent_escapes": bool(re.search(r"%[0-9a-fA-F]{2}", raw_url)),
                    }
                    try:
                        decoded_token = base64.b64decode(raw_url, validate=True)
                        item["looks_base64"] = bool(decoded_token)
                        item["base64_decoded_length"] = len(decoded_token)
                        item["base64_decoded_has_http"] = b"http" in decoded_token.lower()
                    except (ValueError, TypeError):
                        pass
                    if item["looks_hex"] and len(raw_url) % 2 == 0:
                        decoded_hex = bytes.fromhex(raw_url)
                        item["hex_decoded_length"] = len(decoded_hex)
                        item["hex_decoded_has_http"] = b"http" in decoded_hex.lower()
                        item["hex_decoded_printable_ratio"] = round(
                            sum(32 <= value <= 126 for value in decoded_hex)
                            / max(1, len(decoded_hex)), 3
                        )
                        hosts = re.findall(
                            rb"(?i)(?:https?://)?([a-z0-9.-]+\.(?:qq\.com|qpic\.cn|weixin\.qq\.com))",
                            decoded_hex,
                        )
                        item["hex_decoded_hosts"] = sorted({
                            host.decode("ascii", "ignore").casefold() for host in hosts
                        })
                        derived_tests = []
                        for encoding, parameter in (
                            ("hex", raw_url),
                            ("base64_der", base64.b64encode(decoded_hex).decode("ascii")),
                        ):
                            derived: dict[str, object] = {"encoding": encoding}
                            endpoint = (
                                "https://novac2c.cdn.weixin.qq.com/c2c/download?"
                                + urllib.parse.urlencode({"encrypted_query_param": parameter})
                            )
                            try:
                                request = urllib.request.Request(
                                    endpoint, headers={"User-Agent": "wechat-ai-exporter/1"}
                                )
                                with urllib.request.urlopen(request, timeout=20) as response:
                                    data = response.read(args.max_bytes + 1)
                                    derived["http_status"] = getattr(response, "status", None)
                                    derived["final_hostname"] = (
                                        urllib.parse.urlsplit(response.geturl()).hostname or ""
                                    ).casefold()
                                    derived["content_type"] = response.headers.get(
                                        "Content-Type", ""
                                    )[:80]
                                derived["size"] = len(data)
                                direct_video = _detect_video(data)
                                derived["direct_video"] = (
                                    direct_video[1] if direct_video else None
                                )
                                decrypted_video = None
                                for key in key_values:
                                    decoded = _decrypt_aes_ecb_media(data, key)
                                    detected = _detect_video(decoded or b"")
                                    if detected:
                                        decrypted_video = detected[1]
                                        break
                                derived["aes_ecb_video"] = decrypted_video
                            except (OSError, ValueError, urllib.error.URLError) as exc:
                                derived["error_type"] = type(exc).__name__
                                derived["error_code"] = getattr(exc, "code", None)
                            derived_tests.append(derived)
                        item["derived_cdn_tests"] = derived_tests
                    if parsed.scheme not in {"http", "https"} or not item["host_allowed"]:
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
                            item["final_hostname"] = (
                                urllib.parse.urlsplit(response.geturl()).hostname or ""
                            ).casefold()
                            item["content_type"] = response.headers.get("Content-Type", "")[:80]
                        item["size"] = len(data)
                        item["sha256_prefix"] = hashlib.sha256(data).hexdigest()[:12]
                        item["header_hex"] = data[:16].hex()
                        direct = _detect_video(data)
                        item["direct_video"] = direct[1] if direct else None
                        item["block_aligned"] = bool(data) and len(data) % 16 == 0
                        decrypted = None
                        for key in key_values:
                            decoded = _decrypt_aes_ecb_media(data, key)
                            detected = _detect_video(decoded or b"")
                            if detected:
                                decrypted = {
                                    "media_type": detected[1],
                                    "size": len(decoded or b""),
                                    "sha256_prefix": hashlib.sha256(decoded or b"").hexdigest()[:12],
                                }
                                break
                        item["aes_ecb_video"] = decrypted
                    except (OSError, ValueError, urllib.error.URLError) as exc:
                        item["error_type"] = type(exc).__name__
                        item["error_code"] = getattr(exc, "code", None)
                    rows.append(item)
            finally:
                for key in key_values:
                    key[:] = b"\x00" * len(key)
    return {
        "status": "redacted_video_remote_diagnostic",
        "message_count": message_count,
        "rows": rows,
        "urls_printed": False,
        "keys_printed": False,
        "message_content_printed": False,
        "response_bodies_retained": False,
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
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
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
