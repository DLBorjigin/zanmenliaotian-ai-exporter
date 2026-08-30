from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import html
import os
from pathlib import Path
import re
import shutil
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

from .chat_data import _columns, _connect, _quote, _tables
from .models import MessageKind, NormalizedMessage


V1_MAGIC = b"\x07\x08V1\x08\x07"
V2_MAGIC = b"\x07\x08V2\x08\x07"
V2_HEADER_SIZE = 15
IMAGE_MAGICS = (
    (b"\xff\xd8\xff", ".jpg", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", ".png", "image/png"),
    (b"GIF8", ".gif", "image/gif"),
    (b"BM", ".bmp", "image/bmp"),
    (b"II*\x00", ".tif", "image/tiff"),
)

ASSET_KIND_DIRECTORIES = {
    MessageKind.IMAGE: "images",
    MessageKind.VIDEO: "videos",
    MessageKind.AUDIO: "audio",
    MessageKind.FILE: "files",
    MessageKind.EMOTICON: "emoticons",
}


@dataclass(frozen=True)
class AssetRecord:
    id: str
    message_id: str
    kind: str
    status: str
    relative_path: str | None = None
    media_type: str | None = None
    size: int | None = None
    sha256: str | None = None
    original_name: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(value: str, fallback: str) -> str:
    name = Path(value.replace("\\", "/")).name
    name = re.sub(r"[\x00-\x1f<>:\"/\\|?*]+", "_", name).strip(" .")
    return name[:180] or fallback


def _detect_image(data: bytes) -> tuple[str, str] | None:
    for magic, extension, media_type in IMAGE_MAGICS:
        if data.startswith(magic):
            return extension, media_type
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return ".webp", "image/webp"
    if data.startswith(b"wxgf"):
        return ".wxgf", "application/x-wechat-wxgf"
    return None


def _allowed_remote_media_host(hostname: str) -> bool:
    hostname = hostname.casefold().rstrip(".")
    return (
        hostname == "qpic.cn" or hostname.endswith(".qpic.cn")
        or hostname == "weixin.qq.com" or hostname.endswith(".weixin.qq.com")
        or hostname == "wxapp.tc.qq.com"
    )


def _asset_dir(assets_root: Path, message: NormalizedMessage) -> Path:
    category = ASSET_KIND_DIRECTORIES.get(message.kind, "other")
    return assets_root / category / message.id


def decode_legacy_xor(data: bytes) -> tuple[bytes, str, str] | None:
    if len(data) < 12:
        return None
    for magic, extension, media_type in IMAGE_MAGICS:
        key = data[0] ^ magic[0]
        if bytes(value ^ key for value in data[:len(magic)]) == magic:
            decoded = bytes(value ^ key for value in data)
            return decoded, extension, media_type
    for magic in (b"RIFF",):
        key = data[0] ^ magic[0]
        decoded_header = bytes(value ^ key for value in data[:12])
        if decoded_header.startswith(b"RIFF") and decoded_header[8:12] == b"WEBP":
            return bytes(value ^ key for value in data), ".webp", "image/webp"
    return None


def _derive_v2_xor_key(source: Path) -> int | None:
    for candidate in (source.with_name(source.stem + "_t.dat"),
                      source.with_name(source.stem + "_h.dat"), source):
        try:
            with candidate.open("rb") as handle:
                handle.seek(-2, os.SEEK_END)
                tail = handle.read(2)
        except OSError:
            continue
        if len(tail) == 2:
            key = tail[0] ^ 0xFF
            if tail[1] ^ 0xD9 == key:
                return key
    return None


def decrypt_v2_image(data: bytes, aes_key: bytes | bytearray,
                     xor_key: int | None) -> bytes:
    if len(aes_key) != 16:
        raise ValueError("invalid V2 AES key length")
    if len(data) < V2_HEADER_SIZE or not data.startswith(V2_MAGIC):
        raise ValueError("invalid V2 image header")
    aes_size = int.from_bytes(data[6:10], "little")
    xor_size = int.from_bytes(data[10:14], "little")
    aes_block_size = aes_size + (16 - aes_size % 16) if aes_size % 16 else aes_size + 16
    if aes_block_size <= 0 or V2_HEADER_SIZE + aes_block_size + xor_size > len(data):
        raise ValueError("invalid V2 image segment sizes")
    if xor_size and xor_key is None:
        raise ValueError("V2 XOR key is unavailable")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    start = V2_HEADER_SIZE
    decryptor = Cipher(algorithms.AES(bytes(aes_key)), modes.ECB()).decryptor()
    padded = decryptor.update(data[start:start + aes_block_size]) + decryptor.finalize()
    pad = padded[-1]
    if not 1 <= pad <= 16 or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("V2 AES key validation failed")
    first = padded[:-pad]
    raw_start = start + aes_block_size
    raw_end = len(data) - xor_size if xor_size else len(data)
    raw = data[raw_start:raw_end]
    tail = data[raw_end:]
    decoded_tail = bytes(value ^ int(xor_key) for value in tail) if tail else b""
    output = first + raw + decoded_tail
    if _detect_image(output) is None:
        raise ValueError("V2 key produced an unsupported image signature")
    return output


class MediaIndex:
    def __init__(self, account_root: Path, max_files: int = 200_000,
                 time_budget_seconds: float = 15.0,
                 include_emoticons: bool = False) -> None:
        self.account_root = account_root.resolve(strict=True)
        self.max_files = max_files
        self.time_budget_seconds = time_budget_seconds
        self.include_emoticons = include_emoticons
        self.by_name: dict[str, list[Path]] = {}
        self.by_token: dict[str, list[Path]] = {}
        self.files_scanned = 0
        self.timed_out = False
        self._build()

    def _build(self) -> None:
        roots = [
            self.account_root / name
            for name in ("msg", "resource", "FileStorage", "MsgAttach", "CustomEmotion")
            if (self.account_root / name).is_dir()
        ]
        emoticon_root = self.account_root / "business" / "emoticon"
        if self.include_emoticons and emoticon_root.is_dir():
            roots.append(emoticon_root)
        cache_root = self.account_root / "cache"
        if self.include_emoticons and cache_root.is_dir():
            roots.append(cache_root)
        started = time.monotonic()
        for root in roots:
            for current, directories, files in os.walk(root, followlinks=False):
                directories[:] = [
                    name for name in directories
                    if name.casefold() not in {"cache", "temp", ".git"}
                    and not (Path(current) / name).is_symlink()
                ]
                for filename in files:
                    if self.files_scanned >= self.max_files or time.monotonic() - started >= self.time_budget_seconds:
                        self.timed_out = True
                        return
                    path = Path(current) / filename
                    self.files_scanned += 1
                    self.by_name.setdefault(filename.casefold(), []).append(path)
                    for token in re.findall(r"(?i)[0-9a-f]{16,64}", filename):
                        self.by_token.setdefault(token.casefold(), []).append(path)

    def authorized(self, path: Path) -> bool:
        try:
            return path.resolve(strict=True).is_relative_to(self.account_root)
        except (OSError, ValueError):
            return False


class MediaResolver:
    def __init__(self, account_root: Path | None = None,
                 media_databases: list[Path] | None = None,
                 max_asset_bytes: int = 512 * 1024 * 1024,
                 image_aes_key: bytearray | None = None,
                 image_xor_key: int | None = None,
                 include_emoticons: bool = False,
                 allow_remote_media_download: bool = False) -> None:
        self.account_root = Path(account_root) if account_root else None
        self.media_databases = [Path(item) for item in (media_databases or [])]
        self.max_asset_bytes = max_asset_bytes
        self.image_aes_key = image_aes_key
        self.image_xor_key = image_xor_key
        self.include_emoticons = include_emoticons
        self.allow_remote_media_download = allow_remote_media_download
        self._index: MediaIndex | None = None

    def _media_index(self) -> MediaIndex | None:
        if self.account_root is None:
            return None
        if self._index is None:
            self._index = MediaIndex(
                self.account_root, include_emoticons=self.include_emoticons
            )
        return self._index

    def resolve(self, message: NormalizedMessage, assets_root: Path) -> list[AssetRecord]:
        if message.kind == MessageKind.AUDIO:
            voice = self._resolve_voice(message, assets_root)
            if voice is not None:
                return [voice]
        if message.kind not in {
            MessageKind.IMAGE, MessageKind.VIDEO, MessageKind.AUDIO,
            MessageKind.FILE, MessageKind.EMOTICON,
        }:
            return []
        index = self._media_index()
        if index is None:
            return [self._status(message, "media_root_unavailable")]
        candidates = self._candidates(message, index)
        if not candidates:
            return [self._status(message, "not_found")]
        top_score = candidates[0][0]
        top = sorted({path for score, path in candidates if score == top_score})
        if len(top) > 1 and self._all_files_identical(top):
            top = [top[0]]
        if len(top) != 1:
            return [self._status(message, "ambiguous_match")]
        primary = self._package_path(message, top[0], assets_root)
        if (
            message.kind == MessageKind.EMOTICON
            and self.allow_remote_media_download
            and primary.status in {"unsupported_emoticon_format", "unsupported_dat_format"}
        ):
            remote = self._package_remote_emoticon(message, assets_root)
            if remote is not None:
                primary = remote
        records = [primary]
        if (
            primary.status == "packaged_opaque"
            and message.kind in {MessageKind.IMAGE, MessageKind.EMOTICON}
            and top[0].suffix.casefold() == ".dat"
        ):
            preview = self._package_v2_preview(message, top[0], assets_root)
            if preview is not None:
                records.append(preview)
        return records

    @staticmethod
    def _all_files_identical(paths: list[Path]) -> bool:
        fingerprints = set()
        for path in paths:
            try:
                fingerprints.add((path.stat().st_size, _hash_file(path)))
            except OSError:
                return False
        return len(fingerprints) == 1

    def _status(self, message: NormalizedMessage, status: str,
                original_name: str | None = None) -> AssetRecord:
        return AssetRecord(
            id=f"asset-{message.id.removeprefix('message-')}", message_id=message.id,
            kind=message.kind.value, status=status, original_name=original_name,
        )

    def _metadata_text(self, message: NormalizedMessage) -> str:
        pieces = [message.content]
        for name in ("source", "compress_content", "origin_source"):
            value = message.metadata.get(name)
            if value:
                pieces.append(str(value))
        raw = message.metadata.get("packed_info")
        if isinstance(raw, bytes):
            for chunk in re.findall(rb"[\x20-\x7e]{4,}", raw):
                pieces.append(chunk.decode("ascii", "ignore"))
            try:
                pieces.append(raw.decode("utf-16le"))
            except UnicodeDecodeError:
                pass
        elif raw is not None:
            pieces.append(str(raw))
        return "\n".join(pieces)

    def _candidates(self, message: NormalizedMessage,
                    index: MediaIndex) -> list[tuple[int, Path]]:
        text = self._metadata_text(message)
        scores: dict[Path, int] = {}
        filenames = set()
        for field in ("title", "filename", "file_name", "path", "thumbpath", "bigimgpath"):
            filenames.update(
                match.strip() for match in re.findall(
                    rf"(?is)<{field}>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</{field}>", text
                ) if match.strip()
            )
        for path_text in re.findall(
            r"(?i)(?:[a-z]:[\\/]|(?:msg|resource|filestorage)[\\/])[^\x00\r\n<>|?*]+", text
        ):
            candidate = Path(path_text)
            if not candidate.is_absolute():
                candidate = index.account_root / path_text.replace("\\", os.sep)
            if candidate.is_file() and index.authorized(candidate):
                scores[candidate] = max(scores.get(candidate, 0), 120)
            filenames.add(Path(path_text.replace("\\", "/")).name)
        for filename in filenames:
            for path in index.by_name.get(Path(filename).name.casefold(), []):
                scores[path] = max(scores.get(path, 0), 100)
        tokens = set(match.casefold() for match in re.findall(r"(?i)[0-9a-f]{16,64}", text))
        for token in tokens:
            for path in index.by_token.get(token, []):
                scores[path] = max(scores.get(path, 0), 80)
        for path in list(scores):
            lowered = str(path).casefold()
            bonus = 0
            if message.kind in {MessageKind.IMAGE, MessageKind.EMOTICON} and any(
                part in lowered for part in ("\\img\\", "/img/", "attach", "emotion")
            ):
                bonus += 10
            if message.kind == MessageKind.VIDEO and "video" in lowered:
                bonus += 10
            if message.kind == MessageKind.VIDEO and path.suffix.casefold() in {
                ".mp4", ".mov", ".m4v", ".avi", ".mkv",
            }:
                bonus += 15
            if message.kind == MessageKind.VIDEO and path.suffix.casefold() in {
                ".jpg", ".jpeg", ".png", ".webp",
            }:
                bonus -= 3
            if message.kind == MessageKind.FILE and "file" in lowered:
                bonus += 10
            if message.kind == MessageKind.IMAGE and "_h.dat" in lowered:
                bonus += 3
            if message.kind == MessageKind.IMAGE and "_t.dat" in lowered:
                bonus -= 2
            if message.kind == MessageKind.EMOTICON and (
                path.suffix.casefold() == ".thumb" or "thumb" in path.name.casefold()
            ):
                bonus -= 3
            scores[path] += bonus
        return sorted(((score, path) for path, score in scores.items()), key=lambda item: (-item[0], str(item[1])))

    def _package_path(self, message: NormalizedMessage, source: Path,
                      assets_root: Path) -> AssetRecord:
        try:
            size = source.stat().st_size
        except OSError:
            return self._status(message, "not_found")
        if size > self.max_asset_bytes:
            return self._status(message, "size_limit_exceeded", source.name)
        asset_dir = _asset_dir(assets_root, message)
        asset_dir.mkdir(parents=True, exist_ok=True)
        if source.suffix.casefold() == ".dat":
            data = source.read_bytes()
            if data.startswith((V1_MAGIC, V2_MAGIC)):
                version = "v1" if data.startswith(V1_MAGIC) else "v2"
                if version == "v1":
                    return self._status(message, "image_v1_key_required", source.name)
                if self.image_aes_key is None:
                    return self._status(message, "image_v2_key_required", source.name)
                xor_key = self.image_xor_key
                if xor_key is None:
                    xor_key = _derive_v2_xor_key(source)
                try:
                    decoded = decrypt_v2_image(data, self.image_aes_key, xor_key)
                except (ValueError, ImportError):
                    return self._status(message, "image_v2_key_invalid_or_xor_unavailable", source.name)
                detected = _detect_image(decoded)
                assert detected is not None
                extension, media_type = detected
                name = _safe_name(source.stem + extension, message.id + extension)
                target = asset_dir / name
                target.write_bytes(decoded)
                status = "packaged_opaque" if extension == ".wxgf" else "packaged"
                return AssetRecord(
                    id=f"asset-{message.id.removeprefix('message-')}", message_id=message.id,
                    kind=message.kind.value, status=status, relative_path=target.relative_to(assets_root.parent).as_posix(),
                    media_type=media_type, size=len(decoded), sha256=_hash_bytes(decoded),
                    original_name=source.name,
                )
            detected = _detect_image(data)
            if detected:
                extension, media_type = detected
                decoded = data
            else:
                xor_result = decode_legacy_xor(data)
                if xor_result is None:
                    return self._status(message, "unsupported_dat_format", source.name)
                decoded, extension, media_type = xor_result
            name = _safe_name(source.stem + extension, message.id + extension)
            target = asset_dir / name
            target.write_bytes(decoded)
            relative = target.relative_to(assets_root.parent).as_posix()
            status = "packaged_opaque" if extension == ".wxgf" else "packaged"
            return AssetRecord(
                id=f"asset-{_hash_bytes(decoded)[:12]}", message_id=message.id,
                kind=message.kind.value, status=status, relative_path=relative,
                media_type=media_type, size=len(decoded), sha256=_hash_bytes(decoded),
                original_name=source.name,
            )
        name = _safe_name(source.name, message.id + source.suffix)
        try:
            with source.open("rb") as handle:
                detected = _detect_image(handle.read(16))
        except OSError:
            detected = None
        if message.kind == MessageKind.EMOTICON and detected is None:
            return self._status(message, "unsupported_emoticon_format", source.name)
        target = asset_dir / name
        shutil.copy2(source, target)
        relative = target.relative_to(assets_root.parent).as_posix()
        status = "packaged"
        media_type = detected[1] if detected else None
        if message.kind == MessageKind.VIDEO and detected is not None:
            status = "packaged_thumbnail_only"
        elif message.kind == MessageKind.VIDEO and source.suffix.casefold() in {
            ".mp4", ".m4v", ".mov",
        }:
            media_type = "video/mp4"
        return AssetRecord(
            id=f"asset-{_hash_file(target)[:12]}", message_id=message.id,
            kind=message.kind.value, status=status, relative_path=relative,
            media_type=media_type, size=target.stat().st_size, sha256=_hash_file(target),
            original_name=source.name,
        )

    def _package_remote_emoticon(
        self, message: NormalizedMessage, assets_root: Path
    ) -> AssetRecord | None:
        text = html.unescape(self._metadata_text(message))
        urls = []
        for name in ("cdnurl", "tpurl", "externurl", "thumburl", "cdnthumburl"):
            match = re.search(rf'(?is)\b{name}\s*=\s*["\']([^"\']+)["\']', text)
            if match:
                urls.append(match.group(1).strip())
        for raw_url in urls:
            try:
                parsed = urllib.parse.urlsplit(raw_url)
                hostname = (parsed.hostname or "").casefold()
                if parsed.scheme not in {"http", "https"} or not _allowed_remote_media_host(hostname):
                    continue
                if parsed.scheme == "http":
                    parsed = parsed._replace(scheme="https")
                url = urllib.parse.urlunsplit(parsed)
                request = urllib.request.Request(
                    url, headers={"User-Agent": "wechat-ai-exporter/1"}
                )
                with urllib.request.urlopen(request, timeout=15) as response:
                    final_host = (urllib.parse.urlsplit(response.geturl()).hostname or "").casefold()
                    if not _allowed_remote_media_host(final_host):
                        continue
                    declared = response.headers.get("Content-Length")
                    if declared and int(declared) > self.max_asset_bytes:
                        continue
                    data = response.read(self.max_asset_bytes + 1)
                if len(data) > self.max_asset_bytes:
                    continue
                detected = _detect_image(data)
                if detected is None or detected[0] == ".wxgf":
                    continue
                extension, media_type = detected
                asset_dir = _asset_dir(assets_root, message)
                asset_dir.mkdir(parents=True, exist_ok=True)
                target = asset_dir / _safe_name(
                    message.id + "_emoticon" + extension,
                    message.id + extension,
                )
                target.write_bytes(data)
                return AssetRecord(
                    id=f"asset-{_hash_bytes(data)[:12]}", message_id=message.id,
                    kind=message.kind.value, status="packaged_remote",
                    relative_path=target.relative_to(assets_root.parent).as_posix(),
                    media_type=media_type, size=len(data), sha256=_hash_bytes(data),
                    original_name=None,
                )
            except (OSError, ValueError, urllib.error.URLError):
                continue
        return None

    def _package_v2_preview(
        self, message: NormalizedMessage, source: Path, assets_root: Path
    ) -> AssetRecord | None:
        if self.image_aes_key is None:
            return None
        index = self._media_index()
        for suffix in ("_t.dat", "_h.dat"):
            preview_source = source.with_name(source.stem + suffix)
            if (
                not preview_source.is_file()
                or index is None
                or not index.authorized(preview_source)
            ):
                continue
            try:
                encoded = preview_source.read_bytes()
                xor_key = _derive_v2_xor_key(preview_source) or self.image_xor_key
                decoded = decrypt_v2_image(encoded, self.image_aes_key, xor_key)
            except (OSError, ValueError, ImportError):
                continue
            detected = _detect_image(decoded)
            if detected is None or detected[0] == ".wxgf":
                continue
            extension, media_type = detected
            asset_dir = _asset_dir(assets_root, message)
            asset_dir.mkdir(parents=True, exist_ok=True)
            target = asset_dir / _safe_name(
                source.stem + "_preview" + extension,
                message.id + "_preview" + extension,
            )
            target.write_bytes(decoded)
            return AssetRecord(
                id=f"asset-{_hash_bytes(decoded)[:12]}-preview",
                message_id=message.id, kind=message.kind.value,
                status="packaged_preview",
                relative_path=target.relative_to(assets_root.parent).as_posix(),
                media_type=media_type, size=len(decoded),
                sha256=_hash_bytes(decoded), original_name=preview_source.name,
            )
        return None

    def _resolve_voice(self, message: NormalizedMessage,
                       assets_root: Path) -> AssetRecord | None:
        matches: list[bytes] = []
        local_id = int(message.metadata.get("local_id") or 0)
        server_id = int(message.metadata.get("server_id") or 0)
        for database in self.media_databases:
            connection = _connect(database)
            try:
                table = _tables(connection).get("voiceinfo")
                if not table:
                    continue
                columns = _columns(connection, table)
                voice = columns.get("voice_data")
                if not voice:
                    continue
                clauses = []
                parameters: list[object] = []
                if local_id and columns.get("local_id"):
                    clauses.append(f"{_quote(columns['local_id'])} = ?")
                    parameters.append(local_id)
                server_column = columns.get("svr_id") or columns.get("server_id")
                if server_id and server_column:
                    clauses.append(f"{_quote(server_column)} = ?")
                    parameters.append(server_id)
                if not clauses:
                    continue
                rows = connection.execute(
                    f"SELECT {_quote(voice)} FROM {_quote(table)} WHERE {' AND '.join(clauses)} LIMIT 2",
                    parameters,
                ).fetchall()
                matches.extend(bytes(row[0]) for row in rows if isinstance(row[0], bytes))
            finally:
                connection.close()
        unique = {hashlib.sha256(item).digest(): item for item in matches}
        if not unique:
            return None
        if len(unique) != 1:
            return self._status(message, "ambiguous_voice_match")
        data = next(iter(unique.values()))
        if data.startswith(b"\x02#!SILK_V3"):
            data = data[1:]
        status = "packaged_requires_conversion"
        extension = ".silk" if data.startswith(b"#!SILK_V3") else ".bin"
        media_type = "audio/silk" if extension == ".silk" else "application/octet-stream"
        asset_dir = _asset_dir(assets_root, message)
        asset_dir.mkdir(parents=True, exist_ok=True)
        target = asset_dir / f"voice{extension}"
        target.write_bytes(data)
        relative = target.relative_to(assets_root.parent).as_posix()
        return AssetRecord(
            id=f"asset-{_hash_bytes(data)[:12]}", message_id=message.id,
            kind=message.kind.value, status=status, relative_path=relative,
            media_type=media_type, size=len(data), sha256=_hash_bytes(data),
            original_name=None,
        )
