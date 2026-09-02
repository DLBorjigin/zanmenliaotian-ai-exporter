from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import html
import os
from pathlib import Path
import re
import shutil
import sqlite3
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
VIDEO_ASSET_CHOICES = frozenset({"original", "thumbnail", "both"})

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


def _detect_video(data: bytes) -> tuple[str, str] | None:
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return ".mp4", "video/mp4"
    if data.startswith(b"\x1a\x45\xdf\xa3"):
        return ".mkv", "video/x-matroska"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"AVI ":
        return ".avi", "video/x-msvideo"
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


def _decrypt_aes_ecb_media(data: bytes, key: bytes | bytearray) -> bytes | None:
    if len(key) != 16 or not data or len(data) % 16:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        decryptor = Cipher(algorithms.AES(bytes(key)), modes.ECB()).decryptor()
        decoded = decryptor.update(data) + decryptor.finalize()
    except (ImportError, ValueError):
        return None
    pad = decoded[-1]
    if not 1 <= pad <= 16 or decoded[-pad:] != bytes([pad]) * pad:
        return None
    return decoded[:-pad]


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
    def __init__(self, account_root: Path,
                 include_emoticons: bool = False) -> None:
        self.account_root = account_root.resolve(strict=True)
        self.include_emoticons = include_emoticons
        self.by_name: dict[str, list[Path]] = {}
        self.by_token: dict[str, list[Path]] = {}
        self.files_scanned = 0
        self._scanned_roots: set[Path] = set()
        self.last_query_complete = True

    @staticmethod
    def _deduplicate_roots(roots: list[Path]) -> list[Path]:
        result: list[Path] = []
        for root in roots:
            try:
                resolved = root.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_dir() or resolved in result:
                continue
            result.append(resolved)
        return result

    def _roots_for(self, message: NormalizedMessage) -> tuple[list[Path], list[Path]]:
        month = datetime.fromtimestamp(message.timestamp).strftime("%Y-%m")
        table = str(message.metadata.get("table") or "")
        shard_match = re.fullmatch(r"(?i)Msg_([0-9a-f]{32})", table)
        shard = shard_match.group(1).casefold() if shard_match else None
        msg = self.account_root / "msg"
        cache = self.account_root / "cache"
        preferred: list[Path] = []
        fallback: list[Path] = []
        if message.kind == MessageKind.IMAGE:
            if shard:
                preferred.extend((
                    msg / "attach" / shard,
                    cache / month / "Message" / shard,
                    self.account_root / "MsgAttach" / shard,
                ))
            fallback.extend((
                msg / "attach", self.account_root / "resource",
                self.account_root / "FileStorage" / "Image",
            ))
        elif message.kind == MessageKind.VIDEO:
            preferred.append(msg / "video" / month)
            if shard:
                preferred.extend((
                    msg / "attach" / shard,
                    cache / month / "Message" / shard,
                ))
            fallback.extend((msg / "video", msg / "attach"))
        elif message.kind == MessageKind.FILE:
            preferred.append(msg / "file" / month)
            if shard:
                preferred.extend((
                    msg / "attach" / shard,
                    cache / month / "Message" / shard,
                ))
            fallback.extend((
                msg / "file", msg / "attach",
                self.account_root / "FileStorage" / "File",
            ))
        elif message.kind == MessageKind.EMOTICON and self.include_emoticons:
            preferred.extend((
                self.account_root / "business" / "emoticon" / "Persist",
                self.account_root / "CustomEmotion",
            ))
            fallback.extend((
                self.account_root / "business" / "emoticon",
                cache / month,
            ))
        return self._deduplicate_roots(preferred), self._deduplicate_roots(fallback)

    def _scan_root(self, root: Path) -> bool:
        if root in self._scanned_roots:
            return True
        errors: list[OSError] = []
        try:
            for current, directories, files in os.walk(
                root, followlinks=False, onerror=errors.append
            ):
                directories[:] = [
                    name for name in directories
                    if name.casefold() not in {"temp", ".git"}
                    and not (Path(current) / name).is_symlink()
                    and (Path(current) / name).resolve(strict=False) not in self._scanned_roots
                ]
                for filename in files:
                    path = Path(current) / filename
                    self.files_scanned += 1
                    self.by_name.setdefault(filename.casefold(), []).append(path)
                    for token in re.findall(r"(?i)[0-9a-f]{16,64}", filename):
                        self.by_token.setdefault(token.casefold(), []).append(path)
        except OSError:
            errors.append(OSError("media directory traversal failed"))
        complete = not errors
        if complete:
            self._scanned_roots.add(root)
        return complete

    def prepare(self, message: NormalizedMessage, filenames: set[str],
                tokens: set[str]) -> None:
        self.last_query_complete = True
        preferred, fallback = self._roots_for(message)
        for root in preferred:
            self.last_query_complete = self._scan_root(root) and self.last_query_complete
        has_match = any(
            self.by_name.get(Path(name).name.casefold()) for name in filenames
        ) or any(self.by_token.get(token) for token in tokens)
        if not has_match:
            for root in fallback:
                self.last_query_complete = self._scan_root(root) and self.last_query_complete

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
                 allow_remote_media_download: bool = False,
                 video_asset: str = "original") -> None:
        self.account_root = Path(account_root) if account_root else None
        self.media_databases = [Path(item) for item in (media_databases or [])]
        self.max_asset_bytes = max_asset_bytes
        self.image_aes_key = image_aes_key
        self.image_xor_key = image_xor_key
        self.include_emoticons = include_emoticons
        self.allow_remote_media_download = allow_remote_media_download
        if video_asset not in VIDEO_ASSET_CHOICES:
            raise ValueError(f"invalid video asset mode: {video_asset}")
        self.video_asset = video_asset
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
        if message.kind == MessageKind.VIDEO:
            return self._resolve_video(message, index, assets_root)
        candidates = self._candidates(message, index)
        if not candidates:
            status = "not_found" if index.last_query_complete else "index_incomplete"
            return [self._status(message, status)]
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

    def _resolve_video(
        self, message: NormalizedMessage, index: MediaIndex, assets_root: Path
    ) -> list[AssetRecord]:
        candidates = self._candidates(message, index)
        originals = [
            (score, path) for score, path in candidates
            if self._path_media_kind(path) == "video"
        ]
        thumbnails = [
            (score, path) for score, path in candidates
            if self._path_media_kind(path) == "image"
        ]
        records: list[AssetRecord] = []
        if self.video_asset in {"original", "both"}:
            selected = self._unique_top_path(originals)
            if selected == "ambiguous":
                records.append(self._status(message, "ambiguous_video_original"))
            elif isinstance(selected, Path):
                records.append(self._package_path(message, selected, assets_root))
            elif not index.last_query_complete:
                records.append(self._status(message, "video_index_incomplete"))
            else:
                reference_kind = self._remote_video_reference_kind(message)
                if self.allow_remote_media_download:
                    remote = self._package_remote_video(message, assets_root)
                    records.append(
                        remote or self._status(message, "video_original_not_found")
                    )
                elif reference_kind is not None:
                    records.append(
                        self._status(message, "video_remote_download_not_authorized")
                    )
                else:
                    records.append(self._status(message, "video_original_not_found"))
        if self.video_asset in {"thumbnail", "both"}:
            selected = self._unique_top_path(thumbnails)
            if selected == "ambiguous":
                records.append(self._status(message, "ambiguous_video_thumbnail"))
            elif isinstance(selected, Path):
                records.append(self._package_path(message, selected, assets_root))
            elif not index.last_query_complete:
                records.append(self._status(message, "video_thumbnail_index_incomplete"))
            else:
                records.append(self._status(message, "video_thumbnail_not_found"))
        return records

    def _unique_top_path(
        self, candidates: list[tuple[int, Path]]
    ) -> Path | str | None:
        if not candidates:
            return None
        top_score = candidates[0][0]
        top = sorted({path for score, path in candidates if score == top_score})
        if len(top) > 1 and self._all_files_identical(top):
            top = [top[0]]
        return top[0] if len(top) == 1 else "ambiguous"

    @staticmethod
    def _path_media_kind(path: Path) -> str:
        try:
            with path.open("rb") as handle:
                header = handle.read(16)
        except OSError:
            return "unknown"
        if _detect_video(header):
            return "video"
        if _detect_image(header):
            return "image"
        return "unknown"

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
        tokens = set(match.casefold() for match in re.findall(r"(?i)[0-9a-f]{16,64}", text))
        index.prepare(message, filenames, tokens)
        for filename in filenames:
            for path in index.by_name.get(Path(filename).name.casefold(), []):
                scores[path] = max(scores.get(path, 0), 100)
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
                header = handle.read(16)
                detected = _detect_image(header)
                detected_video = _detect_video(header)
        except OSError:
            detected = None
            detected_video = None
        if message.kind == MessageKind.EMOTICON and detected is None:
            return self._status(message, "unsupported_emoticon_format", source.name)
        target = asset_dir / name
        shutil.copy2(source, target)
        relative = target.relative_to(assets_root.parent).as_posix()
        status = "packaged"
        media_type = detected[1] if detected else None
        if message.kind == MessageKind.VIDEO and detected is not None:
            status = "packaged_thumbnail_only"
        elif message.kind == MessageKind.VIDEO and detected_video is not None:
            media_type = detected_video[1]
        return AssetRecord(
            id=f"asset-{_hash_file(target)[:12]}", message_id=message.id,
            kind=message.kind.value, status=status, relative_path=relative,
            media_type=media_type, size=target.stat().st_size, sha256=_hash_file(target),
            original_name=source.name,
        )

    def _fetch_remote_blob(self, raw_url: str) -> bytes | None:
        try:
            parsed = urllib.parse.urlsplit(raw_url)
            hostname = (parsed.hostname or "").casefold()
            if parsed.scheme not in {"http", "https"} or not _allowed_remote_media_host(hostname):
                return None
            if parsed.scheme == "http":
                parsed = parsed._replace(scheme="https")
            request = urllib.request.Request(
                urllib.parse.urlunsplit(parsed),
                headers={"User-Agent": "wechat-ai-exporter/1"},
            )
            with urllib.request.urlopen(request, timeout=20) as response:
                final_host = (urllib.parse.urlsplit(response.geturl()).hostname or "").casefold()
                if not _allowed_remote_media_host(final_host):
                    return None
                declared = response.headers.get("Content-Length")
                if declared and int(declared) > self.max_asset_bytes:
                    return None
                data = response.read(self.max_asset_bytes + 1)
            return data if len(data) <= self.max_asset_bytes else None
        except (OSError, ValueError, urllib.error.URLError):
            return None

    def _remote_video_reference_kind(self, message: NormalizedMessage) -> str | None:
        text = html.unescape(self._metadata_text(message))
        for name in ("cdnvideourl", "cdnrawvideourl"):
            match = re.search(rf'(?is)\b{name}\s*=\s*["\']([^"\']+)["\']', text)
            if not match:
                continue
            value = match.group(1).strip()
            parsed = urllib.parse.urlsplit(value)
            if parsed.scheme in {"http", "https"} and parsed.hostname:
                return "direct_url"
            if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
                return "legacy_client_token"
        return None

    def _package_remote_video(
        self, message: NormalizedMessage, assets_root: Path
    ) -> AssetRecord | None:
        text = html.unescape(self._metadata_text(message))
        urls = []
        for name in ("cdnvideourl", "cdnrawvideourl"):
            match = re.search(rf'(?is)\b{name}\s*=\s*["\']([^"\']+)["\']', text)
            if match:
                urls.append(match.group(1).strip())
        keys: list[bytearray] = []
        for name in ("aeskey", "cdnrawvideoaeskey"):
            match = re.search(rf'(?is)\b{name}\s*=\s*["\']([0-9a-f]{{32}})["\']', text)
            if match:
                candidate = bytearray.fromhex(match.group(1))
                if not any(candidate == existing for existing in keys):
                    keys.append(candidate)
        try:
            for raw_url in urls:
                data = self._fetch_remote_blob(raw_url)
                if data is None:
                    continue
                variants = [data]
                variants.extend(
                    decoded for key in keys
                    if (decoded := _decrypt_aes_ecb_media(data, key)) is not None
                )
                for decoded in variants:
                    detected = _detect_video(decoded)
                    if detected is None:
                        continue
                    extension, media_type = detected
                    asset_dir = _asset_dir(assets_root, message)
                    asset_dir.mkdir(parents=True, exist_ok=True)
                    target = asset_dir / _safe_name(
                        message.id + "_video" + extension,
                        message.id + extension,
                    )
                    target.write_bytes(decoded)
                    return AssetRecord(
                        id=f"asset-{_hash_bytes(decoded)[:12]}",
                        message_id=message.id, kind=message.kind.value,
                        status="packaged_remote", relative_path=target.relative_to(
                            assets_root.parent
                        ).as_posix(), media_type=media_type, size=len(decoded),
                        sha256=_hash_bytes(decoded), original_name=None,
                    )
        finally:
            for key in keys:
                key[:] = b"\x00" * len(key)
        reference_kind = self._remote_video_reference_kind(message)
        if reference_kind == "legacy_client_token":
            return self._status(message, "video_cdn_requires_wechat_client")
        if reference_kind == "direct_url":
            return self._status(message, "video_remote_download_failed")
        return None

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
                data = self._fetch_remote_blob(raw_url)
                if data is None:
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
