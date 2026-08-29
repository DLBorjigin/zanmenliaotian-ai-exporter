from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import hashlib
import os
from pathlib import Path
import shutil
import time
import uuid

from .key_validation import CipherProfile, verify_database_key


class SnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class SnapshotResult:
    directory: Path
    database: Path
    copied_files: tuple[Path, ...]
    profile: str


def _source_files(database: Path) -> list[Path]:
    files = [database]
    for suffix in ("-wal", "-shm", "-journal"):
        candidate = Path(str(database) + suffix)
        if candidate.is_file():
            files.append(candidate)
    return files


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _signature(paths: list[Path]) -> tuple[tuple[str, int, int, str], ...]:
    values = []
    for path in paths:
        stat = path.stat()
        values.append((path.name, stat.st_size, stat.st_mtime_ns, _sha256(path)))
    return tuple(values)


def create_verified_snapshot(database: Path, destination_parent: Path,
                             key_material: bytes | bytearray,
                             profile: CipherProfile, retries: int = 3,
                             manual_process_exit_confirmed: bool = False) -> SnapshotResult:
    database = database.resolve(strict=True)
    if not database.is_file():
        raise SnapshotError("The selected database is not a file.")
    destination_parent.mkdir(parents=True, exist_ok=True)
    staging = destination_parent / f".wechat-snapshot-{uuid.uuid4().hex}"
    final = destination_parent / f"wechat-snapshot-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    staging.mkdir()
    try:
        copied: list[Path] = []
        stable = False
        for attempt in range(max(1, retries)):
            sources = _source_files(database)
            try:
                before = _signature(sources)
                for old_copy in staging.iterdir():
                    if old_copy.is_file():
                        old_copy.unlink()
                copied.clear()
                for source in sources:
                    target = staging / source.name
                    shutil.copy2(source, target)
                    copied.append(target)
                after_sources = _source_files(database)
                after = _signature(after_sources)
                copied_signature = _signature(copied)
                stable = (
                    before == after
                    and tuple((name, size, mtime, digest) for name, size, mtime, digest in before)
                    == copied_signature
                )
            except OSError as exc:
                if attempt + 1 >= retries:
                    raise SnapshotError("Could not copy a stable database snapshot.") from exc
            if stable:
                break
            time.sleep(0.1 * (attempt + 1))
        if not stable:
            raise SnapshotError("The database kept changing; close WeChat and retry.")

        copied_database = staging / database.name
        if not verify_database_key(copied_database, key_material, profile):
            raise SnapshotError("The key did not validate for the selected database profile.")

        manifest = {
            "schema_version": 1,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "source_name": database.name,
            "cipher_profile": profile.name,
            "encrypted": True,
            "read_only_source": True,
            "files": [
                {"name": item.name, "size": item.stat().st_size, "sha256": _sha256(item)}
                for item in copied
            ],
            "contains_key": False,
            "manual_process_exit_confirmed": bool(manual_process_exit_confirmed),
            "wal_state": next(
                (
                    "captured_stable" if item.stat().st_size > 0 else "empty"
                    for item in copied if item.name.endswith("-wal")
                ),
                "absent",
            ),
        }
        (staging / "snapshot-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        os.replace(staging, final)
        return SnapshotResult(
            directory=final, database=final / database.name,
            copied_files=tuple(final / item.name for item in copied), profile=profile.name,
        )
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
