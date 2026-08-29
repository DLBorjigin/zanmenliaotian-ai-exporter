from __future__ import annotations

import hmac
import os
from pathlib import Path
import struct
import uuid

from .key_validation import (
    CipherProfile, IV_SIZE, PAGE_SIZE, SALT_SIZE, cipher_keys, page_hmac,
)


SQLITE_HEADER = b"SQLite format 3\x00"


class DecryptionError(RuntimeError):
    pass


WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24
WAL_MAGIC = {0x377F0682, 0x377F0683}


def _aes_cbc_decrypt(key: bytes, iv: bytes, payload: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise DecryptionError(
            "AES support is unavailable; install the packaged cryptography dependency."
        ) from exc
    if len(payload) % 16:
        raise DecryptionError("Encrypted page payload is not AES-block aligned.")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(payload) + decryptor.finalize()


def _verified_plaintext_page(page: bytes, page_number: int, aes_key: bytes,
                             mac_key: bytes, profile: CipherProfile) -> bytes:
    if len(page) != PAGE_SIZE:
        raise DecryptionError(f"Page {page_number} is truncated.")
    offset = SALT_SIZE if page_number == 1 else 0
    if not any(page):
        return (SQLITE_HEADER if page_number == 1 else b"") + page[offset:]
    iv_start = PAGE_SIZE - profile.reserve_size
    authenticated_end = iv_start + IV_SIZE
    expected_start = authenticated_end
    expected_end = expected_start + profile.hmac_size
    actual = page_hmac(mac_key, page[offset:authenticated_end], page_number, profile)
    if not hmac.compare_digest(actual, page[expected_start:expected_end]):
        raise DecryptionError(f"Page integrity check failed at page {page_number}.")
    plaintext = _aes_cbc_decrypt(
        aes_key, page[iv_start:authenticated_end], page[offset:iv_start]
    )
    return (
        (SQLITE_HEADER if page_number == 1 else b"")
        + plaintext
        + page[iv_start:]
    )


def _merge_encrypted_wal(output_database: Path, encrypted_wal: Path,
                         aes_key: bytes, mac_key: bytes,
                         profile: CipherProfile) -> int:
    wal_size = encrypted_wal.stat().st_size
    if wal_size == 0:
        return 0
    if wal_size < WAL_HEADER_SIZE:
        raise DecryptionError("Encrypted WAL header is truncated.")
    frame_size = WAL_FRAME_HEADER_SIZE + PAGE_SIZE
    frames: list[tuple[int, int, int]] = []
    last_commit_index = -1
    last_commit_pages = 0
    with encrypted_wal.open("rb") as wal:
        header = wal.read(WAL_HEADER_SIZE)
        magic, _version, wal_page_size = struct.unpack(">III", header[:12])
        if magic not in WAL_MAGIC:
            raise DecryptionError("Encrypted WAL has an unsupported header magic.")
        if wal_page_size == 1:
            wal_page_size = 65536
        if wal_page_size != PAGE_SIZE:
            raise DecryptionError("Encrypted WAL page size does not match the database.")
        wal_salt = header[16:24]
        frame_count = (wal_size - WAL_HEADER_SIZE) // frame_size
        for index in range(frame_count):
            frame_offset = WAL_HEADER_SIZE + index * frame_size
            wal.seek(frame_offset)
            frame_header = wal.read(WAL_FRAME_HEADER_SIZE)
            page = wal.read(PAGE_SIZE)
            page_number, commit_pages = struct.unpack(">II", frame_header[:8])
            if page_number == 0 or frame_header[8:16] != wal_salt:
                break
            try:
                _verified_plaintext_page(page, page_number, aes_key, mac_key, profile)
            except DecryptionError:
                if last_commit_index >= 0 and commit_pages == 0:
                    break
                raise DecryptionError(
                    f"Encrypted WAL integrity check failed at frame {index + 1}."
                ) from None
            frames.append((frame_offset + WAL_FRAME_HEADER_SIZE, page_number, commit_pages))
            if commit_pages:
                last_commit_index = len(frames) - 1
                last_commit_pages = commit_pages

    if last_commit_index < 0:
        return 0
    committed = frames[:last_commit_index + 1]
    highest_page = max(page_number for _, page_number, _ in committed)
    if last_commit_pages <= 0 or last_commit_pages > max(
        highest_page, output_database.stat().st_size // PAGE_SIZE
    ):
        raise DecryptionError("Encrypted WAL commit size is inconsistent with its frames.")

    with encrypted_wal.open("rb") as wal, output_database.open("r+b") as output:
        for page_offset, page_number, _commit_pages in committed:
            wal.seek(page_offset)
            page = wal.read(PAGE_SIZE)
            plaintext = _verified_plaintext_page(
                page, page_number, aes_key, mac_key, profile
            )
            if page_number <= last_commit_pages:
                output.seek((page_number - 1) * PAGE_SIZE)
                output.write(plaintext)
        output.truncate(last_commit_pages * PAGE_SIZE)
        output.seek(28)
        output.write(struct.pack(">I", last_commit_pages))
        output.flush()
        os.fsync(output.fileno())
    return last_commit_index + 1


def decrypt_database(encrypted_database: Path, output_database: Path,
                     key_material: bytes | bytearray,
                     profile: CipherProfile) -> Path:
    encrypted_database = encrypted_database.resolve(strict=True)
    output_database = output_database.resolve(strict=False)
    if encrypted_database == output_database:
        raise DecryptionError("Encrypted input and decrypted output must be different files.")
    output_database.parent.mkdir(parents=True, exist_ok=True)
    staging = output_database.parent / f".{output_database.name}.{uuid.uuid4().hex}.partial"
    try:
        size = encrypted_database.stat().st_size
        if size == 0 or size % PAGE_SIZE:
            raise DecryptionError("Encrypted database size is not a whole number of 4096-byte pages.")
        with encrypted_database.open("rb") as source:
            first_page = source.read(PAGE_SIZE)
            if len(first_page) != PAGE_SIZE:
                raise DecryptionError("Encrypted database has no complete first page.")
            salt = first_page[:SALT_SIZE]
            aes_key, mac_key = cipher_keys(key_material, salt, profile)
            source.seek(0)
            with staging.open("xb") as destination:
                page_number = 1
                while True:
                    page = source.read(PAGE_SIZE)
                    if not page:
                        break
                    if len(page) != PAGE_SIZE:
                        raise DecryptionError(f"Page {page_number} is truncated.")
                    destination.write(_verified_plaintext_page(
                        page, page_number, aes_key, mac_key, profile
                    ))
                    page_number += 1
                destination.flush()
                os.fsync(destination.fileno())
        encrypted_wal = Path(str(encrypted_database) + "-wal")
        if encrypted_wal.is_file():
            _merge_encrypted_wal(staging, encrypted_wal, aes_key, mac_key, profile)
        os.replace(staging, output_database)
        return output_database
    except Exception:
        staging.unlink(missing_ok=True)
        raise
