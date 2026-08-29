from __future__ import annotations

from dataclasses import dataclass
import getpass
import hashlib
import hmac
from pathlib import Path
import re


PAGE_SIZE = 4096
SALT_SIZE = 16
IV_SIZE = 16


@dataclass(frozen=True)
class CipherProfile:
    name: str
    kdf_hash: str
    kdf_iterations: int
    hmac_hash: str
    hmac_iterations: int
    hmac_size: int
    derive_encryption_key: bool

    @property
    def reserve_size(self) -> int:
        return ((IV_SIZE + self.hmac_size + 15) // 16) * 16


WEIXIN4 = CipherProfile("weixin4-raw-sha512", "sha512", 1, "sha512", 2, 64, False)
WECHAT3 = CipherProfile("wechat3-sqlcipher3-sha1", "sha1", 64_000, "sha1", 2, 20, True)
PROFILES = {item.name: item for item in (WEIXIN4, WECHAT3)}


class KeyInputError(ValueError):
    pass


def profile_for_layout(layout: str) -> CipherProfile:
    normalized = layout.casefold()
    if normalized in {"weixin-4", "weixin4", WEIXIN4.name}:
        return WEIXIN4
    if normalized in {"wechat-3", "wechat3", WECHAT3.name}:
        return WECHAT3
    raise KeyInputError(f"Unsupported database layout: {layout}")


def parse_hex_key(value: str) -> bytearray:
    normalized = value.strip()
    if normalized.casefold().startswith("hex:"):
        normalized = normalized[4:].strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", normalized):
        raise KeyInputError("The key must contain exactly 64 hexadecimal characters.")
    return bytearray.fromhex(normalized)


def prompt_key(input_mode: str = "console") -> bytearray:
    if input_mode == "console":
        return parse_hex_key(getpass.getpass("WeChat database key (hidden): "))
    if input_mode == "dialog":
        try:
            import tkinter as tk
            from tkinter import simpledialog
            root = tk.Tk()
            root.withdraw()
            value = simpledialog.askstring(
                "WeChat chat export", "Enter the 64-character database key:",
                show="•", parent=root,
            )
            root.destroy()
        except Exception as exc:
            raise KeyInputError("The local hidden-entry dialog could not be opened.") from exc
        if value is None:
            raise KeyInputError("Key entry was cancelled.")
        return parse_hex_key(value)
    raise KeyInputError(f"Unsupported input mode: {input_mode}")


def prompt_image_key(input_mode: str = "console") -> bytearray:
    if input_mode == "console":
        value = getpass.getpass("WeChat V2 image AES key (hidden, 16 ASCII characters): ")
    elif input_mode == "dialog":
        try:
            import tkinter as tk
            from tkinter import simpledialog
            root = tk.Tk()
            root.withdraw()
            value = simpledialog.askstring(
                "WeChat image export", "Enter the 16-character V2 image AES key:",
                show="•", parent=root,
            )
            root.destroy()
        except Exception as exc:
            raise KeyInputError("The local hidden-entry dialog could not be opened.") from exc
        if value is None:
            raise KeyInputError("Image-key entry was cancelled.")
    else:
        raise KeyInputError(f"Unsupported input mode: {input_mode}")
    normalized = value.strip()
    if not re.fullmatch(r"[0-9A-Za-z]{16}", normalized):
        raise KeyInputError("The V2 image key must contain exactly 16 ASCII letters or digits.")
    return bytearray(normalized.encode("ascii"))


def wipe_key(key: bytearray) -> None:
    for index in range(len(key)):
        key[index] = 0


def encryption_key(key_material: bytes | bytearray, salt: bytes, profile: CipherProfile) -> bytes:
    if not profile.derive_encryption_key:
        return bytes(key_material)
    return hashlib.pbkdf2_hmac(
        profile.kdf_hash, bytes(key_material), salt, profile.kdf_iterations, dklen=32
    )


def cipher_keys(key_material: bytes | bytearray, salt: bytes,
                profile: CipherProfile) -> tuple[bytes, bytes]:
    encrypted_key = encryption_key(key_material, salt, profile)
    mac_salt = bytes(value ^ 0x3A for value in salt)
    mac_key = hashlib.pbkdf2_hmac(
        profile.hmac_hash, encrypted_key, mac_salt,
        profile.hmac_iterations, dklen=32,
    )
    return encrypted_key, mac_key


def page_hmac(mac_key: bytes, authenticated_bytes: bytes, page_number: int,
              profile: CipherProfile) -> bytes:
    return hmac.new(
        mac_key,
        authenticated_bytes + page_number.to_bytes(4, "little"),
        profile.hmac_hash,
    ).digest()


def verify_first_page(key_material: bytes | bytearray, first_page: bytes,
                      profile: CipherProfile) -> bool:
    if len(key_material) != 32 or len(first_page) < PAGE_SIZE:
        return False
    salt = first_page[:SALT_SIZE]
    if salt == b"\x00" * SALT_SIZE or first_page.startswith(b"SQLite format 3\x00"):
        return False
    _, mac_key = cipher_keys(key_material, salt, profile)
    reserve = profile.reserve_size
    authenticated_end = PAGE_SIZE - reserve + IV_SIZE
    expected_start = authenticated_end
    expected_end = expected_start + profile.hmac_size
    if expected_end > len(first_page):
        return False
    digest = page_hmac(mac_key, first_page[SALT_SIZE:authenticated_end], 1, profile)
    return hmac.compare_digest(digest, first_page[expected_start:expected_end])


def verify_database_key(database: Path, key_material: bytes | bytearray,
                        profile: CipherProfile) -> bool:
    try:
        with database.open("rb") as handle:
            first_page = handle.read(PAGE_SIZE)
    except OSError:
        return False
    return verify_first_page(key_material, first_page, profile)
