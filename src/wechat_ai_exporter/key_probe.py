from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import hashlib
from pathlib import Path
import platform
import re
import struct
import time
from typing import Callable, Iterator

from .key_validation import PAGE_SIZE, WEIXIN4, verify_first_page, wipe_key


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MAX_DLL_SIZE = 512 * 1024 * 1024
MAX_REMOTE_STRING = 1024
CFG_LANDMARK = b"global_config"
EXACT_SALT_CONFIG_MARKER = b"com.Tencent.WCDB.Config.Cipher"
# The serialized key+salt form was identified with help from the MIT-licensed
# weflow-cli project; this adapter deliberately follows an exact registration
# node instead of adopting its general key-pattern memory scan.
CONFIG_CIPHER_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)
EXACT_SALT_SCAN_CHUNK = 1024 * 1024
MAX_EXACT_SALT_SCAN_BYTES = 1024 * 1024 * 1024
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
PAGE_GUARD = 0x100
READABLE_PAGE_PROTECTIONS = {0x02, 0x04, 0x20, 0x40, 0x80}

# These signatures and structure offsets are adapted from the Apache-2.0
# wechatauto-replica project. They are deliberately treated as version adapters,
# never as proof of compatibility; a derived key must still pass SQLCipher HMAC
# validation against the exact database selected by the user.
MASTER_DLL_PATTERN = bytes.fromhex(
    "83ec404889d64889cb0f57c00f1142100f11024c8bb1c8020000"
    "4883b9d0020000107209488b9bb8020000eb074881c3b8020000"
    "4d85f60f880a0200004983fe10736d4c89761048c746180f0000"
    "000f10030f110648b8"
)
MASTER_DLL_VERIFY = tuple(bytes.fromhex(value) for value in (
    "488944242048b8", "488944242848b8", "488944243048b8",
))


class ProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class MasterKeyAdapter:
    name: str
    pointer_back: int
    cfg_pointer_offset: int = 0x68
    cfg_dword_offset: int = 0x40
    cfg_account_offset: int = 0x48
    cfg_cipher_offset: int = 0x2B8


SUPPORTED_ADAPTERS = (
    MasterKeyAdapter("weixin-4.1.12-current", 0x138),
    MasterKeyAdapter("weixin-4.1.10-legacy", 0x130),
)
EXACT_SALT_ADAPTER = "weixin-4.1.13.12-exact-salt-config"
READ_ONLY_PROBE_ADAPTER_NAMES = tuple(
    item.name for item in SUPPORTED_ADAPTERS
) + (EXACT_SALT_ADAPTER,)


@dataclass(frozen=True)
class ProbeResult:
    key: bytearray
    adapter: str
    process_id: int
    cfg_dword: int
    image_key: bytearray | None = None
    image_xor_key: int | None = None


def wait_for_manual_weixin_exit(timeout_seconds: float = 180.0,
                                poll_interval_seconds: float = 0.5) -> float:
    """Wait for a user-initiated exit. This function never terminates a process."""
    timeout = max(5.0, min(timeout_seconds, 600.0))
    poll = max(0.1, min(poll_interval_seconds, 2.0))
    started = time.monotonic()
    while _process_ids():
        if time.monotonic() - started >= timeout:
            raise ProbeError(
                "Timed out waiting for the user to close Weixin; no process was terminated."
            )
        time.sleep(poll)
    return time.monotonic() - started


def derive_database_key(master_key: bytes | bytearray, database_salt: bytes) -> bytearray:
    if len(master_key) != 32:
        raise ProbeError("The discovered master key has an unsupported length.")
    if len(database_salt) != 16 or database_salt == b"\x00" * 16:
        raise ProbeError("The selected database does not contain a usable SQLCipher salt.")
    return bytearray(hashlib.pbkdf2_hmac(
        "sha512", bytes(master_key), database_salt, 256_000, dklen=32
    ))


def extract_xor_material(dll_bytes: bytes) -> bytes | None:
    hit = dll_bytes.find(MASTER_DLL_PATTERN)
    if hit < 0:
        return None
    cursor = hit + len(MASTER_DLL_PATTERN)
    material = bytearray()
    for index in range(4):
        if cursor + 8 > len(dll_bytes):
            return None
        material.extend(dll_bytes[cursor:cursor + 8])
        cursor += 8
        if index < 3:
            verify = MASTER_DLL_VERIFY[index]
            if dll_bytes[cursor:cursor + len(verify)] != verify:
                return None
            cursor += len(verify)
    return bytes(material) if len(material) == 32 else None


def derive_image_key(cfg_dword: int, account_identifier: str) -> tuple[bytearray, int]:
    if not 0 < cfg_dword <= 0xFFFFFFFF or not account_identifier:
        raise ProbeError("The account configuration cannot derive an image key.")
    seed = f"{cfg_dword}{account_identifier}".encode("utf-8")
    return bytearray(hashlib.md5(seed).hexdigest()[:16].encode("ascii")), cfg_dword & 0xFF


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260),
    ]


class _MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260),
    ]


class _MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def _kernel32():
    if platform.system() != "Windows" or not hasattr(ctypes, "WinDLL"):
        raise ProbeError("Read-only key discovery is supported only on 64-bit Windows.")
    if struct.calcsize("P") != 8:
        raise ProbeError("A 64-bit Python runtime is required to inspect 64-bit Weixin.")
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _process_ids(executable: str = "Weixin.exe") -> list[int]:
    k32 = _kernel32()
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
    k32.Process32FirstW.restype = wintypes.BOOL
    k32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
    k32.Process32NextW.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    snapshot = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot in (-1, (1 << 64) - 1):
        raise ProbeError("Windows could not enumerate running processes.")
    result: list[int] = []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.casefold() == executable.casefold():
                result.append(int(entry.th32ProcessID))
            entry.dwSize = ctypes.sizeof(entry)
            ok = k32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snapshot)
    return result


def _weixin_module(pid: int) -> tuple[int, int, Path] | None:
    k32 = _kernel32()
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Module32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_MODULEENTRY32W)]
    k32.Module32FirstW.restype = wintypes.BOOL
    k32.Module32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_MODULEENTRY32W)]
    k32.Module32NextW.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    snapshot = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if not snapshot or snapshot in (-1, (1 << 64) - 1):
        return _weixin_module_psapi(pid)
    try:
        entry = _MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = k32.Module32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            if entry.szModule.casefold() == "weixin.dll":
                return int(entry.modBaseAddr or 0), int(entry.modBaseSize), Path(entry.szExePath)
            entry.dwSize = ctypes.sizeof(entry)
            ok = k32.Module32NextW(snapshot, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snapshot)
    return _weixin_module_psapi(pid)


def _weixin_module_psapi(pid: int) -> tuple[int, int, Path] | None:
    k32 = _kernel32()
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    psapi.EnumProcessModulesEx.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
    ]
    psapi.EnumProcessModulesEx.restype = wintypes.BOOL
    psapi.GetModuleFileNameExW.argtypes = [
        wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD,
    ]
    psapi.GetModuleFileNameExW.restype = wintypes.DWORD
    psapi.GetModuleInformation.argtypes = [
        wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(_MODULEINFO), wintypes.DWORD,
    ]
    psapi.GetModuleInformation.restype = wintypes.BOOL
    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        modules = (wintypes.HMODULE * 2048)()
        needed = wintypes.DWORD()
        if not psapi.EnumProcessModulesEx(
            handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), 0x03
        ):
            return None
        count = min(needed.value // ctypes.sizeof(wintypes.HMODULE), len(modules))
        for index in range(count):
            path_buffer = ctypes.create_unicode_buffer(32768)
            if not psapi.GetModuleFileNameExW(
                handle, modules[index], path_buffer, len(path_buffer)
            ):
                continue
            path = Path(path_buffer.value)
            if path.name.casefold() != "weixin.dll":
                continue
            info = _MODULEINFO()
            if not psapi.GetModuleInformation(
                handle, modules[index], ctypes.byref(info), ctypes.sizeof(info)
            ):
                return None
            return int(info.lpBaseOfDll or 0), int(info.SizeOfImage), path
    finally:
        k32.CloseHandle(handle)
    return None


def _open_reader(pid: int) -> tuple[object, Callable[[int, int], bytes | None]]:
    k32 = _kernel32()
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    k32.ReadProcessMemory.restype = wintypes.BOOL
    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        raise ProbeError("Windows denied read-only access to a Weixin process.")

    def read(address: int, length: int) -> bytes | None:
        if address < 0x10000 or length <= 0 or length > MAX_DLL_SIZE:
            return None
        buffer = ctypes.create_string_buffer(length)
        count = ctypes.c_size_t()
        ok = k32.ReadProcessMemory(
            handle, ctypes.c_void_p(address), buffer, length, ctypes.byref(count)
        )
        if not ok or count.value != length:
            return None
        return buffer.raw

    return handle, read


def _remote_std_string(read: Callable[[int, int], bytes | None], address: int,
                       *, binary: bool = False) -> bytes | str | None:
    descriptor = read(address, 32)
    if not descriptor:
        return None
    size = struct.unpack_from("<Q", descriptor, 16)[0]
    capacity = struct.unpack_from("<Q", descriptor, 24)[0]
    if size <= 0 or size > MAX_REMOTE_STRING:
        return None
    if capacity <= 15:
        data = descriptor[:size]
    else:
        pointer = struct.unpack_from("<Q", descriptor, 0)[0]
        data = read(pointer, size)
    if data is None or len(data) != size:
        return None
    return data if binary else data.decode("utf-8", "replace")


def _version_from_module_path(path: Path) -> tuple[int, int, int, int] | None:
    for part in reversed(path.parts):
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", part):
            values = tuple(int(value) for value in part.split("."))
            return values if len(values) == 4 else None
    return None


def _file_contains(path: Path, marker: bytes) -> bool:
    carry = b""
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(EXACT_SALT_SCAN_CHUNK):
                combined = carry + chunk
                if marker in combined:
                    return True
                carry = combined[-max(0, len(marker) - 1):]
    except OSError:
        return False
    return False


def _exact_salt_keys_from_bytes(data: bytes, salt: bytes) -> Iterator[bytearray]:
    if len(salt) != 16:
        return
    ascii_pattern = re.compile(
        rb"x'([0-9a-fA-F]{64})" + re.escape(salt.hex().encode("ascii")) + rb"'"
    )
    for match in ascii_pattern.finditer(data):
        try:
            yield bytearray.fromhex(match.group(1).decode("ascii"))
        except ValueError:
            continue


def _process_memory_hits(pid: int, needle: bytes, deadline: float,
                         byte_budget: int = MAX_EXACT_SALT_SCAN_BYTES
                         ) -> Iterator[int]:
    if not needle:
        return
    handle, read = _open_reader(pid)
    k32 = _kernel32()
    k32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.POINTER(_MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
    ]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    scanned = 0
    address = 0x10000
    maximum = 0x7FFFFFFFFFFF
    overlap = len(needle) - 1
    try:
        while address < maximum and scanned < byte_budget:
            if time.monotonic() > deadline:
                return
            info = _MEMORY_BASIC_INFORMATION()
            if not k32.VirtualQueryEx(
                handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
            ):
                return
            region_start = int(info.BaseAddress or 0)
            region_size = int(info.RegionSize or 0)
            next_address = region_start + region_size
            if next_address <= address:
                return
            address = next_address
            protection = int(info.Protect) & 0xFF
            if (
                int(info.State) != MEM_COMMIT
                or int(info.Type) not in {MEM_PRIVATE, MEM_MAPPED}
                or int(info.Protect) & PAGE_GUARD
                or protection not in READABLE_PAGE_PROTECTIONS
                or region_size <= 0
            ):
                continue
            cursor = region_start
            end = region_start + region_size
            carry = b""
            while cursor < end and scanned < byte_budget:
                if time.monotonic() > deadline:
                    return
                length = min(EXACT_SALT_SCAN_CHUNK, end - cursor, byte_budget - scanned)
                if length <= 0:
                    return
                chunk_start = cursor
                chunk = read(cursor, length)
                scanned += length
                cursor += length
                if chunk is None:
                    carry = b""
                    continue
                combined = carry + chunk
                combined_start = chunk_start - len(carry)
                hit_start = 0
                while True:
                    hit = combined.find(needle, hit_start)
                    if hit < 0:
                        break
                    yield combined_start + hit
                    hit_start = hit + 1
                carry = combined[-overlap:] if overlap else b""
    finally:
        k32.CloseHandle(handle)


def _candidate_wcdb_config_keys(pid: int, first_page: bytes,
                                deadline: float) -> Iterator[bytearray]:
    module = _weixin_module(pid)
    if module is None:
        return
    base, module_size, dll_path = module
    if (
        _version_from_module_path(dll_path) != (4, 1, 13, 12)
        or not _file_contains(dll_path, EXACT_SALT_CONFIG_MARKER)
    ):
        return
    handle, read = _open_reader(pid)
    try:
        image = read(base, module_size)
        if image is None:
            return
        marker_hit = image.find(EXACT_SALT_CONFIG_MARKER)
        if marker_hit < 0:
            return
        marker_address = base + marker_hit
        pair = struct.pack("<QQ", marker_address, len(EXACT_SALT_CONFIG_MARKER))
    finally:
        _kernel32().CloseHandle(handle)

    pair_hits = list(_process_memory_hits(pid, pair, deadline))
    handle, read = _open_reader(pid)
    try:
        for pair_address in pair_hits:
            node = read(pair_address - 0x10, 0x50)
            if node is None or len(node) != 0x50:
                continue
            config_ptr = struct.unpack_from("<Q", node, 0x28)[0]
            if not 0x10000 <= config_ptr < 0x800000000000:
                continue
            obj = read(config_ptr + 0x88, 0x28)
            if obj is None or len(obj) != 0x28:
                continue
            data_ptr = struct.unpack_from("<Q", obj, 0x08)[0]
            data_len = struct.unpack_from("<Q", obj, 0x10)[0]
            if not (0 < data_len <= 1024 and 0x10000 <= data_ptr < 0x800000000000):
                continue
            blob = read(data_ptr, int(data_len))
            if blob is None or len(blob) != data_len:
                continue
            decoded = bytes(
                value ^ CONFIG_CIPHER_XOR_MASK[index % len(CONFIG_CIPHER_XOR_MASK)]
                for index, value in enumerate(blob)
            )
            yield from _exact_salt_keys_from_bytes(decoded, first_page[:16])
    finally:
        _kernel32().CloseHandle(handle)


def _landmark_offsets(image: bytes) -> Iterator[int]:
    start = 0
    while True:
        hit = image.find(CFG_LANDMARK, start)
        if hit < 0:
            return
        if hit + 32 <= len(image):
            size = struct.unpack_from("<Q", image, hit + 16)[0]
            capacity = struct.unpack_from("<Q", image, hit + 24)[0]
            if size == len(CFG_LANDMARK) and capacity <= 15:
                yield hit
        start = hit + 1


def _owner_pointer_address(base: int, landmark_start: int,
                           adapter: MasterKeyAdapter) -> int:
    # pointer_back is measured from the std::string size field (+16), not from
    # the start of the inline SSO character buffer.
    return base + landmark_start + 16 - adapter.pointer_back


def _candidate_master_keys(pid: int, adapter: MasterKeyAdapter, deadline: float,
                           derive_media_key: bool) -> Iterator[
                               tuple[bytearray, int, bytearray | None, int | None]
                           ]:
    module = _weixin_module(pid)
    if module is None:
        return
    base, module_size, dll_path = module
    if not 0 < module_size <= MAX_DLL_SIZE:
        return
    try:
        dll_bytes = dll_path.read_bytes()
    except OSError:
        return
    material = extract_xor_material(dll_bytes)
    if material is None:
        return
    handle, read = _open_reader(pid)
    try:
        image = read(base, module_size)
        if image is None:
            return
        for landmark in _landmark_offsets(image):
            if time.monotonic() > deadline or landmark < adapter.pointer_back:
                return
            pointer_data = read(_owner_pointer_address(base, landmark, adapter), 8)
            if not pointer_data:
                continue
            owner = struct.unpack("<Q", pointer_data)[0]
            cfg_data = read(owner + adapter.cfg_pointer_offset, 8)
            if not cfg_data:
                continue
            cfg = struct.unpack("<Q", cfg_data)[0]
            if not 0x10000 <= cfg < 0x800000000000:
                continue
            encrypted = _remote_std_string(read, cfg + adapter.cfg_cipher_offset, binary=True)
            dword_data = read(cfg + adapter.cfg_dword_offset, 4)
            if not isinstance(encrypted, bytes) or len(encrypted) != 32:
                continue
            cfg_dword = struct.unpack("<I", dword_data)[0] if dword_data else 0
            image_key = None
            image_xor_key = None
            if derive_media_key:
                account = _remote_std_string(read, cfg + adapter.cfg_account_offset)
                if not isinstance(account, str) or not account:
                    continue
                try:
                    image_key, image_xor_key = derive_image_key(cfg_dword, account)
                except ProbeError:
                    continue
            yield (
                bytearray(a ^ b for a, b in zip(encrypted, material)), cfg_dword,
                image_key, image_xor_key,
            )
    finally:
        _kernel32().CloseHandle(handle)


def _candidate_image_keys_from_global_config(
    pid: int, deadline: float
) -> Iterator[tuple[int, bytearray, int]]:
    """Read only the account fields needed for the separately authorized media key."""
    module = _weixin_module(pid)
    if module is None:
        return
    base, module_size, _dll_path = module
    if not 0 < module_size <= MAX_DLL_SIZE:
        return
    handle, read = _open_reader(pid)
    seen_configs: set[int] = set()
    try:
        image = read(base, module_size)
        if image is None:
            return
        landmarks = list(_landmark_offsets(image))
        for adapter in SUPPORTED_ADAPTERS:
            for landmark in landmarks:
                if time.monotonic() > deadline or landmark < adapter.pointer_back:
                    return
                pointer_data = read(_owner_pointer_address(base, landmark, adapter), 8)
                if not pointer_data:
                    continue
                owner = struct.unpack("<Q", pointer_data)[0]
                cfg_data = read(owner + adapter.cfg_pointer_offset, 8)
                if not cfg_data:
                    continue
                cfg = struct.unpack("<Q", cfg_data)[0]
                if not 0x10000 <= cfg < 0x800000000000 or cfg in seen_configs:
                    continue
                seen_configs.add(cfg)
                dword_data = read(cfg + adapter.cfg_dword_offset, 4)
                account = _remote_std_string(read, cfg + adapter.cfg_account_offset)
                if not dword_data or not isinstance(account, str) or not account:
                    continue
                cfg_dword = struct.unpack("<I", dword_data)[0]
                try:
                    image_key, image_xor_key = derive_image_key(cfg_dword, account)
                except ProbeError:
                    continue
                yield cfg_dword, image_key, image_xor_key
    finally:
        _kernel32().CloseHandle(handle)


def probe_database_key(database: Path, *, authorized: bool,
                       time_budget_seconds: float = 20.0,
                       derive_media_key: bool = False) -> ProbeResult:
    if not authorized:
        raise ProbeError("Explicit authorization is required for read-only process memory access.")
    database = database.resolve(strict=True)
    if not database.is_file():
        raise ProbeError("The selected database is not a regular file.")
    with database.open("rb") as handle:
        first_page = handle.read(PAGE_SIZE)
    if len(first_page) < PAGE_SIZE:
        raise ProbeError("The selected database is too small for key validation.")
    deadline = time.monotonic() + max(1.0, min(time_budget_seconds, 60.0))
    pids = _process_ids()
    if not pids:
        raise ProbeError("No running Weixin.exe process was found; sign in to WeChat first.")
    for pid in pids:
        for adapter in SUPPORTED_ADAPTERS:
            for master, cfg_dword, image_key, image_xor_key in _candidate_master_keys(
                pid, adapter, deadline, derive_media_key
            ):
                derived = bytearray()
                accepted = False
                try:
                    derived = derive_database_key(master, first_page[:16])
                    accepted = verify_first_page(derived, first_page, WEIXIN4)
                    if accepted:
                        return ProbeResult(
                            derived, adapter.name, pid, cfg_dword,
                            image_key=image_key, image_xor_key=image_xor_key,
                        )
                finally:
                    wipe_key(master)
                    if not accepted:
                        wipe_key(derived)
                        if image_key is not None:
                            wipe_key(image_key)
            if time.monotonic() > deadline:
                raise ProbeError("The bounded read-only scan reached its time limit without a verified key.")
    for pid in pids:
        for candidate in _candidate_wcdb_config_keys(pid, first_page, deadline):
            accepted = False
            try:
                accepted = verify_first_page(candidate, first_page, WEIXIN4)
                if not accepted:
                    continue
                if not derive_media_key:
                    return ProbeResult(candidate, EXACT_SALT_ADAPTER, pid, 0)
                media_pids = [pid, *(item for item in pids if item != pid)]
                for media_pid in media_pids:
                    for cfg_dword, image_key, image_xor_key in (
                        _candidate_image_keys_from_global_config(media_pid, deadline)
                    ):
                        return ProbeResult(
                            candidate, EXACT_SALT_ADAPTER, pid, cfg_dword,
                            image_key=image_key, image_xor_key=image_xor_key,
                        )
                accepted = False
            finally:
                if not accepted:
                    wipe_key(candidate)
        if time.monotonic() > deadline:
            raise ProbeError(
                "The bounded read-only scan reached its time limit without a verified key."
            )
    raise ProbeError(
        "No supported adapter produced a key that validates the selected database. "
        "This WeChat build may need a new read-only adapter."
    )
