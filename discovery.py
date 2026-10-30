from __future__ import annotations

import ctypes
from ctypes import wintypes
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform
import re
import string
import time
from typing import Iterable, Iterator

from .models import AccountCandidate, InstallationCandidate


EXECUTABLE_NAMES = {"wechat.exe", "weixin.exe"}
DATA_ROOT_NAMES = {"wechat files", "xwechat_files"}
ACCOUNT_IGNORES = {"all users", "all_users", "backup", "wmpf", "applet", "plugins"}
WALK_IGNORES = {
    "$recycle.bin", "system volume information", "windows", "recovery",
    "node_modules", ".git", ".cache", "winsxs",
}


@dataclass(frozen=True)
class DiscoveryReport:
    installations: tuple[InstallationCandidate, ...]
    accounts: tuple[AccountCandidate, ...]
    scan: dict[str, object]


def _stable_id(prefix: str, path: Path) -> str:
    normalized = os.path.normcase(str(path.resolve(strict=False)))
    digest = hashlib.sha256(normalized.encode("utf-8", "surrogatepass")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def _path_hint(path: Path) -> str:
    anchor = path.anchor or ""
    return f"{anchor}…{os.sep}{path.name}" if anchor else f"…{os.sep}{path.name}"


def _file_version(path: Path) -> str:
    if platform.system() != "Windows" or not path.is_file():
        return "unknown"
    try:
        size = ctypes.windll.version.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            raise OSError
        buffer = ctypes.create_string_buffer(size)
        if not ctypes.windll.version.GetFileVersionInfoW(str(path), 0, size, buffer):
            raise OSError
        value = ctypes.c_void_p()
        length = wintypes.UINT()
        if not ctypes.windll.version.VerQueryValueW(buffer, "\\", ctypes.byref(value), ctypes.byref(length)):
            raise OSError

        class VSFixedFileInfo(ctypes.Structure):
            _fields_ = [(name, wintypes.DWORD) for name in (
                "signature", "struct_version", "file_version_ms", "file_version_ls",
                "product_version_ms", "product_version_ls", "flags_mask", "flags",
                "file_os", "file_type", "file_subtype", "file_date_ms", "file_date_ls",
            )]

        info = ctypes.cast(value, ctypes.POINTER(VSFixedFileInfo)).contents
        return ".".join(map(str, (
            info.file_version_ms >> 16, info.file_version_ms & 0xFFFF,
            info.file_version_ls >> 16, info.file_version_ls & 0xFFFF,
        )))
    except (AttributeError, OSError, ValueError):
        parent_version = path.parent.name
        return parent_version if parent_version[:1].isdigit() else "unknown"


def _running_processes() -> dict[Path, list[int]]:
    if platform.system() != "Windows":
        return {}
    result: dict[Path, list[int]] = {}
    try:
        kernel32 = ctypes.windll.kernel32
        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            return result

        class ProcessEntry32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
            ]

        entry = ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.casefold() in EXECUTABLE_NAMES:
                handle = kernel32.OpenProcess(0x1000, False, entry.th32ProcessID)
                if handle:
                    capacity = wintypes.DWORD(32768)
                    buffer = ctypes.create_unicode_buffer(capacity.value)
                    if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(capacity)):
                        result.setdefault(Path(buffer.value), []).append(int(entry.th32ProcessID))
                    kernel32.CloseHandle(handle)
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        kernel32.CloseHandle(snapshot)
    except (AttributeError, OSError, ValueError):
        return result
    return result


def _registry_candidates() -> Iterator[Path]:
    if platform.system() != "Windows":
        return
    try:
        import winreg
    except ImportError:
        return
    roots = ((winreg.HKEY_CURRENT_USER, 0), (winreg.HKEY_LOCAL_MACHINE, 0),
             (winreg.HKEY_LOCAL_MACHINE, getattr(winreg, "KEY_WOW64_32KEY", 0)))
    app_keys = [
        r"Software\Microsoft\Windows\CurrentVersion\App Paths\Weixin.exe",
        r"Software\Microsoft\Windows\CurrentVersion\App Paths\WeChat.exe",
    ]
    uninstall = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
    for root, view in roots:
        for key_name in app_keys:
            try:
                with winreg.OpenKey(root, key_name, 0, winreg.KEY_READ | view) as key:
                    value = winreg.QueryValue(key, None)
                    if value:
                        yield Path(str(value).strip('"'))
            except OSError:
                pass
        try:
            with winreg.OpenKey(root, uninstall, 0, winreg.KEY_READ | view) as parent:
                for index in range(winreg.QueryInfoKey(parent)[0]):
                    try:
                        with winreg.OpenKey(parent, winreg.EnumKey(parent, index)) as key:
                            display = str(winreg.QueryValueEx(key, "DisplayName")[0]).casefold()
                            if not any(token in display for token in ("wechat", "weixin", "微信")):
                                continue
                            for field in ("DisplayIcon", "InstallLocation"):
                                try:
                                    raw = str(winreg.QueryValueEx(key, field)[0]).split(",", 1)[0].strip('"')
                                    candidate = Path(raw)
                                    if candidate.is_dir():
                                        for name in ("Weixin.exe", "WeChat.exe"):
                                            yield candidate / name
                                    else:
                                        yield candidate
                                except OSError:
                                    pass
                    except OSError:
                        continue
        except OSError:
            pass


def _known_candidates() -> tuple[list[Path], list[Path]]:
    env = os.environ
    exe_paths: list[Path] = []
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "ProgramData"):
        base = env.get(variable)
        if not base:
            continue
        for vendor in ("Tencent", "WeChat", "Weixin"):
            for product in ("WeChat", "Weixin"):
                exe_paths.append(Path(base) / vendor / product / f"{product}.exe")
    home = Path.home()
    data_roots = [
        home / "Documents" / "WeChat Files",
        home / "Documents" / "xwechat_files",
        home / "Documents" / "Weixin Files",
    ]
    return exe_paths, data_roots


def _fixed_drives() -> list[Path]:
    if platform.system() != "Windows":
        return [Path("/")]
    drives: list[Path] = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for index, letter in enumerate(string.ascii_uppercase):
            if mask & (1 << index):
                root = f"{letter}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:
                    drives.append(Path(root))
    except (AttributeError, OSError):
        pass
    return drives


def _bounded_scan(roots: Iterable[Path], max_depth: int, seconds: float,
                  max_directories: int = 100_000) -> tuple[list[Path], list[Path], dict[str, object]]:
    started = time.monotonic()
    root_list = list(roots)
    queue = deque((root, 0) for root in root_list)
    executables: list[Path] = []
    data_roots: list[Path] = []
    visited = 0
    timed_out = False
    while queue and visited < max_directories:
        if time.monotonic() - started >= seconds:
            timed_out = True
            break
        current, depth = queue.popleft()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        visited += 1
        for entry in entries:
            name = entry.name.casefold()
            try:
                if entry.is_file(follow_symlinks=False) and name in EXECUTABLE_NAMES:
                    executables.append(Path(entry.path))
                elif entry.is_dir(follow_symlinks=False):
                    child = Path(entry.path)
                    if name in DATA_ROOT_NAMES:
                        data_roots.append(child)
                        continue
                    if depth < max_depth and name not in WALK_IGNORES and not entry.is_symlink():
                        queue.append((child, depth + 1))
            except OSError:
                continue
    return executables, data_roots, {
        "enabled": True, "roots": len(root_list), "directories_visited": visited,
        "time_seconds": round(time.monotonic() - started, 3),
        "timed_out": timed_out, "directory_limit_reached": visited >= max_directories,
    }


def _account_candidates(data_root: Path, source: str) -> list[AccountCandidate]:
    accounts: list[AccountCandidate] = []
    try:
        children = [item for item in data_root.iterdir() if item.is_dir()]
    except OSError:
        return accounts
    for account_dir in children:
        if account_dir.name.casefold() in ACCOUNT_IGNORES:
            continue
        names = {item.name.casefold() for item in _safe_iterdir(account_dir)}
        layout = "unknown"
        db_bases: list[Path] = []
        if "db_storage" in names:
            layout = "weixin-4"
            db_bases.append(account_dir / "db_storage")
        if "msg" in names or "filestorage" in names:
            layout = "wechat-3" if layout == "unknown" else layout
            db_bases.extend([account_dir / "Msg", account_dir / "msg"])
        if layout == "unknown":
            continue
        databases: list[Path] = []
        for base in db_bases:
            if base.is_dir():
                databases.extend(_find_databases(base, max_depth=4))
        mtimes = [path.stat().st_mtime_ns for path in databases if _safe_is_file(path)]
        if not mtimes:
            try:
                mtimes = [account_dir.stat().st_mtime_ns]
            except OSError:
                mtimes = [0]
        accounts.append(AccountCandidate(
            data_root=data_root, account_dir=account_dir,
            last_modified_ns=max(mtimes), database_paths=tuple(sorted(set(databases))),
            layout=layout, sources=(source,),
        ))
    return accounts


def _safe_iterdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except OSError:
        return []


def _safe_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _find_databases(root: Path, max_depth: int) -> list[Path]:
    found: list[Path] = []
    queue = [(root, 0)]
    while queue:
        current, depth = queue.pop()
        for item in _safe_iterdir(current):
            try:
                if item.is_file() and item.suffix.casefold() in {".db", ".sqlite"}:
                    found.append(item)
                elif depth < max_depth and item.is_dir() and not item.is_symlink():
                    queue.append((item, depth + 1))
            except OSError:
                continue
    return found


def discover(scan_fixed_drives: bool = False, max_depth: int = 5,
             time_budget_seconds: float = 12.0) -> DiscoveryReport:
    running = _running_processes()
    known_exes, known_data = _known_candidates()
    executable_sources: dict[Path, set[str]] = {}
    data_sources: dict[Path, set[str]] = {}

    def add(mapping: dict[Path, set[str]], path: Path, source: str) -> None:
        try:
            resolved = path.resolve(strict=False)
        except OSError:
            resolved = path
        mapping.setdefault(resolved, set()).add(source)

    for path in known_exes:
        if path.is_file():
            add(executable_sources, path, "known-location")
    for path in _registry_candidates():
        if path.is_file() and path.name.casefold() in EXECUTABLE_NAMES:
            add(executable_sources, path, "registry")
    for path in running:
        add(executable_sources, path, "running-process")
    for path in known_data:
        if path.is_dir():
            add(data_sources, path, "known-location")

    scan_info: dict[str, object] = {"enabled": False}
    if scan_fixed_drives:
        roots = _fixed_drives()
        scan_exes, scan_data, scan_info = _bounded_scan(
            roots, max_depth=max_depth, seconds=time_budget_seconds
        )
        for path in scan_exes:
            add(executable_sources, path, "bounded-fixed-drive-scan")
        for path in scan_data:
            add(data_sources, path, "bounded-fixed-drive-scan")

    installations = []
    for path, sources in sorted(executable_sources.items(), key=lambda pair: str(pair[0]).casefold()):
        pids = tuple(sorted(running.get(path, [])))
        installations.append(InstallationCandidate(
            executable=path, version=_file_version(path), architecture=platform.machine(),
            running_process_ids=pids, sources=tuple(sorted(sources)),
        ))

    accounts_by_path: dict[Path, AccountCandidate] = {}
    for root, sources in data_sources.items():
        for account in _account_candidates(root, "+".join(sorted(sources))):
            existing = accounts_by_path.get(account.account_dir)
            if existing is None or account.last_modified_ns > existing.last_modified_ns:
                accounts_by_path[account.account_dir] = account
    accounts = tuple(sorted(accounts_by_path.values(), key=lambda item: item.last_modified_ns, reverse=True))
    return DiscoveryReport(tuple(installations), accounts, scan_info)


def report_to_dict(report: DiscoveryReport, show_paths: bool = False) -> dict[str, object]:
    now_ns = time.time_ns()

    def freshness(mtime_ns: int) -> str:
        days = max(0.0, (now_ns - mtime_ns) / 86_400_000_000_000)
        return "active" if days <= 30 else "recent" if days <= 180 else "stale"

    def database_roles(paths: tuple[Path, ...]) -> dict[str, list[Path]]:
        roles: dict[str, list[Path]] = {
            "message": [], "session": [], "contact": [], "voice_media": [], "other": [],
        }
        for path in paths:
            name = path.name.casefold()
            parent = path.parent.name.casefold()
            if parent == "message" and re.fullmatch(r"message_\d+\.db", name):
                roles["message"].append(path)
            elif name == "session.db":
                roles["session"].append(path)
            elif name == "contact.db":
                roles["contact"].append(path)
            elif parent == "message" and re.fullmatch(r"media_\d+\.db", name):
                roles["voice_media"].append(path)
            else:
                roles["other"].append(path)
        return {key: sorted(value, key=lambda item: str(item).casefold()) for key, value in roles.items()}

    accounts = []
    for item in report.accounts:
        roles = database_roles(item.database_paths)
        account_payload: dict[str, object] = {
            "id": _stable_id("account", item.account_dir),
            "data_root": str(item.data_root) if show_paths else _path_hint(item.data_root),
            "layout": item.layout,
            "freshness": freshness(item.last_modified_ns),
            "last_database_update_utc": datetime.fromtimestamp(
                item.last_modified_ns / 1_000_000_000, timezone.utc
            ).isoformat(),
            "database_count": len(item.database_paths),
            "database_role_counts": {key: len(value) for key, value in roles.items()},
            "sources": list(item.sources),
        }
        if show_paths:
            account_payload["account_root"] = str(item.account_dir)
            account_payload["database_plan"] = {
                key: [str(path) for path in value] for key, value in roles.items()
            }
        accounts.append(account_payload)

    return {
        "schema_version": 1,
        "privacy": {"absolute_paths_included": show_paths, "account_names_included": False},
        "installations": [
            {
                "id": _stable_id("install", item.executable),
                "executable": str(item.executable) if show_paths else _path_hint(item.executable),
                "version": item.version,
                "architecture": item.architecture,
                "running": bool(item.running_process_ids),
                "process_count": len(item.running_process_ids),
                "sources": list(item.sources),
            }
            for item in report.installations
        ],
        "accounts": accounts,
        "scan": report.scan,
    }
