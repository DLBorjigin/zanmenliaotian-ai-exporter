from __future__ import annotations

import ctypes
from ctypes.util import find_library
from functools import lru_cache
from pathlib import Path
import shutil
import sys


ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
MAX_ZSTD_OUTPUT = 16 * 1024 * 1024
ZSTD_CONTENTSIZE_UNKNOWN = (1 << 64) - 1
ZSTD_CONTENTSIZE_ERROR = (1 << 64) - 2


def _library_candidates() -> list[str]:
    candidates: list[Path | str] = []
    executable = Path(sys.executable).resolve()
    for parent in executable.parents[:4]:
        candidates.extend((
            parent / "native" / "git" / "mingw64" / "bin" / "libzstd.dll",
            parent / "native" / "poppler" / "Library" / "bin" / "libzstd.dll",
            parent / "native" / "poppler" / "Library" / "bin" / "zstd.dll",
        ))
    git = shutil.which("git.exe") or shutil.which("git")
    if git:
        git_path = Path(git).resolve()
        candidates.extend((
            git_path.parent / "libzstd.dll",
            git_path.parent.parent / "mingw64" / "bin" / "libzstd.dll",
        ))
    located = find_library("zstd")
    if located:
        candidates.append(located)
    result: list[str] = []
    for candidate in candidates:
        text = str(candidate)
        if text not in result and (not isinstance(candidate, Path) or candidate.is_file()):
            result.append(text)
    return result


@lru_cache(maxsize=1)
def _zstd_library():
    for candidate in _library_candidates():
        try:
            dll = ctypes.WinDLL(candidate) if sys.platform == "win32" else ctypes.CDLL(candidate)
            dll.ZSTD_getFrameContentSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            dll.ZSTD_getFrameContentSize.restype = ctypes.c_ulonglong
            dll.ZSTD_decompress.argtypes = [
                ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t
            ]
            dll.ZSTD_decompress.restype = ctypes.c_size_t
            dll.ZSTD_isError.argtypes = [ctypes.c_size_t]
            dll.ZSTD_isError.restype = ctypes.c_uint
            return dll
        except (OSError, AttributeError):
            continue
    return None


def decode_zstd_if_needed(
    data: bytes, max_output: int = MAX_ZSTD_OUTPUT
) -> bytes | None:
    """Return raw data, decompressed data, or None for an unavailable/invalid frame."""
    if not data.startswith(ZSTD_MAGIC):
        return data
    dll = _zstd_library()
    if dll is None:
        return None
    source = ctypes.create_string_buffer(data)
    size = int(dll.ZSTD_getFrameContentSize(source, len(data)))
    if size in {ZSTD_CONTENTSIZE_UNKNOWN, ZSTD_CONTENTSIZE_ERROR} or not 0 < size <= max_output:
        return None
    target = ctypes.create_string_buffer(size)
    written = int(dll.ZSTD_decompress(target, size, source, len(data)))
    if dll.ZSTD_isError(written) or written != size:
        return None
    return target.raw[:written]
