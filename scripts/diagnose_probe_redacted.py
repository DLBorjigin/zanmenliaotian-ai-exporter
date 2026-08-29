from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import time

from wechat_ai_exporter.key_probe import (
    EXACT_SALT_ADAPTER, SUPPORTED_ADAPTERS, _candidate_wcdb_config_keys,
    _landmark_offsets, _open_reader, _owner_pointer_address, _process_ids,
    _remote_std_string, _weixin_module, derive_database_key, extract_xor_material,
)
from wechat_ai_exporter.key_validation import PAGE_SIZE, WEIXIN4, verify_first_page, wipe_key


def diagnose(database: Path) -> dict[str, object]:
    database = database.resolve(strict=True)
    with database.open("rb") as handle:
        page = handle.read(PAGE_SIZE)
    report: dict[str, object] = {
        "process_count": 0,
        "module_found_count": 0,
        "module_image_readable_count": 0,
        "static_material_found_count": 0,
        "landmark_count": 0,
        "adapters": {
            adapter.name: {
                "owner_pointer_read": 0,
                "owner_pointer_plausible": 0,
                "cfg_pointer_read": 0,
                "cfg_pointer_plausible": 0,
                "cipher_descriptor_read": 0,
                "cipher_32_bytes": 0,
                "decoded_key_validated_directly": 0,
                "database_key_validated": 0,
            }
            for adapter in SUPPORTED_ADAPTERS
        },
        "secrets_printed": False,
        "memory_dump_created": False,
        "process_modified": False,
    }
    pids = _process_ids()
    report["process_count"] = len(pids)
    adapters = report["adapters"]
    assert isinstance(adapters, dict)
    adapters[EXACT_SALT_ADAPTER] = {
        "structured_candidates_found": 0,
        "database_key_validated": 0,
    }
    deadline = time.monotonic() + 20.0
    for pid in pids:
        module = _weixin_module(pid)
        if module is None:
            continue
        report["module_found_count"] = int(report["module_found_count"]) + 1
        base, size, dll_path = module
        try:
            material = extract_xor_material(dll_path.read_bytes())
        except OSError:
            material = None
        if material is not None:
            report["static_material_found_count"] = int(report["static_material_found_count"]) + 1
        handle, read = _open_reader(pid)
        try:
            image = read(base, size)
            if image is None:
                continue
            report["module_image_readable_count"] = int(report["module_image_readable_count"]) + 1
            landmarks = list(_landmark_offsets(image))
            report["landmark_count"] = int(report["landmark_count"]) + len(landmarks)
            for adapter in SUPPORTED_ADAPTERS:
                counts = adapters[adapter.name]
                assert isinstance(counts, dict)
                for landmark in landmarks:
                    owner_data = read(_owner_pointer_address(base, landmark, adapter), 8)
                    if not owner_data:
                        continue
                    counts["owner_pointer_read"] += 1
                    owner = struct.unpack("<Q", owner_data)[0]
                    if not 0x10000 <= owner < 0x800000000000:
                        continue
                    counts["owner_pointer_plausible"] += 1
                    cfg_data = read(owner + adapter.cfg_pointer_offset, 8)
                    if not cfg_data:
                        continue
                    counts["cfg_pointer_read"] += 1
                    cfg = struct.unpack("<Q", cfg_data)[0]
                    if not 0x10000 <= cfg < 0x800000000000:
                        continue
                    counts["cfg_pointer_plausible"] += 1
                    encrypted = _remote_std_string(read, cfg + adapter.cfg_cipher_offset, binary=True)
                    if encrypted is None:
                        continue
                    counts["cipher_descriptor_read"] += 1
                    if not isinstance(encrypted, bytes) or len(encrypted) != 32 or material is None:
                        continue
                    counts["cipher_32_bytes"] += 1
                    master = bytearray(a ^ b for a, b in zip(encrypted, material))
                    derived = bytearray()
                    try:
                        if verify_first_page(master, page, WEIXIN4):
                            counts["decoded_key_validated_directly"] += 1
                        derived = derive_database_key(master, page[:16])
                        if verify_first_page(derived, page, WEIXIN4):
                            counts["database_key_validated"] += 1
                    finally:
                        wipe_key(master)
                        wipe_key(derived)
        finally:
            import ctypes
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
        exact_counts = adapters[EXACT_SALT_ADAPTER]
        assert isinstance(exact_counts, dict)
        for candidate in _candidate_wcdb_config_keys(pid, page, deadline):
            try:
                exact_counts["structured_candidates_found"] += 1
                if verify_first_page(candidate, page, WEIXIN4):
                    exact_counts["database_key_validated"] += 1
            finally:
                wipe_key(candidate)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--confirm-read-only-config-diagnostic", action="store_true")
    args = parser.parse_args()
    if not args.confirm_read_only_config_diagnostic:
        raise SystemExit("explicit read-only configuration-diagnostic authorization is required")
    print(json.dumps(diagnose(args.database), ensure_ascii=False, indent=2))
