from __future__ import annotations

import argparse
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import platform
import sqlite3
import sys
import uuid

from . import __version__
from .chat_data import ChatDataError, ChatDataset, parse_time_bound
from .discovery import discover, report_to_dict
from .decrypt import DecryptionError, decrypt_database
from .exporter import ExportError, export_chat
from .key_validation import KeyInputError, profile_for_layout, prompt_image_key, prompt_key, wipe_key
from .key_probe import (
    ProbeError, READ_ONLY_PROBE_ADAPTER_NAMES, probe_database_key,
    wait_for_manual_weixin_exit,
)
from .media import MediaResolver
from .models import AccessMode, ExportScope, MessageKind
from .security import AUTHORIZATION_MATRIX
from .snapshot import SnapshotError, create_verified_snapshot
from .schema_inspector import SchemaInspectionError, inspect_schema


def _doctor_payload() -> dict[str, object]:
    return {
        "product": "wechat-ai-exporter",
        "version": __version__,
        "platform": platform.system(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "available_modes": [mode.value for mode in AccessMode],
        "authorization": {
            mode.value: {
                "mutates_wechat_process": item.mutates_wechat_process,
                "reads_message_bodies": item.reads_message_bodies,
                "copies_attachments": item.copies_attachments,
                "requires_explicit_confirmation": item.requires_explicit_confirmation,
            }
            for mode, item in AUTHORIZATION_MATRIX.items()
        },
        "network_required": False,
        "optional_network_media_download": True,
        "aes_backend_available": importlib.util.find_spec("cryptography") is not None,
        "read_only_probe_adapters": list(READ_ONLY_PROBE_ADAPTER_NAMES),
        "native_hook_bundled": False,
        "status": "runtime_ready",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wechat-ai-export",
        description="Local, read-only WeChat chat export tooling.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="Report runtime and authorization capabilities.")
    doctor.add_argument("--json", action="store_true", dest="as_json")
    onboard = sub.add_parser(
        "onboard", help="Run a body-free first-use check and report the next safe action."
    )
    onboard.add_argument(
        "--scan-fixed-drives", action="store_true",
        help="Run the bounded custom-location scan after user approval.",
    )
    onboard.add_argument("--max-depth", type=int, default=5, choices=range(1, 9), metavar="1-8")
    onboard.add_argument("--time-budget", type=float, default=12.0, metavar="SECONDS")
    onboard.add_argument(
        "--show-paths", action="store_true",
        help="Include the selected account root and exact database plan locally.",
    )
    onboard.add_argument("--json", action="store_true", dest="as_json")
    find = sub.add_parser("discover", help="Find WeChat installations and account data without reading messages.")
    find.add_argument("--scan-fixed-drives", action="store_true", help="Run a bounded scan for custom locations.")
    find.add_argument("--max-depth", type=int, default=5, choices=range(1, 9), metavar="1-8")
    find.add_argument("--time-budget", type=float, default=12.0, metavar="SECONDS")
    find.add_argument("--show-paths", action="store_true", help="Include absolute local paths in output.")
    find.add_argument("--json", action="store_true", dest="as_json")
    prepare = sub.add_parser(
        "prepare-known-key",
        help="Validate a locally entered key and create an encrypted read-only working snapshot.",
    )
    prepare.add_argument("--database", required=True)
    prepare.add_argument("--layout", required=True, choices=("weixin-4", "wechat-3"))
    prepare.add_argument("--snapshot-dir", required=True)
    prepare.add_argument("--input", choices=("console", "dialog"), default="console", dest="input_mode")
    prepare.add_argument(
        "--confirm-authorized", action="store_true",
        help="Confirm this is the user's authorized local account and database.",
    )
    prepare.add_argument("--json", action="store_true", dest="as_json")
    auto_prepare = sub.add_parser(
        "prepare-auto-key",
        help="With explicit authorization, run a bounded read-only Weixin memory probe and create an encrypted snapshot.",
    )
    auto_prepare.add_argument("--database", required=True)
    auto_prepare.add_argument("--snapshot-dir", required=True)
    auto_prepare.add_argument("--time-budget", type=float, default=20.0, metavar="SECONDS")
    auto_prepare.add_argument(
        "--confirm-read-process-memory", action="store_true",
        help="Confirm read-only inspection of local Weixin.exe memory for this exact database.",
    )
    auto_prepare.add_argument(
        "--wait-for-manual-exit", action="store_true",
        help="After key validation, wait for the user to close Weixin before snapshotting.",
    )
    auto_prepare.add_argument(
        "--manual-close-timeout", type=float, default=180.0, metavar="SECONDS",
    )
    auto_prepare.add_argument(
        "--confirm-manual-close-flow", action="store_true",
        help="Confirm that the tool may wait, but must never terminate Weixin itself.",
    )
    auto_prepare.add_argument("--json", action="store_true", dest="as_json")
    inspect = sub.add_parser(
        "inspect-known-key",
        help="Decrypt a verified snapshot locally and report schema compatibility without reading rows.",
    )
    inspect.add_argument("--snapshot-database", required=True)
    inspect.add_argument("--layout", required=True, choices=("weixin-4", "wechat-3"))
    inspect.add_argument("--work-dir", required=True)
    inspect.add_argument("--input", choices=("console", "dialog"), default="console", dest="input_mode")
    inspect.add_argument("--confirm-authorized", action="store_true")
    inspect.add_argument("--keep-decrypted", action="store_true")
    inspect.add_argument(
        "--confirm-retain-decrypted", action="store_true",
        help="Separately confirm retention of a plaintext database containing chat data.",
    )
    inspect.add_argument("--json", action="store_true", dest="as_json")
    auto_inspect = sub.add_parser(
        "inspect-auto-key",
        help="Read-only probe a running Weixin key, inspect an encrypted snapshot schema, and discard plaintext.",
    )
    auto_inspect.add_argument("--snapshot-database", required=True)
    auto_inspect.add_argument("--key-database", required=True)
    auto_inspect.add_argument("--work-dir", required=True)
    auto_inspect.add_argument("--time-budget", type=float, default=20.0, metavar="SECONDS")
    auto_inspect.add_argument("--confirm-read-process-memory", action="store_true")
    auto_inspect.add_argument("--confirm-schema-inspection", action="store_true")
    auto_inspect.add_argument("--json", action="store_true", dest="as_json")
    snapshot_inspect = sub.add_parser(
        "snapshot-inspect-auto-key",
        help="Probe one exact live database once, snapshot it consistently, inspect schema, and discard plaintext.",
    )
    snapshot_inspect.add_argument("--database", required=True)
    snapshot_inspect.add_argument("--snapshot-dir", required=True)
    snapshot_inspect.add_argument("--work-dir", required=True)
    snapshot_inspect.add_argument("--time-budget", type=float, default=20.0, metavar="SECONDS")
    snapshot_inspect.add_argument("--confirm-read-process-memory", action="store_true")
    snapshot_inspect.add_argument("--confirm-schema-inspection", action="store_true")
    snapshot_inspect.add_argument("--json", action="store_true", dest="as_json")
    catalog_preview = sub.add_parser(
        "catalog-preview-auto-key",
        help="Temporarily decrypt exact message/session/contact snapshots and report conversation metadata and type counts only.",
    )
    catalog_preview.add_argument(
        "--message-database", required=True, action="append",
        help="Exact encrypted message database; repeat for multiple message_N.db files.",
    )
    catalog_preview.add_argument("--session-database", required=True)
    catalog_preview.add_argument("--contact-database", required=True)
    catalog_preview.add_argument("--snapshot-dir", required=True)
    catalog_preview.add_argument("--work-dir", required=True)
    catalog_preview.add_argument("--time-budget", type=float, default=20.0, metavar="SECONDS")
    catalog_preview.add_argument("--limit-conversations", type=int, default=500)
    catalog_preview.add_argument("--confirm-read-process-memory", action="store_true")
    catalog_preview.add_argument("--confirm-private-metadata", action="store_true")
    catalog_preview.add_argument("--confirm-count-query", action="store_true")
    catalog_preview.add_argument("--json", action="store_true", dest="as_json")
    selection_auto = sub.add_parser(
        "selection-preview-auto-key",
        help="Preview one exact conversation/time/type selection with transient automatic keys and no message bodies.",
    )
    _add_auto_dataset_arguments(selection_auto)
    selection_auto.add_argument("--conversation-id", required=True)
    selection_auto.add_argument("--start")
    selection_auto.add_argument("--end")
    selection_auto.add_argument(
        "--include", default="text,image,video,audio,file,link",
    )
    selection_auto.add_argument("--confirm-private-metadata", action="store_true")
    selection_auto.add_argument("--confirm-count-query", action="store_true")
    selection_auto.add_argument("--json", action="store_true", dest="as_json")
    export_auto = sub.add_parser(
        "export-auto-key",
        help="Export one approved conversation scope through transient automatic keys without retaining plaintext databases.",
    )
    _add_auto_dataset_arguments(export_auto)
    export_auto.add_argument("--conversation-id", required=True)
    export_auto.add_argument("--start")
    export_auto.add_argument("--end")
    export_auto.add_argument("--include", default="text,image,video,audio,file,link")
    export_auto.add_argument("--output-dir", required=True)
    export_auto.add_argument("--limit", type=int, default=100_000)
    export_auto.add_argument("--include-assets", action="store_true")
    export_auto.add_argument(
        "--split-asset-bundles", action="store_true", default=True,
        help="Compatibility alias: media is separated from the records ZIP by default.",
    )
    export_auto.add_argument(
        "--embed-assets", action="store_false", dest="split_asset_bundles",
        help="Advanced compatibility mode: embed selected media bytes in the records ZIP.",
    )
    export_auto.add_argument("--account-root")
    export_auto.add_argument("--voice-media-database")
    export_auto.add_argument("--max-asset-bytes", type=int, default=512 * 1024 * 1024)
    export_auto.add_argument(
        "--video-asset", choices=("original", "thumbnail", "both"), default="original",
        help="Select complete video files, video thumbnails, or both.",
    )
    export_auto.add_argument("--confirm-private-metadata", action="store_true")
    export_auto.add_argument("--confirm-selection", action="store_true")
    export_auto.add_argument("--confirm-read-message-bodies", action="store_true")
    export_auto.add_argument("--confirm-copy-attachments", action="store_true")
    export_auto.add_argument("--confirm-image-key-discovery", action="store_true")
    export_auto.add_argument("--confirm-voice-media-database", action="store_true")
    export_auto.add_argument("--allow-remote-media-download", action="store_true")
    export_auto.add_argument("--confirm-remote-media-download", action="store_true")
    export_auto.add_argument("--json", action="store_true", dest="as_json")
    sessions = sub.add_parser(
        "list-sessions", help="List authorized conversations from retained plaintext snapshots."
    )
    _add_dataset_arguments(sessions)
    sessions.add_argument("--confirm-authorized", action="store_true")
    sessions.add_argument("--json", action="store_true", dest="as_json")
    preview = sub.add_parser(
        "preview-selection", help="Count selected messages by type without reading message bodies."
    )
    _add_dataset_arguments(preview)
    preview.add_argument("--conversation-id", required=True)
    preview.add_argument("--start")
    preview.add_argument("--end")
    preview.add_argument(
        "--include", default="text,image,video,audio,file,link",
        help="Comma-separated normalized message kinds.",
    )
    preview.add_argument("--confirm-authorized", action="store_true")
    preview.add_argument("--json", action="store_true", dest="as_json")
    export = sub.add_parser(
        "export-plaintext", help="Package an approved scope from retained plaintext snapshots."
    )
    _add_dataset_arguments(export)
    export.add_argument("--conversation-id", required=True)
    export.add_argument("--start")
    export.add_argument("--end")
    export.add_argument("--include", default="text,image,video,audio,file,link")
    export.add_argument("--output-dir", required=True)
    export.add_argument("--limit", type=int, default=100_000)
    export.add_argument("--include-assets", action="store_true")
    export.add_argument(
        "--split-asset-bundles", action="store_true", default=True,
        help="Compatibility alias: media is separated from the records ZIP by default.",
    )
    export.add_argument(
        "--embed-assets", action="store_false", dest="split_asset_bundles",
        help="Advanced compatibility mode: embed selected media bytes in the records ZIP.",
    )
    export.add_argument("--account-root")
    export.add_argument("--media-database", action="append", default=[])
    export.add_argument("--max-asset-bytes", type=int, default=512 * 1024 * 1024)
    export.add_argument(
        "--video-asset", choices=("original", "thumbnail", "both"), default="original",
        help="Select complete video files, video thumbnails, or both.",
    )
    export.add_argument(
        "--image-key-input", choices=("console", "dialog"),
        help="Securely prompt for a separate 16-character Weixin V2 image key.",
    )
    export.add_argument("--image-xor-key", type=int, choices=range(0, 256), metavar="0-255")
    export.add_argument(
        "--auto-image-key-database",
        help="Exact encrypted DB used to verify a separately authorized read-only image-key probe.",
    )
    export.add_argument("--image-key-time-budget", type=float, default=20.0, metavar="SECONDS")
    export.add_argument("--confirm-authorized", action="store_true")
    export.add_argument("--confirm-selection", action="store_true")
    export.add_argument("--confirm-copy-attachments", action="store_true")
    export.add_argument("--confirm-image-key-use", action="store_true")
    export.add_argument("--confirm-read-process-memory-for-image-key", action="store_true")
    export.add_argument("--allow-remote-media-download", action="store_true")
    export.add_argument("--confirm-remote-media-download", action="store_true")
    export.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _add_dataset_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--message-database", required=True, action="append")
    parser.add_argument("--layout", required=True, choices=("weixin-4", "wechat-3"))
    parser.add_argument("--session-database")
    parser.add_argument("--contact-database")


def _add_auto_dataset_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--message-database", required=True, action="append",
        help="Exact encrypted message database; repeat for multiple message_N.db files.",
    )
    parser.add_argument("--session-database", required=True)
    parser.add_argument("--contact-database", required=True)
    parser.add_argument("--snapshot-dir", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--time-budget", type=float, default=20.0, metavar="SECONDS")
    parser.add_argument("--confirm-read-process-memory", action="store_true")


def _auto_sources_from_args(args: argparse.Namespace, include_media: bool = False) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    for index, value in enumerate(args.message_database):
        role = "message" if index == 0 else f"message-{index}"
        sources[role] = Path(value)
    sources["session"] = Path(args.session_database)
    sources["contact"] = Path(args.contact_database)
    if include_media and getattr(args, "voice_media_database", None):
        sources["media"] = Path(args.voice_media_database)
    return sources


def _message_plaintexts(plaintext: dict[str, Path]) -> list[Path]:
    return [path for role, path in plaintext.items() if role == "message" or role.startswith("message-")]


def _dataset_from_args(args: argparse.Namespace) -> ChatDataset:
    return ChatDataset(
        [Path(item) for item in args.message_database], args.layout,
        Path(args.session_database) if args.session_database else None,
        Path(args.contact_database) if args.contact_database else None,
    )


def _included_kinds(value: str) -> frozenset[MessageKind]:
    try:
        kinds = frozenset(MessageKind(item.strip().casefold()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise ChatDataError("The include list contains an unsupported message kind.") from exc
    if not kinds:
        raise ChatDataError("At least one message kind must be included.")
    return kinds


@contextmanager
def _auto_plaintext_bundle(sources: dict[str, Path], snapshot_root: Path,
                           work_dir: Path, time_budget: float,
                           derive_image_key: bool = False):
    plaintext: dict[str, Path] = {}
    snapshots: dict[str, object] = {}
    image_key = bytearray()
    image_xor_key: int | None = None
    token = uuid.uuid4().hex[:10]
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
        for role, source_database in sources.items():
            database_key = bytearray()
            probe = None
            try:
                probe = probe_database_key(
                    source_database, authorized=True,
                    time_budget_seconds=max(1.0, min(time_budget, 60.0)),
                    derive_media_key=bool(derive_image_key and role == "message"),
                )
                database_key = probe.key
                if derive_image_key and role == "message":
                    if probe.image_key is None or probe.image_xor_key is None:
                        raise ProbeError("The verified adapter did not produce a media key.")
                    image_key = probe.image_key
                    image_xor_key = probe.image_xor_key
                snapshot = create_verified_snapshot(
                    database=source_database,
                    destination_parent=snapshot_root / role,
                    key_material=database_key,
                    profile=profile_for_layout("weixin-4"),
                )
                output = work_dir / f"decrypted-{role}-{token}.sqlite"
                decrypt_database(
                    snapshot.database, output, database_key,
                    profile_for_layout("weixin-4"),
                )
                plaintext[role] = output
                snapshots[role] = snapshot
            finally:
                wipe_key(database_key)
                if (
                    probe is not None and isinstance(probe.image_key, bytearray)
                    and probe.image_key is not image_key
                ):
                    wipe_key(probe.image_key)
        yield plaintext, snapshots, image_key, image_xor_key
    finally:
        for path in plaintext.values():
            path.unlink(missing_ok=True)
        wipe_key(image_key)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        payload = _doctor_payload()
        if args.as_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"wechat-ai-exporter {payload['version']}: {payload['status']}")
        return 0
    if args.command == "onboard":
        doctor_payload = _doctor_payload()
        report = discover(
            scan_fixed_drives=args.scan_fixed_drives,
            max_depth=args.max_depth,
            time_budget_seconds=max(0.5, min(args.time_budget, 60.0)),
        )
        discovery_payload = report_to_dict(report, show_paths=args.show_paths)
        running = [item for item in discovery_payload["installations"] if item["running"]]
        active = [item for item in discovery_payload["accounts"] if item["freshness"] == "active"]
        usable = [
            item for item in active
            if item["database_role_counts"]["message"]
            and item["database_role_counts"]["session"]
            and item["database_role_counts"]["contact"]
        ]
        if not doctor_payload["aes_backend_available"]:
            status, next_action = "dependency_missing", "Use a Python runtime with the cryptography package."
        elif not running:
            status, next_action = "open_wechat", "Open and sign in to WeChat, then run onboarding again."
        elif not usable and not args.scan_fixed_drives:
            status, next_action = (
                "needs_fixed_drive_scan",
                "Ask once for a bounded read-only fixed-drive scan, then rerun with --scan-fixed-drives.",
            )
        elif not usable:
            status, next_action = "account_not_found", "Check WeChat storage settings or provide the data location."
        elif len(usable) > 1:
            status, next_action = "choose_account", "Ask the user to choose one opaque active account ID."
        elif not args.show_paths:
            status, next_action = (
                "ready_for_path_confirmation",
                "Confirm local path disclosure, then rerun with --show-paths for the exact database plan.",
            )
        else:
            status, next_action = "ready", "Use the exact database plan for a count-only conversation preview."
        payload = {
            "status": status,
            "version": __version__,
            "next_action": next_action,
            "message_bodies_read": 0,
            "process_memory_read": False,
            "network_used": False,
            "doctor": doctor_payload,
            "discovery": discovery_payload,
            "usable_account_ids": [item["id"] for item in usable],
        }
        if args.as_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"{status}: {next_action}")
        return 0 if status in {"ready", "ready_for_path_confirmation"} else 2
    if args.command == "discover":
        report = discover(
            scan_fixed_drives=args.scan_fixed_drives,
            max_depth=args.max_depth,
            time_budget_seconds=max(0.5, min(args.time_budget, 60.0)),
        )
        payload = report_to_dict(report, show_paths=args.show_paths)
        if args.as_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(
                f"Found {len(payload['installations'])} installation(s) and "
                f"{len(payload['accounts'])} account data set(s)."
            )
        return 0
    if args.command == "prepare-known-key":
        if not args.confirm_authorized:
            print("Authorization confirmation is required.", file=sys.stderr)
            return 4
        key = bytearray()
        try:
            key = prompt_key(args.input_mode)
            result = create_verified_snapshot(
                database=Path(args.database),
                destination_parent=Path(args.snapshot_dir),
                key_material=key,
                profile=profile_for_layout(args.layout),
            )
            payload = {
                "status": "key_validated",
                "snapshot_directory": str(result.directory),
                "database_name": result.database.name,
                "copied_file_count": len(result.copied_files),
                "cipher_profile": result.profile,
                "key_persisted": False,
            }
            if args.as_json:
                print(json.dumps(payload, ensure_ascii=False, indent=2))
            else:
                print(f"Key validated; encrypted snapshot created at {result.directory}")
            return 0
        except (KeyInputError, SnapshotError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 3
        finally:
            wipe_key(key)
    if args.command == "prepare-auto-key":
        if not args.confirm_read_process_memory:
            print("Explicit read-only process-memory authorization is required.", file=sys.stderr)
            return 4
        if args.wait_for_manual_exit and not args.confirm_manual_close_flow:
            print("Explicit confirmation is required for the manual-close waiting flow.", file=sys.stderr)
            return 4
        key = bytearray()
        try:
            probe = probe_database_key(
                Path(args.database), authorized=True,
                time_budget_seconds=max(1.0, min(args.time_budget, 60.0)),
            )
            key = probe.key
            manual_wait_seconds = None
            if args.wait_for_manual_exit:
                print(
                    "KEY_VALIDATED: Please close Weixin manually, including its tray process. "
                    "The tool will only wait and will never terminate it.",
                    file=sys.stderr, flush=True,
                )
                manual_wait_seconds = wait_for_manual_weixin_exit(
                    max(5.0, min(args.manual_close_timeout, 600.0))
                )
            result = create_verified_snapshot(
                database=Path(args.database),
                destination_parent=Path(args.snapshot_dir),
                key_material=key,
                profile=profile_for_layout("weixin-4"),
                manual_process_exit_confirmed=bool(args.wait_for_manual_exit),
            )
            payload = {
                "status": "key_discovered_and_validated",
                "snapshot_directory": str(result.directory),
                "database_name": result.database.name,
                "copied_file_count": len(result.copied_files),
                "adapter": probe.adapter,
                "process_memory_access": "read_only",
                "key_persisted": False,
                "account_identifier_printed": False,
                "manual_process_exit_confirmed": bool(args.wait_for_manual_exit),
                "process_termination_attempted": False,
                "manual_wait_seconds": round(manual_wait_seconds, 3) if manual_wait_seconds is not None else None,
            }
            if args.as_json:
                print(json.dumps(payload, ensure_ascii=False, indent=2))
            else:
                print(f"Verified key discovered; encrypted snapshot created at {result.directory}")
            return 0
        except (ProbeError, SnapshotError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 3
        finally:
            wipe_key(key)
    if args.command == "inspect-known-key":
        if not args.confirm_authorized:
            print("Authorization confirmation is required.", file=sys.stderr)
            return 4
        if args.keep_decrypted and not args.confirm_retain_decrypted:
            print("Separate confirmation is required to retain a decrypted database.", file=sys.stderr)
            return 4
        key = bytearray()
        decrypted: Path | None = None
        try:
            key = prompt_key(args.input_mode)
            work_dir = Path(args.work_dir)
            work_dir.mkdir(parents=True, exist_ok=True)
            token = uuid.uuid4().hex[:10]
            decrypted = work_dir / f"decrypted-{token}.sqlite"
            decrypt_database(
                Path(args.snapshot_database), decrypted, key,
                profile_for_layout(args.layout),
            )
            payload = inspect_schema(decrypted)
            snapshot_path = Path(args.snapshot_database)
            sidecars = [
                item for suffix in ("-wal", "-shm", "-journal")
                if (item := Path(str(snapshot_path) + suffix)).is_file()
            ]
            nonempty_wal = any(
                item.name.endswith("-wal") and item.stat().st_size > 0 for item in sidecars
            )
            schema_status = payload["status"]
            payload.update({
                "database_name": snapshot_path.name,
                "encrypted_sidecar_count": len(sidecars),
                "nonempty_wal_present": nonempty_wal,
                "encrypted_wal_processed": nonempty_wal,
                "schema_status": schema_status,
                "safe_for_message_export": schema_status == "compatible",
                "decrypted_database_retained": bool(args.keep_decrypted),
                "decrypted_database": str(decrypted) if args.keep_decrypted else None,
                "key_persisted": False,
            })
            report_path = work_dir / f"compatibility-{token}.json"
            report_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            if not args.keep_decrypted:
                decrypted.unlink(missing_ok=True)
                decrypted = None
            result = {"status": payload["status"], "report": str(report_path), **payload}
            if args.as_json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(f"Compatibility report created at {report_path}")
            return 0 if payload["status"] == "compatible" else 5
        except (KeyInputError, DecryptionError, SchemaInspectionError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 3
        finally:
            if decrypted is not None and not args.keep_decrypted:
                decrypted.unlink(missing_ok=True)
            wipe_key(key)
    if args.command == "inspect-auto-key":
        if not args.confirm_read_process_memory or not args.confirm_schema_inspection:
            print(
                "Separate confirmations are required for read-only key discovery and schema inspection.",
                file=sys.stderr,
            )
            return 4
        key = bytearray()
        decrypted: Path | None = None
        try:
            probe = probe_database_key(
                Path(args.key_database), authorized=True,
                time_budget_seconds=max(1.0, min(args.time_budget, 60.0)),
            )
            key = probe.key
            work_dir = Path(args.work_dir)
            work_dir.mkdir(parents=True, exist_ok=True)
            token = uuid.uuid4().hex[:10]
            decrypted = work_dir / f"decrypted-{token}.sqlite"
            snapshot_path = Path(args.snapshot_database)
            decrypt_database(snapshot_path, decrypted, key, profile_for_layout("weixin-4"))
            payload = inspect_schema(decrypted)
            sidecars = [
                item for suffix in ("-wal", "-shm", "-journal")
                if (item := Path(str(snapshot_path) + suffix)).is_file()
            ]
            nonempty_wal = any(
                item.name.endswith("-wal") and item.stat().st_size > 0 for item in sidecars
            )
            payload.update({
                "database_name": snapshot_path.name,
                "encrypted_sidecar_count": len(sidecars),
                "nonempty_wal_present": nonempty_wal,
                "encrypted_wal_processed": nonempty_wal,
                "safe_for_message_export": payload["status"] == "compatible",
                "decrypted_database_retained": False,
                "decrypted_database": None,
                "adapter": probe.adapter,
                "process_memory_access": "read_only",
                "message_rows_read": 0,
                "key_persisted": False,
            })
            report_path = work_dir / f"compatibility-{token}.json"
            report_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            decrypted.unlink(missing_ok=True)
            decrypted = None
            result = {"report": str(report_path), **payload}
            if args.as_json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(f"Compatibility report created at {report_path}")
            return 0 if payload["status"] == "compatible" else 5
        except (ProbeError, KeyInputError, DecryptionError, SchemaInspectionError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 3
        finally:
            if decrypted is not None:
                decrypted.unlink(missing_ok=True)
            wipe_key(key)
    if args.command == "snapshot-inspect-auto-key":
        if not args.confirm_read_process_memory or not args.confirm_schema_inspection:
            print(
                "Separate confirmations are required for read-only key discovery and schema inspection.",
                file=sys.stderr,
            )
            return 4
        key = bytearray()
        decrypted: Path | None = None
        try:
            source_database = Path(args.database)
            probe = probe_database_key(
                source_database, authorized=True,
                time_budget_seconds=max(1.0, min(args.time_budget, 60.0)),
            )
            key = probe.key
            snapshot = create_verified_snapshot(
                database=source_database,
                destination_parent=Path(args.snapshot_dir),
                key_material=key,
                profile=profile_for_layout("weixin-4"),
            )
            work_dir = Path(args.work_dir)
            work_dir.mkdir(parents=True, exist_ok=True)
            token = uuid.uuid4().hex[:10]
            decrypted = work_dir / f"decrypted-{token}.sqlite"
            decrypt_database(
                snapshot.database, decrypted, key, profile_for_layout("weixin-4")
            )
            payload = inspect_schema(decrypted)
            nonempty_wal = any(
                item.name.endswith("-wal") and item.stat().st_size > 0
                for item in snapshot.copied_files
            )
            payload.update({
                "database_name": snapshot.database.name,
                "snapshot_directory": str(snapshot.directory),
                "encrypted_file_count": len(snapshot.copied_files),
                "nonempty_wal_present": nonempty_wal,
                "encrypted_wal_processed": nonempty_wal,
                "safe_for_message_export": payload["status"] == "compatible",
                "decrypted_database_retained": False,
                "decrypted_database": None,
                "adapter": probe.adapter,
                "process_memory_access": "read_only",
                "process_memory_scan_count": 1,
                "message_rows_read": 0,
                "key_persisted": False,
            })
            report_path = work_dir / f"compatibility-{token}.json"
            report_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            decrypted.unlink(missing_ok=True)
            decrypted = None
            result = {"report": str(report_path), **payload}
            if args.as_json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(f"Encrypted snapshot and compatibility report created at {snapshot.directory}")
            return 0 if payload["status"] == "compatible" else 5
        except (
            ProbeError, SnapshotError, KeyInputError, DecryptionError,
            SchemaInspectionError, OSError,
        ) as exc:
            print(str(exc), file=sys.stderr)
            return 3
        finally:
            if decrypted is not None:
                decrypted.unlink(missing_ok=True)
            wipe_key(key)
    if args.command == "catalog-preview-auto-key":
        if not (
            args.confirm_read_process_memory
            and args.confirm_private_metadata
            and args.confirm_count_query
        ):
            print(
                "Separate confirmations are required for process-memory access, private metadata, and count queries.",
                file=sys.stderr,
            )
            return 4
        work_dir = Path(args.work_dir)
        try:
            token = uuid.uuid4().hex[:10]
            sources = _auto_sources_from_args(args)
            with _auto_plaintext_bundle(
                sources, Path(args.snapshot_dir), work_dir, args.time_budget
            ) as (plaintext_paths, snapshots, _image_key, _image_xor_key):
                dataset = ChatDataset(
                    _message_plaintexts(plaintext_paths), "weixin-4",
                    session_database=plaintext_paths["session"],
                    contact_database=plaintext_paths["contact"],
                )
                conversations = dataset.conversations()
                limit = max(1, min(args.limit_conversations, 5000))
                included_kinds = frozenset({
                    MessageKind.TEXT, MessageKind.IMAGE, MessageKind.VIDEO,
                    MessageKind.AUDIO, MessageKind.FILE, MessageKind.LINK,
                })
                catalog = []
                for conversation in conversations[:limit]:
                    preview = dataset.preview(ExportScope(
                        conversation_id=conversation.id,
                        include=included_kinds,
                    ))
                    visible_counts = {
                        kind: count for kind, count in preview["counts_by_kind"].items()
                        if kind in {item.value for item in included_kinds}
                    }
                    catalog.append({
                        "id": conversation.id,
                        "display_name": conversation.display_name,
                        "type": conversation.conversation_type,
                        "last_timestamp": conversation.last_timestamp,
                        "counts_by_kind": visible_counts,
                        "selected_count": sum(visible_counts.values()),
                        "ambiguous_link_or_file_count": preview["ambiguous_link_or_file_count"],
                    })
                payload = {
                    "status": "catalog_preview_ready",
                    "conversation_count": len(conversations),
                    "returned_count": len(catalog),
                    "conversation_limit_reached": len(conversations) > limit,
                    "conversations": catalog,
                    "included_kinds": sorted(item.value for item in included_kinds),
                    "emoticons_excluded_by_default": True,
                    "internal_identifiers_included": False,
                    "source_paths_included": False,
                    "private_metadata_read": True,
                    "message_bodies_read": 0,
                    "summaries_or_drafts_read": 0,
                    "attachments_copied": 0,
                    "process_memory_access": "read_only",
                    "process_memory_scan_count": len(sources),
                    "keys_persisted": False,
                    "decrypted_databases_retained": False,
                    "encrypted_snapshots": {
                        role: str(snapshot.directory) for role, snapshot in snapshots.items()
                    },
                }
            report_path = work_dir / f"catalog-preview-{token}.json"
            report_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            result = {"report": str(report_path), **payload}
            if args.as_json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(f"Conversation preview created at {report_path}")
            return 0
        except (
            ProbeError, SnapshotError, KeyInputError, DecryptionError,
            ChatDataError, OSError, sqlite3.DatabaseError,
        ) as exc:
            print(str(exc), file=sys.stderr)
            return 3
    if args.command == "selection-preview-auto-key":
        if not (
            args.confirm_read_process_memory
            and args.confirm_private_metadata
            and args.confirm_count_query
        ):
            print(
                "Separate confirmations are required for process-memory access, private metadata, and count queries.",
                file=sys.stderr,
            )
            return 4
        try:
            scope = ExportScope(
                conversation_id=args.conversation_id,
                start_timestamp=parse_time_bound(args.start),
                end_timestamp=parse_time_bound(args.end),
                include=_included_kinds(args.include),
            )
            if (
                scope.start_timestamp is not None and scope.end_timestamp is not None
                and scope.start_timestamp > scope.end_timestamp
            ):
                raise ChatDataError("The start time must not be later than the end time.")
            sources = _auto_sources_from_args(args)
            report_path = None
            with _auto_plaintext_bundle(
                sources, Path(args.snapshot_dir), Path(args.work_dir), args.time_budget
            ) as (plaintext, snapshots, _image_key, _image_xor_key):
                dataset = ChatDataset(
                    _message_plaintexts(plaintext), "weixin-4",
                    session_database=plaintext["session"],
                    contact_database=plaintext["contact"],
                )
                payload = {
                    "status": "selection_preview_ready",
                    **dataset.preview(scope),
                    "private_metadata_read": True,
                    "summaries_or_drafts_read": 0,
                    "attachments_copied": 0,
                    "process_memory_access": "read_only",
                    "process_memory_scan_count": len(sources),
                    "keys_persisted": False,
                    "decrypted_databases_retained": False,
                    "encrypted_snapshots": {
                        role: str(snapshot.directory) for role, snapshot in snapshots.items()
                    },
                }
                report_root = Path(args.work_dir)
                report_root.mkdir(parents=True, exist_ok=True)
                report_path = report_root / f"selection-preview-{uuid.uuid4().hex[:10]}.json"
                report_path.write_text(
                    json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
                )
            result = {"report": str(report_path), **payload}
            if args.as_json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(f"Selection preview created at {report_path}")
            return 0
        except (
            ProbeError, SnapshotError, KeyInputError, DecryptionError,
            ChatDataError, OSError, sqlite3.DatabaseError,
        ) as exc:
            print(str(exc), file=sys.stderr)
            return 3
    if args.command == "export-auto-key":
        if not (
            args.confirm_read_process_memory
            and args.confirm_private_metadata
            and args.confirm_selection
            and args.confirm_read_message_bodies
        ):
            print(
                "Separate confirmations are required for process-memory access, private metadata, the exact selection, and reading selected message bodies.",
                file=sys.stderr,
            )
            return 4
        if args.include_assets and not args.confirm_copy_attachments:
            print("Separate confirmation is required to copy selected attachments.", file=sys.stderr)
            return 4
        if args.allow_remote_media_download and not args.confirm_remote_media_download:
            print("Separate confirmation is required for selected-media network downloads.", file=sys.stderr)
            return 4
        if args.include_assets and not (args.account_root or args.voice_media_database):
            print("An account root or exact voice media database is required for attachments.", file=sys.stderr)
            return 3
        if args.voice_media_database and not (
            args.include_assets and args.confirm_voice_media_database
        ):
            print(
                "The exact voice media database requires attachment mode and separate confirmation.",
                file=sys.stderr,
            )
            return 4
        try:
            scope = ExportScope(
                conversation_id=args.conversation_id,
                start_timestamp=parse_time_bound(args.start),
                end_timestamp=parse_time_bound(args.end),
                include=_included_kinds(args.include),
            )
            if (
                scope.start_timestamp is not None and scope.end_timestamp is not None
                and scope.start_timestamp > scope.end_timestamp
            ):
                raise ChatDataError("The start time must not be later than the end time.")
            sources = _auto_sources_from_args(args, include_media=True)
            snapshots_payload: dict[str, str] = {}
            with _auto_plaintext_bundle(
                sources, Path(args.snapshot_dir), Path(args.work_dir), args.time_budget,
                derive_image_key=bool(
                    args.include_assets and args.confirm_image_key_discovery
                ),
            ) as (plaintext, snapshots, image_key, image_xor_key):
                dataset = ChatDataset(
                    _message_plaintexts(plaintext), "weixin-4",
                    session_database=plaintext["session"],
                    contact_database=plaintext["contact"],
                )
                media_resolver = None
                if args.include_assets:
                    media_resolver = MediaResolver(
                        Path(args.account_root) if args.account_root else None,
                        [plaintext["media"]] if "media" in plaintext else [],
                        max_asset_bytes=max(1, args.max_asset_bytes),
                        image_aes_key=image_key or None,
                        image_xor_key=image_xor_key,
                        include_emoticons=MessageKind.EMOTICON in scope.include,
                        allow_remote_media_download=args.allow_remote_media_download,
                        video_asset=args.video_asset,
                    )
                export_result = export_chat(
                    dataset, scope, Path(args.output_dir),
                    limit=max(1, min(args.limit, 1_000_000)),
                    media_resolver=media_resolver,
                    split_asset_bundles=args.split_asset_bundles,
                )
                snapshots_payload = {
                    role: str(snapshot.directory) for role, snapshot in snapshots.items()
                }
            payload = {
                "status": "export_ready",
                "archive": str(export_result.archive),
                "message_count": export_result.message_count,
                "counts_by_kind": export_result.counts_by_kind,
                "sha256": export_result.sha256,
                "asset_archives": {
                    category: {
                        "path": str(path),
                        "sha256": export_result.asset_archive_sha256[category],
                    }
                    for category, path in export_result.asset_archives.items()
                },
                "encrypted_snapshots": snapshots_payload,
                "process_memory_access": "read_only",
                "process_memory_scan_count": len(sources),
                "keys_persisted": False,
                "decrypted_databases_retained": False,
                "message_content_printed": False,
                "attachments_requested": bool(args.include_assets),
                "image_key_discovery_used": bool(
                    args.include_assets and args.confirm_image_key_discovery
                ),
                "video_asset": args.video_asset,
            }
            if args.as_json:
                print(json.dumps(payload, ensure_ascii=False, indent=2))
            else:
                print(f"Exported {export_result.message_count} messages to {export_result.archive}")
            return 0
        except (
            ProbeError, SnapshotError, KeyInputError, DecryptionError,
            ChatDataError, ExportError, OSError, sqlite3.DatabaseError,
        ) as exc:
            print(str(exc), file=sys.stderr)
            return 3
    if args.command in {"list-sessions", "preview-selection"}:
        if not args.confirm_authorized:
            print("Authorization confirmation is required.", file=sys.stderr)
            return 4
        try:
            dataset = _dataset_from_args(args)
            if args.command == "list-sessions":
                conversations = dataset.conversations()
                payload = {
                    "status": "sessions_ready",
                    "count": len(conversations),
                    "conversations": [
                        {
                            "id": item.id,
                            "display_name": item.display_name,
                            "type": item.conversation_type,
                            "last_timestamp": item.last_timestamp,
                            "layout": item.layout,
                        }
                        for item in conversations
                    ],
                    "internal_identifiers_included": False,
                    "message_bodies_read": 0,
                }
            else:
                scope = ExportScope(
                    conversation_id=args.conversation_id,
                    start_timestamp=parse_time_bound(args.start),
                    end_timestamp=parse_time_bound(args.end),
                    include=_included_kinds(args.include),
                )
                if (
                    scope.start_timestamp is not None and scope.end_timestamp is not None
                    and scope.start_timestamp > scope.end_timestamp
                ):
                    raise ChatDataError("The start time must not be later than the end time.")
                payload = {"status": "preview_ready", **dataset.preview(scope)}
            if args.as_json:
                print(json.dumps(payload, ensure_ascii=False, indent=2))
            else:
                print(f"{payload['status']}: {payload.get('count', payload.get('selected_count', 0))}")
            return 0
        except (ChatDataError, OSError, sqlite3.DatabaseError) as exc:
            print(str(exc), file=sys.stderr)
            return 3
    if args.command == "export-plaintext":
        if not args.confirm_authorized or not args.confirm_selection:
            print("Authorization and selection confirmations are required.", file=sys.stderr)
            return 4
        if args.include_assets and not args.confirm_copy_attachments:
            print("Separate confirmation is required to copy attachments.", file=sys.stderr)
            return 4
        if args.allow_remote_media_download and not args.confirm_remote_media_download:
            print("Separate confirmation is required for selected-media network downloads.", file=sys.stderr)
            return 4
        if args.include_assets and not (args.account_root or args.media_database):
            print("An account root or plaintext media database is required for attachments.", file=sys.stderr)
            return 3
        if args.image_key_input and not args.confirm_image_key_use:
            print("Separate confirmation is required to use a V2 image key.", file=sys.stderr)
            return 4
        if args.image_key_input and args.auto_image_key_database:
            print("Choose either hidden image-key input or automatic image-key discovery, not both.", file=sys.stderr)
            return 3
        if args.auto_image_key_database and not args.confirm_read_process_memory_for_image_key:
            print("Separate read-only process-memory authorization is required for image-key discovery.", file=sys.stderr)
            return 4
        image_key = bytearray()
        try:
            scope = ExportScope(
                conversation_id=args.conversation_id,
                start_timestamp=parse_time_bound(args.start),
                end_timestamp=parse_time_bound(args.end),
                include=_included_kinds(args.include),
            )
            if (
                scope.start_timestamp is not None and scope.end_timestamp is not None
                and scope.start_timestamp > scope.end_timestamp
            ):
                raise ChatDataError("The start time must not be later than the end time.")
            media_resolver = None
            if args.include_assets:
                if args.image_key_input:
                    image_key = prompt_image_key(args.image_key_input)
                image_xor_key = args.image_xor_key
                if args.auto_image_key_database:
                    image_probe = probe_database_key(
                        Path(args.auto_image_key_database), authorized=True,
                        time_budget_seconds=max(1.0, min(args.image_key_time_budget, 60.0)),
                        derive_media_key=True,
                    )
                    try:
                        if image_probe.image_key is None or image_probe.image_xor_key is None:
                            raise ProbeError("The verified adapter did not produce a media key.")
                        image_key = image_probe.image_key
                        image_xor_key = image_probe.image_xor_key
                    finally:
                        wipe_key(image_probe.key)
                media_resolver = MediaResolver(
                    Path(args.account_root) if args.account_root else None,
                    [Path(item) for item in args.media_database],
                    max_asset_bytes=max(1, args.max_asset_bytes),
                    image_aes_key=image_key or None,
                    image_xor_key=image_xor_key,
                    include_emoticons=MessageKind.EMOTICON in scope.include,
                    allow_remote_media_download=args.allow_remote_media_download,
                    video_asset=args.video_asset,
                )
            result = export_chat(
                _dataset_from_args(args), scope, Path(args.output_dir),
                limit=max(1, min(args.limit, 1_000_000)),
                media_resolver=media_resolver,
                split_asset_bundles=args.split_asset_bundles,
            )
            payload = {
                "status": "export_ready",
                "archive": str(result.archive),
                "message_count": result.message_count,
                "counts_by_kind": result.counts_by_kind,
                "sha256": result.sha256,
                "asset_archives": {
                    category: {
                        "path": str(path),
                        "sha256": result.asset_archive_sha256[category],
                    }
                    for category, path in result.asset_archives.items()
                },
                "message_content_printed": False,
                "video_asset": args.video_asset,
            }
            if args.as_json:
                print(json.dumps(payload, ensure_ascii=False, indent=2))
            else:
                print(f"Exported {result.message_count} messages to {result.archive}")
            return 0
        except (ChatDataError, ExportError, KeyInputError, ProbeError, OSError, sqlite3.DatabaseError) as exc:
            print(str(exc), file=sys.stderr)
            return 3
        finally:
            wipe_key(image_key)
    return 2


if __name__ == "__main__":
    sys.exit(main())
