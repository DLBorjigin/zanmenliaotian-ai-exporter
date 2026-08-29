from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class AccessMode(StrEnum):
    METADATA_ONLY = "metadata_only"
    SUPPLIED_KEY = "supplied_key"
    READ_ONLY_PROBE = "read_only_probe"
    NATIVE_HOOK = "native_hook"


class MessageKind(StrEnum):
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    FILE = "file"
    EMOTICON = "emoticon"
    LINK = "link"
    SYSTEM = "system"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class InstallationCandidate:
    executable: Path
    version: str
    architecture: str
    running_process_ids: tuple[int, ...] = ()
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class AccountCandidate:
    data_root: Path
    account_dir: Path
    last_modified_ns: int
    database_paths: tuple[Path, ...] = ()
    layout: str = "unknown"
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExportScope:
    conversation_id: str
    start_timestamp: int | None = None
    end_timestamp: int | None = None
    include: frozenset[MessageKind] = field(
        default_factory=lambda: frozenset({MessageKind.TEXT, MessageKind.IMAGE, MessageKind.VIDEO, MessageKind.FILE})
    )


@dataclass(frozen=True)
class Conversation:
    id: str
    display_name: str
    conversation_type: str
    last_timestamp: int | None
    layout: str
    database: Path = field(repr=False)
    table: str = field(repr=False)
    selector: str = field(repr=False)


@dataclass(frozen=True)
class NormalizedMessage:
    id: str
    conversation_id: str
    timestamp: int
    sender_name: str
    is_self: bool | None
    kind: MessageKind
    type_code: int
    subtype_code: int | None
    content: str
    sequence: int
    metadata: dict[str, object] = field(default_factory=dict)
