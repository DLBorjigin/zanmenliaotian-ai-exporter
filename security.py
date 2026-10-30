from __future__ import annotations

from dataclasses import dataclass

from .models import AccessMode


@dataclass(frozen=True)
class AuthorizationRequirement:
    mode: AccessMode
    mutates_wechat_process: bool
    reads_message_bodies: bool
    copies_attachments: bool
    requires_explicit_confirmation: bool


AUTHORIZATION_MATRIX = {
    AccessMode.METADATA_ONLY: AuthorizationRequirement(
        mode=AccessMode.METADATA_ONLY,
        mutates_wechat_process=False,
        reads_message_bodies=False,
        copies_attachments=False,
        requires_explicit_confirmation=False,
    ),
    AccessMode.SUPPLIED_KEY: AuthorizationRequirement(
        mode=AccessMode.SUPPLIED_KEY,
        mutates_wechat_process=False,
        reads_message_bodies=False,
        copies_attachments=False,
        requires_explicit_confirmation=True,
    ),
    AccessMode.READ_ONLY_PROBE: AuthorizationRequirement(
        mode=AccessMode.READ_ONLY_PROBE,
        mutates_wechat_process=False,
        reads_message_bodies=False,
        copies_attachments=False,
        requires_explicit_confirmation=True,
    ),
    AccessMode.NATIVE_HOOK: AuthorizationRequirement(
        mode=AccessMode.NATIVE_HOOK,
        mutates_wechat_process=True,
        reads_message_bodies=False,
        copies_attachments=False,
        requires_explicit_confirmation=True,
    ),
}

