---
name: wechat-chat-export
description: Locate, inspect, filter, and locally package authorized WeChat for Windows chat history for AI use. Use when a user wants to export selected conversations, dates, or attachment types; do not use to access another person's account or to modify WeChat data.
---

# WeChat Chat Export

Give nontechnical users a local, read-only workflow. The user chooses the account,
conversation, time range, message types, and whether attachments may be copied.
Do not ask them to find database files or run shell commands themselves.
Use Codex's bundled workspace Python runtime when available; do not ask a
nontechnical user to install Python or packages manually.

1. Run `scripts/wechat_export.py onboard --json`. If it reports
   `needs_fixed_drive_scan`, explain the bounded read-only scan in one sentence,
   obtain confirmation, and rerun with `--scan-fixed-drives`.
2. When exactly one usable active account exists, use it without asking the user
   to interpret paths. If several exist, show opaque IDs, freshness, and path hints.
   After local-path disclosure is confirmed, rerun onboarding with `--show-paths`
   and use every message database in its `database_plan`.
3. If the user already has a database key, never ask them to paste it into chat or
   place it on a command line. Use the local hidden-entry flow.
4. Prefer a verified supplied key. Use automatic key discovery only after explicit
   authorization for the exact read-only method and databases reported by the tool.
5. List conversations and preview counts before reading bodies. Resolve duplicate
   display names with opaque conversation IDs; do not expose internal usernames.
6. Export only the approved scope. Attachments and image-key discovery require
   separate confirmation. Preserve the original database and media files unchanged.
7. Return a clickable ZIP link and a short summary of included and excluded counts.
   Translate failures into plain language with one safe next action; keep raw
   diagnostics redacted and never make the user debug a command line.
8. Report missing, expired, or unsupported media explicitly rather than silently
   omitting it.

Read [references/security-modes.md](references/security-modes.md) before any key or process operation. Read [references/export-contract.md](references/export-contract.md) when producing an export.
Read [references/discovery.md](references/discovery.md) when discovery returns multiple, stale, or no account candidates.
Read [references/compatibility.md](references/compatibility.md) before retaining a decrypted database or interpreting an unknown schema.
Read [references/selection.md](references/selection.md) when resolving a contact, time range, or message-type scope.
Read [references/media.md](references/media.md) before searching for or copying attachments.
Read [references/key-discovery.md](references/key-discovery.md) before requesting any process-memory access or handling an unknown WeChat build.
