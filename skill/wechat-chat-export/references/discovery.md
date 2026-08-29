# Discovery behavior

Discovery reads filesystem and process metadata only. It does not open message bodies, databases, media, or process memory.

For first use, prefer `onboard --json`. It combines the runtime check and ordinary
discovery, returns one plain next action, and reads no process memory or message
bodies. If it reports `needs_fixed_drive_scan`, obtain one explicit confirmation
and rerun with `--scan-fixed-drives`. After the user confirms local path disclosure,
`--show-paths` returns an exact `database_plan` grouped into message, session,
contact, voice-media, and other databases. Pass every listed message database to
the automatic catalog, preview, and export commands.

- Start with registered applications, running WeChat/Weixin executables, and standard Windows data locations.
- Use the bounded fixed-drive scan only when custom locations may exist. It stops at its depth, directory, or time limit and does not follow directory links.
- Treat `xwechat_files` with `db_storage` as a Weixin 4.x layout and `WeChat Files` with `Msg`/`FileStorage` as a WeChat 3.x layout.
- Rank accounts by the newest database timestamp. `active`, `recent`, and `stale` are activity hints, not proof that an account is signed in.
- Default reports hide absolute paths and never expose the account directory name. Use the opaque account ID for later selection.
- A zero-result or timed-out scan is a compatibility result, not permission to search unrelated user folders without bounds.
