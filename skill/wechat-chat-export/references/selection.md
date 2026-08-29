# Conversation and message selection

List conversations before reading message bodies. The runtime maps WeChat 3.x `MSG.StrTalker` and Weixin 4.x `SessionTable.username` plus `Msg_<md5>` shards into opaque conversation IDs.

- Show display names using `remark`, then nickname, then alias, then the internal username. Do not include the internal username in the normal report.
- If multiple conversations have the same display name, present their opaque IDs and type (`direct`, `group`, or `official`) and ask the user to choose.
- Parse absolute time bounds locally. Naive date/time values use the computer's local timezone. Reject an end before a start.
- Normalize seconds, milliseconds, and microseconds to Unix seconds. Preserve chronological ordering using the native sequence field as a tie-breaker.
- Preview counts by normalized type before selecting message bodies. Type 49 is only a coarse `link` count during preview because distinguishing a file requires inspecting XML content; report it as ambiguous.
- Exclude emoticons by default unless the user asks for them. Apply the approved kind filter again after normalization.

For users without supplied keys, `catalog-preview-auto-key` is the transient
three-database path. Require exact message, session, and contact database paths
and separate confirmations for the three bounded read-only key probes, private
contact/session metadata, and aggregate count queries. It may read only display
fields, session identifiers/timestamps, and grouped message type counts. It must
not select message content, session summaries, drafts, or attachment data. Wipe
each key immediately after its snapshot is decrypted, delete all temporary
plaintext databases after the catalog report is written, and omit internal
identifiers and source paths from the report.

When onboarding reports multiple `message_N.db` files for one account, repeat
`--message-database` for every file in the plan. The transient catalog, selection
preview, and export flows validate and decrypt each exact snapshot independently,
then merge normalized messages chronologically. Do not silently choose only
`message_0.db`, because older ranges may live in another file.

Use `selection-preview-auto-key` after the user chooses an opaque conversation
ID and optional time/type bounds. It repeats the three exact bounded probes,
queries grouped type counts only, writes a private preview report, and removes
all temporary plaintext. Reject reversed time bounds and an unknown or ambiguous
conversation ID.
