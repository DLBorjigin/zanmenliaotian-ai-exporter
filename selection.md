# Conversation and message selection

List conversations before reading message bodies. The runtime maps WeChat 3.x `MSG.StrTalker` and Weixin 4.x `SessionTable.username` plus `Msg_<md5>` shards into opaque conversation IDs.

- Show display names using `remark`, then nickname, then alias, then the internal username. Do not include the internal username in the normal report.
- If multiple conversations have the same display name, present their opaque IDs and type (`direct`, `group`, or `official`) and ask the user to choose.
- Parse absolute time bounds locally. Naive date/time values use the computer's
  local timezone. Reject an end before a start. If a user gives an end time only
  to the minute (for example `23:07`), treat it as including that whole minute
  (`23:07:59`) unless they explicitly request an exact instant or half-open range.
- Normalize seconds, milliseconds, and microseconds to Unix seconds. Preserve chronological ordering using the native sequence field as a tie-breaker.
- Preview counts by normalized type before selecting message bodies. Type 49 is only a coarse `link` count during preview because distinguishing a file requires inspecting XML content; report it as ambiguous.
- Weixin 4.1.13.12 may pack an application-message subtype into the high 32 bits
  of `local_type`, leaving base type 49 in the low 32 bits. Split that value
  before classification; packed subtype 6 is a file even when message XML is
  absent. Preserve the original packed type and expose the decoded subtype.
- Exclude emoticons by default unless the user asks for them. Apply the approved kind filter again after normalization.
- Interpret media words as exact selectors. `图片` selects normalized kind
  `image`, `表情` selects `emoticon`, and either video request selects `video`.
  For `视频`, set video asset mode to `original`; for `视频封面`, set it to
  `thumbnail`. `both` is allowed only when the user explicitly asks for both.
  A request for one selector must not silently include any of the others.

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
The same `Msg_<md5>` table may exist in several message databases. Preserve every
location for that conversation instead of allowing the last database to overwrite
earlier ones; merge the iterators and deduplicate overlapping rows by stable
message ID before applying the global export limit.

Treat sender identity and message direction as separate facts. For Weixin 4.x,
map `real_sender_id` through `Name2Id` and the contact database even when the
status/direction value is empty or unfamiliar. A present real sender identifies
an incoming group sender and may safely recover `is_self=false`; record that the
direction came from `real_sender_id`. For legacy group messages, accept a
conservative `wxid_*:\n` sender prefix and remove it from the displayed body.
Never replace a resolved contact name with the group name merely because
`is_self` is unknown. If neither a sender identifier nor a safe direction exists,
label the sender unknown instead of inventing an attribution.

Use `selection-preview-auto-key` after the user chooses an opaque conversation
ID and optional time/type bounds. It repeats the three exact bounded probes,
queries grouped type counts only, writes a private preview report, and removes
all temporary plaintext. Reject reversed time bounds and an unknown or ambiguous
conversation ID.
