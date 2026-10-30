# Database compatibility

`inspect-known-key` decrypts a verified encrypted snapshot, checks every database page before writing it, and opens the result with SQLite in read-only immutable mode. It reads schema metadata and column definitions only; it does not select message rows.

- A WeChat 3.x message database contains a compatible `MSG` table signature.
- A Weixin 4.x message database contains one or more compatible `Msg_<hash>` table signatures and may contain `Name2Id`.
- Contact and session databases are classified as auxiliary databases rather than rejected.
- Table names are represented by hashes in the report because sharded names can identify conversations.
- `unsupported_schema` means the current adapter cannot safely interpret the structure. Stop before querying rows.
- A stable snapshot may legitimately contain a nonempty encrypted WAL after Weixin exits. The decryptor accepts only current-salt pages that pass the database-key HMAC, applies frames only through the last commit marker, ignores an uncommitted tail, and materializes the committed database size before schema inspection. Any integrity or layout mismatch fails closed and removes the temporary plaintext database.
- `inspect-auto-key` is the no-retention path for users who do not know their key. It requires separate confirmations for the exact live key database and schema-only inspection, reports `message_rows_read: 0`, and wipes the key buffer and temporary plaintext database after writing the compatibility report.
- `snapshot-inspect-auto-key` combines key discovery, a fingerprint-stable encrypted snapshot, and schema inspection so an exact live auxiliary database is scanned only once. The encrypted snapshot may remain; the key and temporary plaintext must not.

Plaintext databases are deleted immediately after inspection by default. Retaining one requires both `--keep-decrypted` and `--confirm-retain-decrypted`; retained files contain private chat data and must never be included in a Skill bundle or diagnostic archive.
