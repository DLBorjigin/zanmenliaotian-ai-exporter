# Key discovery

Database keys and image keys are separate secrets. Authorization for one target
database does not authorize scanning for other databases, media keys, accounts,
or processes.

## Supplied key

Use `prepare-known-key` when the user already has the 64-hex-character key for
the exact database. Enter it only through the hidden local console or dialog.
Never put it in chat, an argument, a shell history, a log, JSON, or an export.

## Read-only automatic discovery

For Weixin 4.x, `prepare-auto-key` performs a bounded, read-only inspection of
running `Weixin.exe` memory. Before running it, obtain explicit confirmation for:

- the exact local encrypted database path;
- read-only inspection of the user's running Weixin process;
- a bounded time budget.

The adapter finds a version signature, reads the account configuration, derives
a candidate key from the target database salt, and accepts it only if that key
passes the target database's SQLCipher page-HMAC check. It never writes to the
Weixin process, injects a library, saves a memory dump, caches the key, or prints
the account identifier.

Weixin 4.1.13.12 stores independent serialized key-and-salt values for individual
WCDB databases. Its exact-version adapter locates the registered
`com.Tencent.WCDB.Config.Cipher` configuration node, decodes only its bounded
value, matches the selected database salt, and still requires the exact target
page-HMAC check. Do not replace this structured path with an unrestricted search
for key-like byte sequences. Unknown versions remain unsupported until separately
researched and validated.

After the exact 4.1.13.12 database key has passed HMAC validation, a separately
authorized V2 image-key request may read the existing bounded `global_config`
account fields through the known adapter offsets. The matching WCDB configuration
and `global_config` may live in different child processes of the same running
Weixin instance, so inspect the bounded known structure in each running Weixin
PID after the exact database key is verified. Keep database-key acceptance
independent from media-key derivation; the derived media key is accepted for an
asset only when V2 padding and the decrypted image signature both validate.

Example after explicit confirmation:

```text
scripts/wechat_export.py prepare-auto-key --database <exact-db> --snapshot-dir <work> --time-budget 20 --confirm-read-process-memory --json
```

For schema-only inspection of a small live auxiliary database, prefer
`snapshot-inspect-auto-key`. It probes the exact database only once, creates a
content-stable encrypted snapshot including sidecars, processes its committed
WAL, reads schema metadata without selecting rows, deletes the temporary
plaintext, and wipes the key buffer. It requires separate confirmations for the
read-only process scan and schema inspection.

For a separately authorized conversation catalog preview, use
`catalog-preview-auto-key`; it performs one bounded probe for each exact message,
session, and contact database. It must not reuse that authorization for media or
other databases.

If an account has multiple message databases, authorization and validation apply
to each exact file. Pass all of them as repeated `--message-database` arguments;
the tool wipes each derived database key immediately after its own snapshot is
decrypted.

## Stable snapshot after manual exit

When a running database has a non-empty WAL, use `--wait-for-manual-exit` only
after the user explicitly agrees to close Weixin themselves. The tool validates
the key first, keeps it only in its mutable in-process buffer, prints a manual
close prompt, and waits. It must never call a process-termination API. Use
`--confirm-manual-close-flow` and a bounded `--manual-close-timeout`.

After every `Weixin.exe` process exits naturally, copy the encrypted main
database and every present `-wal`, `-shm`, or `-journal` sidecar as one snapshot.
Publish it only when the source file set and the SHA-256 content fingerprints are
unchanged before and after copying and every copied fingerprint matches its
source. Weixin 4 may retain a non-empty preallocated WAL after a clean exit; keep
that WAL and record `wal_state: captured_stable` in the manifest. Never treat the
base database alone as complete when that state is present. A timeout or changing
source set is a safe failure: publish no snapshot and wipe the key buffer.

## Failure handling

`No supported adapter` means compatibility is unproven, not that the account has
no key. Stop and report the WeChat version and the redacted diagnostic result.
Do not try arbitrary offsets, broad memory dumps, unverified keys, or a native
hook. A native hook changes the Weixin process, is not bundled, and would require
a separate, plainly worded authorization and compatibility review.

Image V2 encryption uses a separate account media key. A database-key scan does
not authorize or silently enable image-key acquisition. When the user separately
approves read-only image-key discovery, `export-plaintext` can use
`--auto-image-key-database <exact encrypted DB>` together with
`--confirm-read-process-memory-for-image-key`; the derived image key remains in
memory only and is wiped after export. Otherwise export the `.dat` status as
`image_v2_key_required`. A known image key must use `--image-key-input dialog` or
`console`, never a command-line value.
