# Security modes

| Mode | Reads process memory | Changes Weixin | Reads bodies | Copies attachments | Confirmation |
|---|---:|---:|---:|---:|---:|
| Metadata discovery | No | No | No | No | Not normally |
| Supplied key | No | No | No | No | Required |
| Read-only probe | Yes, bounded | No | No | No | Required for exact DB |
| Native hook | Yes | Yes | No | No | Separate confirmation; not bundled |
| Selection preview | No | No | Counts only | No | Required |
| Export | No | No | Selected scope | Optional | Scope confirmation; separate attachment confirmation |

Never treat a general request to continue development as authorization to scan
the live process, read chat bodies, retain plaintext databases, or copy media.
Keep database and image keys out of chat, command-line arguments, logs, reports,
manifests, and archives. Use hidden local entry and wipe mutable buffers on a
best-effort basis after each operation.

For `supplied_key`, invoke `prepare-known-key` only after the user confirms the
selected local account and database. Prefer the local dialog for nontechnical
users and the hidden console prompt when a GUI is unavailable. The command
accepts exactly 32 key bytes represented as 64 hexadecimal characters, validates
an encrypted snapshot, and removes failed staging copies. Python cannot guarantee
removal of every transient immutable copy, so describe wiping as best effort.
