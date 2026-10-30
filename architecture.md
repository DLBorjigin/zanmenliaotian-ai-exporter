# Architecture contract

The product has two separately releasable layers:

1. `wechat-chat-export` is the Codex Skill. It gathers scope, explains permissions, invokes the local runtime, and packages results.
2. `wechat-ai-exporter` is the local runtime. It discovers local installations, validates keys, opens read-only database snapshots, normalizes messages, resolves selected media, and writes exports.

The runtime separates version-sensitive behavior behind adapters:

- installation and data-root discovery;
- encrypted database profiles;
- supplied-key validation;
- read-only process probes;
- native hooks, disabled unless explicitly authorized;
- message schemas and media codecs.

The Weixin 4.1.13.12 adapter is gated to that exact module version and a static
WCDB configuration marker. It searches only for the exact in-memory registration
pair for that marker, follows the verified configuration-node layout, decodes a
bounded configuration value, and accepts only the key whose serialized salt
matches the selected database. The key must then pass the selected database's
first-page HMAC. It does not use arbitrary offsets, hooks, injection, or a saved
memory dump. Message, session, and contact databases are validated independently.

Unknown versions return a compatibility report and stop before content access. Original WeChat files are never modified. Secrets never cross the local process boundary or appear in CLI arguments, stdout, logs, manifests, or crash reports.

Discovery is tiered. The fast tier checks running processes, registry entries, and standard locations. The optional bounded tier scans fixed drives for exact WeChat directory and executable names with depth, directory-count, time, and link-following limits. Reports use opaque IDs and path hints by default; account directory names and process IDs are withheld.

Known-key preparation receives a 32-byte key through a hidden local prompt, copies the encrypted database and present SQLite sidecars into a uniquely named staging directory, confirms that the source metadata remained stable during copying, and validates the snapshot's first-page HMAC. Only a validated snapshot is atomically published. Failed staging directories are removed and the mutable key buffer is overwritten on a best-effort basis.

Database decryption verifies every page HMAC before AES-CBC decryption and publishes output atomically. Schema inspection opens plaintext SQLite with `mode=ro`, `immutable=1`, and `query_only`, reads no table rows, hashes table identifiers, and produces a compatibility fingerprint. Plaintext inspection files are ephemeral unless the user separately confirms retention.
