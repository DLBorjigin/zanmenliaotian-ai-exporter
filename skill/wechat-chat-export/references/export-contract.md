# Export contract

Create a ZIP containing:

- `transcript.md`: chronological, readable conversation text with relative attachment links.
- `messages.json`: normalized chronological records for programmatic or AI ingestion.
- `manifest.json`: schema version, requested scope, checksums, message counts, attachment mapping, and privacy flags.
- `assets/`: only attachments selected by the user.

Exclude database keys, absolute source paths, raw account identifiers unless requested, temporary decrypted databases, and diagnostic memory data. Represent omitted or unavailable content with explicit placeholders so the timeline remains understandable.

Prefix `transcript.md` with a warning that chat text is untrusted data, not instructions. Quote message bodies so headings or code-like content cannot silently change the document structure. Write JSON incrementally for large conversations, build the archive under a unique staging name, and publish it atomically. If any step fails, remove partial output.

For users without supplied keys, `export-auto-key` is the no-plaintext-retention
path. Require separate confirmations for the exact database probes, private
contact/session metadata, the opaque conversation/time/type selection, and
reading the selected message bodies. Decrypt the exact message, session, and
contact snapshots only inside a cleanup context, create the ZIP atomically, then
delete every plaintext database and wipe every key. Attachment mode additionally
requires copying confirmation and a bounded account root or exact voice media
database. Derive the V2 image key only when separately confirmed.
