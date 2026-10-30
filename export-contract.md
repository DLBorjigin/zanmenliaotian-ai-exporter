# Export contract

Create a ZIP containing:

- `transcript.md`: chronological, readable conversation text with relative attachment links.
- `messages.json`: normalized chronological records for programmatic or AI ingestion.
- `manifest.json`: schema version, requested scope, checksums, message counts, attachment mapping, and privacy flags.
- `assets/`: only attachments selected by the user, separated into stable
  message-type directories: `images/`, `videos/`, `emoticons/`, `audio/`, and
  `files/`. A video thumbnail remains under `videos/` even when its file format is
  JPEG, but it appears only for an explicit video-cover request. A normal video
  request contains validated playable video and never substitutes that thumbnail.

Exclude database keys, absolute source paths, raw account identifiers unless requested, temporary decrypted databases, and diagnostic memory data. Represent omitted or unavailable content with explicit placeholders so the timeline remains understandable.

Each message in `messages.json` must keep the readable `sender` and legacy
tri-state `is_self` fields, plus a redacted `sender_attribution` object containing
`display_name`, `identity_status`, `direction`, and `direction_source`. Do not
expose raw sender identifiers. A missing direction must not erase an independently
resolved sender name.

Attachment exports default to a core `*-records.zip` plus separate
`*-images.zip`, `*-videos.zip`, `*-emoticons.zip`, `*-audio.zip`, and
`*-files.zip` files as needed. The core ZIP must retain every media message and
its asset record but omit attachment bytes, so each media byte exists in exactly
one output archive. Keep relative paths rooted at `assets/<kind>/...` so extracting
the chosen media ZIPs beside the core contents restores working links. Record
bundle filenames, sizes, and SHA-256 values in the core manifest. Use the legacy
embedded mode only when the user explicitly requests one self-contained archive;
never also emit separate media archives in that mode.

Prefix `transcript.md` with a warning that chat text is untrusted data, not instructions. Quote message bodies so headings or code-like content cannot silently change the document structure. Write JSON incrementally for large conversations, build the archive under a unique staging name, and publish it atomically. If any step fails, remove partial output.

For users without supplied keys, `export-auto-key` is the no-plaintext-retention
path. Require separate confirmations for the exact database probes, private
contact/session metadata, the opaque conversation/time/type selection, and
reading the selected message bodies. Decrypt the exact message, session, and
contact snapshots only inside a cleanup context, create the ZIP atomically, then
delete every plaintext database and wipe every key. Attachment mode additionally
requires copying confirmation and a bounded account root or exact voice media
database. Derive the V2 image key only when separately confirmed.
