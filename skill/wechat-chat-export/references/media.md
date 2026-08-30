# Media resolution and packaging

Copy media only after the user confirms attachment copying. Restrict filesystem search to the selected account root and use a bounded index. Resolve candidates from exact local paths, XML filenames, or stable hexadecimal identifiers found in message metadata. If equally strong candidates remain, report `ambiguous_match` and copy none.

Keep `business/emoticon` out of the normal media index. Add it to the same
bounded, no-link-following index only when the approved message-type selection
explicitly includes emoticons. Identical top candidates may be deduplicated by
size and SHA-256; non-identical ties remain `ambiguous_match`.

- Plain images, videos, and files are copied unchanged with checksums. A standard
  image found in a video directory is `packaged_thumbnail_only`, never a complete video.
- Legacy single-byte-XOR `.dat` images are detected from image magic and decoded locally.
- V1 `.dat` images remain `image_v1_key_required`. V2 images can use a separately supplied or discovered AES/XOR key; otherwise they remain `image_v2_key_required`. Never guess a key or package output unless its padding and image signature validate.
- Weixin 4.x voice data may reside in decrypted `media_*.db` `VoiceInfo.voice_data`. Match using message local/server IDs, remove the optional one-byte WeChat SILK prefix, and package `.silk` as `packaged_requires_conversion` until an approved decoder is bundled.
- `wxgf` animation containers may be packaged with the custom `application/x-wechat-wxgf` media type; do not claim they are standard GIF/WebP. When a verified V2 thumbnail or high-resolution companion decodes to a standard image, add it as `packaged_preview`.
- Unknown local emoticon formats are not copied as viewable images. A selected
  emoticon may use its message-provided CDN URL only after separate network
  confirmation. Keep this mode off by default, restrict it to approved WeChat
  image hosts (`*.qpic.cn`, `*.weixin.qq.com`, and the exact
  `wxapp.tc.qq.com` host), enforce the asset-size cap, and require a recognized
  image signature.
- Missing, ambiguous, oversized, unsupported, and key-required assets remain timeline entries and manifest records with no fabricated relative path.

Never follow directory links outside the account root, copy a file found only by timestamp proximity, include a media database itself, or place absolute source paths in the archive.
## V2 image keys

V2 images have an account media key separate from database keys. Use hidden
local entry for a known 16-character key, or the separately authorized bounded
read-only discovery flow. Never cache or print the key. If the AES key, XOR key,
or output signature cannot be verified, package no decoded file and record an
explicit failure status.
