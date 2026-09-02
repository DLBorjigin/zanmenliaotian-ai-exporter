# Media resolution and packaging

Copy media only after the user confirms attachment copying. Restrict filesystem
search to the selected account root. Build query-scoped indexes from the selected
conversation shard, message month, exact XML filenames, and stable hexadecimal
identifiers before considering broader type-specific directories. Do not build a
whole-account index first: large `msg/attach` and `msg/video` trees can exceed a
global file or time cap before the relevant directory is reached. If a required
targeted directory cannot be traversed completely, report `index_incomplete`, not
`not_found`. If equally strong candidates remain, report `ambiguous_match` and copy none.

Package resolved files by message kind, not by detected file extension:
`assets/images/`, `assets/videos/`, `assets/emoticons/`, `assets/audio/`, and
`assets/files/`. This keeps a JPEG video cover in the video section and a PNG
emoticon in the emoticon section instead of mixing either with normal images.

Within video messages, keep the requested asset role equally strict:

- `original` is the default for a request for videos. Package only a file with a
  recognized video container signature. Do not fall back to a JPEG cover.
- `thumbnail` is used only for an explicit video-cover request. Package only a
  recognized image and label it `packaged_thumbnail_only`.
- `both` is used only when the user explicitly requests videos and their covers.
- If an original video is absent locally, report `video_original_not_found`.
  Access its message-provided CDN reference only after separate confirmation,
  and package it only when the downloaded or decrypted bytes validate as video.

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
- A selected original video may use its message-provided video CDN URL only after
  separate network confirmation. Apply the same exact-host, redirect, size, and
  timeout controls. If message metadata provides an AES key, keep it only in a
  wipeable transient buffer and accept decrypted output only after padding and
  video-container validation. Never save the key or response body as diagnostics.
- Desktop WeChat may instead store an ASN.1-like hexadecimal CDN locator token,
  not an HTTP URL. Label this `video_cdn_requires_wechat_client`; do not send the
  token or AES key to a third-party service and do not force it through an
  unrelated public CDN endpoint. Do not automate the Weixin window to fetch it.
  Report that the original video is available only after the user has opened it
  normally in Weixin and it exists in the local cache.
- Missing, ambiguous, oversized, unsupported, and key-required assets remain timeline entries and manifest records with no fabricated relative path.

Never follow directory links outside the account root, copy a file found only by timestamp proximity, include a media database itself, or place absolute source paths in the archive.
## V2 image keys

V2 images have an account media key separate from database keys. Use hidden
local entry for a known 16-character key, or the separately authorized bounded
read-only discovery flow. Never cache or print the key. If the AES key, XOR key,
or output signature cannot be verified, package no decoded file and record an
explicit failure status.
