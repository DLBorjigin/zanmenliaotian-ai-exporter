# Third-party notices

Parts of the Weixin 4.x master-key adapter (binary signature, documented
configuration offsets, and derivation approach) are adapted from
[`fanyuantaier/wechatauto-replica`](https://github.com/fanyuantaier/wechatauto-replica),
licensed under the Apache License, Version 2.0. The implementation here was
modified to require an exact-target authorization gate, bounded execution,
fail-closed version adapters, no key cache, and verification against the exact
selected database.

A copy of the Apache License 2.0 is included in `licenses/Apache-2.0.txt`.

The Weixin 4.1.13.12 adapter's recognition of WCDB's serialized
`x'<key><salt>'` configuration form was informed by
[`zhuobichen/weflow-cli`](https://github.com/zhuobichen/weflow-cli), licensed
under the MIT License. This project replaces that reference implementation's
general key-pattern scan with an exact-version, exact-registration-node path and
mandatory HMAC validation against the user-selected database.

A copy of that MIT License is included in `licenses/MIT-weflow-cli.txt`.

Offline voice transcription uses [whisper.cpp](https://github.com/ggml-org/whisper.cpp)
and the multilingual OpenAI Whisper base model. Both are distributed under the
MIT License; copies are included in `licenses/MIT-whisper.cpp.txt` and
`licenses/MIT-openai-whisper.txt`.

WeChat SILK decoding is compiled from the pinned
[`kn007/silk-v3-decoder`](https://github.com/kn007/silk-v3-decoder) source.
The wrapper is MIT licensed and the included SILK SDK carries its own
BSD-style terms. Copies are included in `licenses/MIT-silk-v3-decoder.txt` and
`licenses/BSD-SILK-SDK.txt`. Source pins and download checksums are recorded in
`vendor/voice-runtime.json`.
