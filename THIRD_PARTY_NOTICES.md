# Third-party notices

Parts of the Weixin 4.x master-key adapter (binary signature, documented
configuration offsets, and derivation approach) are adapted from
[`fanyuantaier/wechatauto-replica`](https://github.com/fanyuantaier/wechatauto-replica),
licensed under the Apache License, Version 2.0. The implementation here was
modified to require an exact-target authorization gate, bounded execution,
fail-closed version adapters, no key cache, and verification against the exact
selected database.

A copy of the Apache License 2.0 is included in `licenses/Apache-2.0.txt`.
