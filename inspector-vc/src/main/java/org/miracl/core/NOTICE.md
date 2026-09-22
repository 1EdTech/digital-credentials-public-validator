This directory contains source code vendored from [MIRACL Core](https://github.com/miracl/core)
(commit-of-the-day at the time of vendoring), licensed under the Apache License, Version 2.0.

Only the BLS12-381 curve implementation and its shared dependencies (`HMAC`, `HASH256`,
`HASH384`, `HASH512`, `SHA3`, `RAND`) were vendored, generated via MIRACL Core's
`java/config64.py` code generator restricted to the `BLS12381` pairing-friendly curve entry.

These files are used to provide the raw BLS12-381 pairing primitives (G1/G2 arithmetic, the
optimal ate pairing, and RFC 9380-style hash-to-curve) needed to implement the `bbs-2023`
Data Integrity cryptosuite (see `org.oneedtech.inspect.vc.verification.bbs`), since no
Java library implementing the IETF BBS signature scheme (draft-irtf-cfrg-bbs-signatures) or
the W3C bbs-2023 cryptosuite (https://www.w3.org/TR/vc-di-bbs/) was available at the time.

MIRACL Core license: http://www.apache.org/licenses/LICENSE-2.0
