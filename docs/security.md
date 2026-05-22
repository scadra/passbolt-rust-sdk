---
title: Security
sidebar_position: 5
---

# Security

- No OpenSSL: TLS through [rustls](https://github.com/rustls/rustls), OpenPGP through
  [rPGP](https://github.com/rpgp/rpgp), both pure Rust.
- The passphrase is kept as a `secrecy::SecretString`, never logged, even in `--debug` mode; the
  config and the KeePass entries are zeroized on drop with
  [`zeroize`](https://github.com/RustCrypto/utils/tree/master/zeroize). Decrypted secrets do pass
  through ordinary strings on their way to the output.
- With `passbolt verify` (or a pinned `serverPublicKey` in the SDK), each login checks the server
  holds the pinned key, and shared metadata is only encrypted for the pinned metadata key.
- The login checks the GPGAuth headers of each step and that the server's copy of the user's key
  matches the private key.
- Nothing is encrypted for a revoked or expired key.
- What is encrypted is checked against OpenPGP.js, the library of the browser extension
  (`tests/interop`).
- Config files are restricted to their owner (`0600`); secrets given by a variable are never saved.

## Reporting a vulnerability

Do not open an issue: follow Passbolt's
[responsible disclosure process](https://www.passbolt.com/docs/contribute/security/vulnerability/).
