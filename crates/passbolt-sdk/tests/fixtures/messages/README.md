# Test-only OpenPGP messages

Messages in the AEAD containers the client reads but does not write, encrypted for `erin`
(`keys/erin_public.asc`) by OpenPGP.js with `tests/interop/encrypt.mjs`. Each holds
`line one\nline two`.

| Message               | Container                                                  | Cipher, mode |
|-----------------------|------------------------------------------------------------|--------------|
| `erin_seipd_v2.asc`   | PKESK v6 + SEIPD v2 (RFC 9580)                             | AES-256, GCM |
| `erin_gnupg_aead.asc` | PKESK v3 + the encrypted data packet GnuPG writes (tag 20) | AES-128, OCB |

To write them again:

```sh
jq -n --rawfile key crates/passbolt-sdk/tests/fixtures/keys/erin_private.asc \
  '{text: "line one\nline two", container: "seipd_v2", private_key: $key, passphrase: "erin-passphrase"}' \
  | node tests/interop/encrypt.mjs | jq -j .message
```
