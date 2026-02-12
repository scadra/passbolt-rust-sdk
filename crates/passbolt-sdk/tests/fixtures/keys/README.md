# Test-only OpenPGP keys

Do not use these keys outside the test suite.

| Key      | Passphrase         | Used as                                |
|----------|--------------------|----------------------------------------|
| ada      | `ada-passphrase`   | logged-in user                         |
| betty    | `betty-passphrase` | second user                            |
| carol    | `carol-passphrase` | group member                           |
| erin     | `erin-passphrase`  | ECC user (Ed25519 + Curve25519 subkey) |
| server   | none               | server identity                        |
| metadata | none               | shared v5 metadata key                 |

All but `erin` are RSA-2048 keys whose primary key also encrypts.

`erin_seipd_v2_public.asc` is `erin` with the preferences OpenPGP.js writes when it asks for SEIPD
v2 (features, AES-256/GCM first): the same key, rewritten with `openpgp.reformatKey` and
`config: { aeadProtect: true }` from `tests/interop`.

Copied from the Passbolt server test data (`passbolt_api`), to check that the client refuses
to encrypt for keys the browser extension refuses:

| Key                          | Server file                                                          | State                                         |
|------------------------------|----------------------------------------------------------------------|-----------------------------------------------|
| `expired_public.asc`         | `plugins/PassboltDev/TestData/config/gpg/lynne_public_expired.key`   | expired on 2018-05-02                         |
| `expired_primary_public.asc` | `tests/Fixture/OpenPGP/PublicKeys/expired_but_subkey_isnt_public.key` | primary key expired, subkey without expiry    |
| `revoked_public.asc`         | `tests/Fixture/OpenPGP/PublicKeys/rsa4096_revoked_public.key`        | revoked                                       |
| `revoked_subkey_public.asc`  | `tests/Fixture/OpenPGP/PublicKeys/revoked_subkey.key`                | its only encryption subkey revoked            |
