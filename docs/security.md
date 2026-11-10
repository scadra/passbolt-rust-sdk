---
title: Security
sidebar_position: 7
---

# Security

Learn how the CLI and the SDK keep your secrets, what they trust, and where their protection
stops.

The words used here (metadata key, session key, pinning…) are explained in
[Concepts](concepts.md).

## Threat model

Secrets and v5 metadata are encrypted and decrypted on the client. The server stores and serves
ciphertext.

The client protects you against:

- **A passive observer of the network**: everything goes over TLS, HTTPS is required.
- **Another server answering at the server's address** (DNS, proxy, TLS interception), once the
  server key is pinned: it cannot prove it holds the server's private key. Pinning does not stop
  an attacker who breaks TLS and relays the traffic to the real server.
- **A shared metadata key swapped on the server**, once the metadata key is pinned: new shared
  metadata is not encrypted for it.
- **Other local users**: the config file and the exports are readable by their owner only
  (Unix).

The client trusts:

- **The server, for availability and for the public keys it serves.** The keys of the users a
  secret is shared with come from the server. A compromised server can serve wrong data or
  refuse to answer.
- **The machine it runs on**: a user who can read the process memory or the config file can read
  the secrets.
- **The OpenPGP engine**: GopenPGP in the released binaries and native packages, OpenPGP.js in
  JavaScript (see [OpenPGP engines](#openpgp-engines)). What every engine writes is checked
  against OpenPGP.js, the library of the browser extension.

## Keep secrets off the disk

### The config file

The config file is `~/.config/passbolt/config.toml` on Linux, or the file you give with
`--config` (`.toml`, `.json` or `.yaml`).

- On Unix, writing it creates it with mode `0600` and its directory with `0700`. Reading it
  restricts it to `0600` again.
- On other systems, its permissions are left as they are.

[`configure`](cli/configuration.md#saving-settings-configure) saves every setting in effect, and
[`verify`](cli/authentication.md#pinning-the-server-verify) saves them with the pinned keys:

| Saved | Never saved |
|---|---|
| Server address, MFA mode, TLS options, proxy, timeouts | A secret set by a variable: private key, passphrase, TOTP secret, TLS client key |
| The private key and passphrase, when given on the command line or already in the file | The path of the key file: its content is saved instead |
| The TOTP secret and TLS client key, under the same condition | |
| `server_public_key`, `metadata_key_fingerprint`, `server_verify_token`, `server_verify_enc_token` (`verify` only) | |

:::caution
A saved passphrase is in clear in the file, protected by its permissions only. To keep it off
the disk, give it by variable (`PASSBOLT_USER_PASSWORD`) or let the CLI ask for it.
:::

Run `configure --debug` to print what was saved, with the secrets masked (`********`).

### Exports

[`export keepass`](cli/commands/export-keepass.md) and [`export csv`](cli/commands/export-csv.md)
write to a temporary file in the same directory, created with mode `0600` on Unix, then rename it
over the target.

- A KeePass file is encrypted with its password, its key file, or both. An empty answer to the
  password prompt writes a KDBX 3.1 file without password, as the browser extension does.
- A CSV file is in clear: every password is readable by whoever can read the file.

### Nothing else

The CLI keeps no cache on disk: no session, no decrypted resources. Metadata session keys are
saved to the server, encrypted for the user.

## Secrets in memory

- The passphrase is a `secrecy::SecretString`, never printed, even with `--debug`.
- The configuration (`SdkConfig`, the CLI config), the KeePass entries and the session keys are
  zeroized on drop with [`zeroize`](https://github.com/RustCrypto/utils/tree/master/zeroize). The
  OpenPGP.js, GopenPGP and Sequoia engines keep a private key unlocked for its passphrase, and
  forget it once its last handle is dropped.
- `Debug` output of metadata keys and session keys shows ids only, never the keys.
- `--debug` prints the method, the URL without its query, and the status of each request: no
  body, no header.

Plain strings remain. A decrypted secret goes through ordinary `String`s and JSON values
(`ResourceView.password`, `secret`, the decrypted metadata) on its way to the output; those are
not zeroized. Once printed, or given to a child process by [`exec`](cli/commands/exec.md), it is
out of the client's hands.

### The terminal UI

The [terminal UI](cli/tui.md) holds the decrypted names, usernames and URIs of the list. A secret
is decrypted only when it is copied or shown, kept in a zeroized buffer, and hidden when another
resource is selected.

A copied secret is cleared from the clipboard after 30 seconds, and on exit, unless something
else was copied meanwhile. Over SSH, the copy goes through the terminal's escape sequence
(OSC 52), and clearing it sends an empty one. A clipboard manager or the terminal may keep its
own copy.

## Network

- **TLS**: [rustls](https://github.com/rustls/rustls), no OpenSSL. Certificates are checked
  against the system's roots (also `SSL_CERT_FILE` / `SSL_CERT_DIR`) and Mozilla's.
- **HTTPS only**: the login refuses any other scheme, except `http` to `localhost` or a loopback
  address.
- **Redirects** are followed within the origin of the request only.
- **mTLS**: a client certificate and its key; one without the other is an error.
- **Proxy**: `--proxy` sends every request through an HTTP(S) proxy. TLS still runs end to end.
- **`--tls-skip-verify`** turns the certificate check off: for labs only. Pin the server key
  then.

See [TLS and proxies](cli/tls.md).

## Pin the server's keys

`passbolt verify` (or `serverPublicKey` / `metadataKeyFingerprint` in the SDK) pins two keys:

- **The server key.** Its fingerprint is computed from the key, not taken from the server. At
  each login, before the user's key is used, a fresh token is encrypted for the pinned key and
  the server must send it back decrypted.
- **The active shared metadata key.** New shared metadata is only encrypted for it. It is pinned
  only when the account logs in without MFA.

A pinned key that changed is refused until `verify --force`.

:::caution
The first `verify` trusts the key the server serves then. Check its fingerprint with your
administrator (`--debug` prints it).
:::

What an attacker in the middle (a TLS certificate it controls, or `--tls-skip-verify`) can do:

| | Without pinning | With pinning |
|---|---|---|
| Answer the login in the server's place | Yes, with a token encrypted for the user's public key | No: it cannot decrypt the token encrypted for the pinned server key |
| Relay the login to the real server, then change its answers | Yes | Yes: the proof is not bound to the TLS connection |
| Use the user's key to decrypt its own messages | No: the client only sends back a GPGAuth token | No |
| Serve its own metadata key, and read new shared metadata | Yes | No: only the pinned key is used |
| Serve wrong public keys for the users a secret is shared with, and read what is shared | Yes | Yes, when it relays the real server |
| Read secrets already stored | No: they are encrypted for the users' keys | No |

A config file holding only `server_verify_token` and `server_verify_enc_token`, without
`server_public_key`, has the same encrypted token sent again at each login. Run `passbolt verify`
again to pin the key itself.

## Login checks

- Each GPGAuth answer must carry the `X-GPGAuth-*` headers of its step (version `1.3.0`,
  progress, authenticated flag), as the browser extension checks them.
- The challenge decrypted with the user's key is sent back only if it has the format of a
  GPGAuth token: the key does not decrypt arbitrary messages for the server.
- The server must set a CSRF token.
- After login, the server's copy of the user's public key must match the private key: a probe
  encrypted for the copy must decrypt with the private key.

## MFA

The server disables an account once its failed TOTP verifications since the last login exceed
`passbolt.security.mfa.maxAttempts` (4 by default), and logs it out. To stay below that limit:

- The client sends at most 3 codes per session, whatever `--mfa-retrys` says, and stops as soon
  as the server ends the session.
- A code computed from the TOTP secret is never sent twice.

Only TOTP is answered.

## OpenPGP engines

Every engine writes and reads messages as the browser extension does:

- Messages are written for the newest valid encryption subkey of each recipient (else its
  primary key), and as SEIPD v2 only when every recipient asks for it.
- Nothing is encrypted for a revoked or expired key.
- Secrets are signed with the user's key; shared metadata with the metadata key too.

The default engines come from maintainers of trust: [GopenPGP](https://github.com/ProtonMail/gopenpgp)
and [OpenPGP.js](https://github.com/openpgpjs/openpgpjs) are both maintained by Proton.

| Engine | Feature | What for | Where it runs |
|---|---|---|---|
| [GopenPGP](https://github.com/ProtonMail/gopenpgp) 3.5.2 | `gopenpgp` | The default when it is built: the library of go-passbolt, the fastest natively | Native only: built with Go (`GO`, else `go`) and cgo into a static archive, linked into the binary |
| OpenPGP.js 6.1.1 | `openpgpjs` (default) | The library and version of the browser extension; the default without `gopenpgp`, and always in JavaScript | Native: the unmodified `openpgp.min.js` embedded in a [QuickJS](https://github.com/DelSkayn/rquickjs) runtime, with Rust digests, AES and HKDF as its WebCrypto. WebAssembly: the OpenPGP.js module of the page, else the unmodified `openpgp.min.mjs` the SDK bundles |
| [Sequoia](https://sequoia-pgp.org/) 2.4 | `sequoia` | The Rust OpenPGP implementation of the Sequoia project, on [Nettle](https://www.lysator.liu.se/~nisse/nettle/) | Native only: needs Nettle and GMP (`nettle-dev`) and libclang to build |
| [rPGP](https://github.com/rpgp/rpgp) | always built | Pure Rust; the default without `gopenpgp` and `openpgpjs`. It also reads the keys of the OpenPGP.js engine in WebAssembly, for their fingerprint | Native and WebAssembly |

`crates/passbolt-sdk/vendor/openpgpjs/README.md` gives the SHA-256 of the embedded files and how
to check them against the npm registry.

Natively, OpenPGP.js runs without the JIT of a browser, one operation at a time: it is 4 to 10
times slower than in the browser extension. GopenPGP runs operations in parallel.

### Check the engine of each package

| Package | Engine |
|---|---|
| CLI binaries of the releases, Python wheels, Java, .NET, Ruby, Android, Swift, on Windows too | GopenPGP |
| Go module | OpenPGP.js: a Go program cannot link a second Go runtime |
| JavaScript / TypeScript (npm) | OpenPGP.js |
| `cargo install` of the CLI, the `passbolt-sdk` crate | OpenPGP.js; GopenPGP with `--features gopenpgp` (needs Go) |

GopenPGP runs the Go runtime inside the host process. Do not call the SDK in a process forked
after its first use (Python `multiprocessing` with the `fork` start method): use `spawn`.

### Choose the engine

In Rust, enable the feature and set `SdkConfig.openpgp`:

```toml title="Cargo.toml"
passbolt-sdk = { version = "0.1", features = ["sequoia"] }
```

```rust
let sdk_config = SdkConfig {
    openpgp: OpenPgp::sequoia(), // or OpenPgp::gopenpgp(), OpenPgp::openpgpjs()?, OpenPgp::rpgp()
    // …the other fields
};
```

`OpenPgp::default()` is GopenPGP when the `gopenpgp` feature is built, else OpenPGP.js, else
rPGP. The engine that reads the private key at login runs every operation of the session.

In JavaScript, the `openpgp` option of `PassboltSession.login` takes the page's OpenPGP.js module
(`import * as openpgp from "openpgp"`), for example the one of a browser extension. Without it,
the SDK uses the OpenPGP.js it bundles. Either way, keys are read by rPGP, for their fingerprint;
OpenPGP.js reads and writes the messages.

## Tests and CI

- **Interop with OpenPGP.js** (`tests/interop`, `openpgp` 6.1.1 from npm): what the SDK writes is
  decrypted by OpenPGP.js and its signatures checked, and what OpenPGP.js writes is read by the
  SDK. CI runs it on every push and pull request, and the WebAssembly tests import the same
  OpenPGP.js:

  ```bash
  cargo test -p passbolt-sdk --features interop --test it interop
  ```

- **Engine tests**: the same cases (expired and revoked keys, SEIPD v2, session keys…) run on
  every engine built in.
- **Secret scan**: [gitleaks](https://github.com/gitleaks/gitleaks) scans the whole Git history in
  CI, with `.gitleaks.toml` and `.gitleaksignore`.

## Known limits

- Signatures are written, not checked: a decrypted secret or metadata is not verified against its
  signer's key.
- The Sequoia engine does not read the GnuPG AEAD (OCB) container, which the server writes for
  keys that ask for it: Sequoia reads SEIPD v1 and v2 only.
- The public keys of the users a secret is shared with are taken from the server, not pinned.
- The server key proof is not bound to the TLS connection: an attacker who breaks TLS can relay
  it.
- Pinning trusts the keys seen at the first `verify`.
- Decrypted secrets pass through ordinary strings; memory can also be swapped to disk.
- The config file is restricted to its owner on Unix only, and holds a saved passphrase in clear.
- CSV exports are in clear.
- In clear on the server: v4 metadata, folder names, tags and comments.
- The shared metadata key is not pinned when `verify` runs with an account that needs MFA.

## Reporting a vulnerability

Do not open an issue: follow Passbolt's
[responsible disclosure process](https://www.passbolt.com/docs/contribute/security/vulnerability/).

## Related

- [Concepts](concepts.md): keys, metadata keys, session keys and pinning.
- [Authentication and MFA](cli/authentication.md): the login and `passbolt verify`.
- [TLS and proxies](cli/tls.md): certificates, mTLS and proxies.
- [Configuration](cli/configuration.md): every setting and where it is saved.
