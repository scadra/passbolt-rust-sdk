---
title: TLS and proxies
sidebar_position: 4
---

# TLS and proxies

Connect to a server with a private certificate authority, a client certificate, a proxy, or a
name your DNS does not resolve.

## How certificates are checked

- Server certificates are checked against the system's roots (also `SSL_CERT_FILE` /
  `SSL_CERT_DIR`) and Mozilla's.
- HTTPS is required, except for a server on localhost (`localhost`, `127.0.0.1`, `::1`).

To trust an internal certificate authority, add it to the system's roots, or point
`SSL_CERT_FILE` at it.

## Accept a self-signed certificate

Skip the verification, for labs only:

```bash
passbolt list resource --tls-skip-verify
```

:::caution
`--tls-skip-verify` accepts any certificate, so anyone between you and the server can read your
session. Do not use it in production.
:::

## Use mutual TLS

Give a client certificate and its key, as files:

```bash
passbolt list resource \
  --tls-client-cert-file /etc/passbolt/client.crt \
  --tls-client-private-key-file /etc/passbolt/client.key
```

Or inline in the config file, as PEM:

```toml title="~/.config/passbolt/config.toml"
tls_client_cert = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"""
tls_client_private_key = """-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----"""
```

Giving only the certificate or only the key is an error.

## Use a proxy

```bash
passbolt list resource --proxy http://proxy.example.com:3128
```

## Pin a host name to an address

`--resolve` takes `host:port:address`, like `curl --resolve`. Write an IPv6 address in brackets.

```bash
passbolt list resource --resolve passbolt.example.com:443:10.0.0.5
```

## Related

- [Configuration](configuration.md#global-flags): the TLS and proxy flags and their variables.
- [Troubleshooting](troubleshooting.md#server-certificate-not-trusted): certificate and proxy
  errors.
