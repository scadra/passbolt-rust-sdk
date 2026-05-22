---
title: TLS and proxies
sidebar_position: 4
---

# TLS and proxies

Server certificates are checked against the system's roots (also `SSL_CERT_FILE` /
`SSL_CERT_DIR`) and Mozilla's. HTTPS is required, except for a server on localhost.

## Self-signed certificates

Skip the verification, for labs only:

```bash
passbolt list resource --tls-skip-verify
```

## Mutual TLS

A client certificate and its key, as files:

```bash
passbolt list resource \
  --tls-client-cert-file /etc/passbolt/client.crt \
  --tls-client-private-key-file /etc/passbolt/client.key
```

Or inline in the config file:

```toml
tls_client_cert = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"""
tls_client_private_key = """-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----"""
```

Giving only the certificate or only the key is an error.

## Proxies and name resolution

```bash
passbolt list resource --proxy http://proxy.example.com:3128
passbolt list resource --resolve passbolt.example.com:443:10.0.0.5   # like curl --resolve
```
