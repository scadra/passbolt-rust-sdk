---
title: Ruby
sidebar_position: 9
---

# Ruby

```bash
gem install switch-case-passbolt-sdk
```

Ruby 3.0 or later, with the `ffi` gem; the gem holds the native library of Linux (x86_64,
aarch64), macOS and Windows. Its calls block.

## Log in and list

```ruby
require "passbolt"

Passbolt::Client.login(
  "https://passbolt.example.com", File.read("private.asc"), ENV.fetch("PASSBOLT_PASSPHRASE")
) do |client|
  client.list_resource_views("github").each do |view|
    puts "#{view["id"]} #{view["name"]}"
  end
end
```

With a block, `login` logs out at the end; without one it returns the client: call
`client.logout` when done.

## Pinning the server, MFA, TLS

```ruby
server_key = Passbolt.fetch_server_key("https://passbolt.example.com")
puts "Check this fingerprint with your administrator: #{server_key.fingerprint}"

client = Passbolt::Client.login(
  "https://passbolt.example.com", private_key, passphrase,
  server_public_key: server_key.armored_key,
  mfa_totp_token: nil,          # the base32 TOTP secret, for an account with TOTP
  metadata_key_fingerprint: nil,
  timeout_seconds: nil,         # 60 by default, 0 waits forever
  tls_skip_verify: false,
  proxy: nil,
  client_certificate_pem: nil   # and client_key_pem:, for mTLS
)
```

Every keyword is optional.


## Errors

```ruby
begin
  PassboltFfi.get_key_fingerprint("not a key")
rescue PassboltFfi::PassboltFfiError::Crypto => error
  puts "not a key: #{error.reason}"
end
```

`PassboltFfi::PassboltClient.login_with_config` takes a `PassboltFfi::FfiLoginOptions.new(...)`,
with the keyword arguments of the [Python](python.md#pinning-the-server-mfa-tls) example. The
calls block. The methods are those of the [overview](README.md#what-the-api-covers), in
snake_case.
